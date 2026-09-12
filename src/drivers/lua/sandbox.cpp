// Hardened LuaJIT sandbox (AGENTS_LUA_DRIVER.md E4).
//
// Every driver script runs in a fresh lua_State built here. Nothing about
// the hardening is conventional: the library set is explicitly curated, the
// allocator enforces a heap ceiling, the instruction hook enforces a per-
// callback instruction budget, and every host->script call goes through
// lua_pcall with a host error handler (E4.3).

#include "drivers/lua/sandbox.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <new>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

namespace ezcap::drivers::lua {
namespace {

// ---------------------------------------------------------------------------
// Custom allocator: hard heap ceiling per state (E4.2).
// ---------------------------------------------------------------------------

struct AllocContext {
  std::size_t ceiling_bytes{0};
  std::size_t used_bytes{0};
  bool exhausted{false};
};

void* budget_alloc(void* ud, void* ptr, size_t osize, size_t nsize) {
  auto* ctx = static_cast<AllocContext*>(ud);
  if (nsize == 0) {
    // Free. ptr may be nullptr when Lua frees a NULL, free(NULL) is a no-op.
    if (ptr != nullptr) {
      ctx->used_bytes -= osize;
      std::free(ptr);
    }
    return nullptr;
  }
  if (ptr == nullptr) {
    // Fresh allocation: refuse once the ceiling would be crossed.
    if (ctx->used_bytes + nsize > ctx->ceiling_bytes) {
      ctx->exhausted = true;
      return nullptr;  // Lua turns this into a memory error we catch.
    }
    void* fresh = std::malloc(nsize);
    if (fresh != nullptr) {
      ctx->used_bytes += nsize;
    }
    return fresh;
  }
  // Resize. Refuse if the delta would cross the ceiling; Lua then keeps the
  // original block and raises a memory error.
  if (nsize > osize && ctx->used_bytes + (nsize - osize) > ctx->ceiling_bytes) {
    ctx->exhausted = true;
    return nullptr;
  }
  void* resized = std::realloc(ptr, nsize);
  if (resized != nullptr) {
    if (nsize > osize) {
      ctx->used_bytes += nsize - osize;
    } else {
      ctx->used_bytes -= osize - nsize;
    }
  } else if (nsize <= osize) {
    // realloc failure on a shrink is a plain OOM, not budget exhaustion.
    return nullptr;
  }
  return resized;
}

// ---------------------------------------------------------------------------
// Per-state host data, reachable from hooks via the allocator userdata.
// ---------------------------------------------------------------------------

struct StateData {
  Sandbox* sandbox{nullptr};
  AllocContext alloc{};
  std::int64_t instructions_remaining{0};
  std::chrono::steady_clock::time_point deadline{};
  bool in_callback{false};
};

StateData* state_data(lua_State* L) {
  void* ud = nullptr;
  lua_getallocf(L, &ud);
  return static_cast<StateData*>(ud);
}

// ---------------------------------------------------------------------------
// Instruction hook (E4.2) and error handler (E4.3).
// ---------------------------------------------------------------------------

void instruction_hook(lua_State* L, lua_Debug* ar) {
  (void)ar;
  StateData* data = state_data(L);
  if (data == nullptr || !data->in_callback) {
    return;  // Between callbacks: nothing runs that we didn't start.
  }
  if (--data->instructions_remaining <= 0) {
    data->sandbox->mark_aborted();
    luaL_error(L, "instruction budget exceeded");
  }
  if (std::chrono::steady_clock::now() > data->deadline) {
    data->sandbox->mark_aborted();
    luaL_error(L, "wall-clock deadline exceeded");
  }
}

int host_error_handler(lua_State* L) {
  // Normalize whatever the script raised into a string message; the host
  // sanitizes it further before logging (no source dumps).
  if (!lua_isstring(L, 1)) {
    if (luaL_callmeta(L, 1, "__tostring") && lua_type(L, -1) == LUA_TSTRING) {
      return 1;
    }
    lua_pushfstring(L, "(error object: %s)", luaL_typename(L, 1));
    return 1;
  }
  luaL_traceback(L, L, lua_tostring(L, 1), 1);
  return 1;
}

// Host panic handler (E4.3). A real Lua panic means the state's integrity is
// already lost and unwinding is unsafe; we log a structured event and abort
// the process rather than continue in an undefined state. Panics are
// unreachable in practice because every host->script call is protected.
int host_panic(lua_State* L) {
  const char* message = lua_tostring(L, -1);
  EZCAP_LOG_CRITICAL("lua.sandbox.panic state={:p} message={}",
                     static_cast<const void*>(L),
                     message != nullptr ? message : "(non-string panic)");
  std::abort();
}

// ---------------------------------------------------------------------------
// Curated library opening (E4.1). We never call luaL_openlibs.
// ---------------------------------------------------------------------------

// Names removed from _G regardless of what any opened module installed.
// `load` is on this list: with bytecode rejected at the loader and
// string.dump removed, `load`-from-source remains, but removing it outright
// keeps the set of executable-code entry points to the host loader alone.
constexpr const char* kForbiddenGlobals[] = {
    "io",       "os",       "package", "debug",    "require",
    "dofile",   "loadfile", "ffi",     "jit",      "collectgarbage",
    "newproxy", "load",     "loadstring",
};

void scrub_globals(lua_State* L, const char* const* names,
                   std::size_t count) {
  for (std::size_t i = 0; i < count; ++i) {
    lua_pushnil(L);
    lua_setfield(L, -2, names[i]);
  }
}

void open_curated_libs(lua_State* L) {
  // luaL_openlibs is never called. Each curated module is opened
  // individually; io, os, package, debug, and the FFI/jit modules are never
  // registered in the first place, then scrubbed from _G by name as well in
  // case anything re-registered them.
  luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
  luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
  luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
  luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
  luaL_requiref(L, LUA_COROLIBNAME, luaopen_coroutine, 1);

  // Base subset. luaopen_base registers the globals (_G, assert, error,
  // pairs, pcall, ...) plus the loaders we do not want. Scrub the escape
  // hatches from _G immediately afterwards.
  lua_pushcfunction(L, luaopen_base);
  lua_pushstring(L, "");
  lua_call(L, 1, 0);

  lua_pushglobaltable(L);
  scrub_globals(L, kForbiddenGlobals,
                sizeof(kForbiddenGlobals) / sizeof(*kForbiddenGlobals));
  lua_pop(L, 1);

  // string.dump serializes a function to bytecode: remove it.
  lua_getglobal(L, "string");
  if (lua_istable(L, -1)) {
    lua_pushnil(L);
    lua_setfield(L, -2, "dump");
  }
  lua_pop(L, 1);

  // A curated `time` shim built on std::chrono replaces os.time/os.clock
  // (E4.1). Registered by the bindings layer (lezcap.util) so capability
  // gating stays in one place.
}
}  // namespace

Sandbox* Sandbox::create(const SandboxBudgets& budgets) {
  auto* data = new (std::nothrow) StateData();
  if (data == nullptr) {
    return nullptr;
  }
  data->alloc.ceiling_bytes = budgets.max_memory_bytes;

  lua_State* L = lua_newstate(budget_alloc, data);
  if (L == nullptr) {
    delete data;
    return nullptr;
  }
  open_curated_libs(L);
  lua_sethook(L, instruction_hook, LUA_MASKCOUNT, 1000);
  lua_atpanic(L, host_panic);

  auto* sandbox = new (std::nothrow) Sandbox(L, budgets);
  if (sandbox == nullptr) {
    lua_close(L);
    delete data;
    return nullptr;
  }
  data->sandbox = sandbox;
  return sandbox;
}

Sandbox::Sandbox(lua_State* lua_state, const SandboxBudgets& budgets)
    : lua_state_(lua_state), budgets_(budgets) {}

Sandbox::~Sandbox() {
  if (lua_state_ != nullptr) {
    void* ud = nullptr;
    lua_getallocf(lua_state_, &ud);
    lua_close(lua_state_);
    delete static_cast<StateData*>(ud);
  }
}

bool Sandbox::load_source(const std::string& name, const std::string& source,
                          SandboxError& error) {
  // Bytecode loading is disabled (E4.1): LuaJIT bytecode dumps start with
  // ESC and luaL_loadbuffer would happily run them.
  if (!source.empty() && static_cast<unsigned char>(source[0]) == 0x1B) {
    error.outcome = SandboxOutcome::RuntimeError;
    error.code = "sandbox.bytecode_rejected";
    error.message = "bytecode input rejected; only source text may be loaded";
    return false;
  }
  const int status = luaL_loadbuffer(lua_state_, source.data(), source.size(),
                                     name.c_str());
  if (status != 0) {
    error.outcome = SandboxOutcome::RuntimeError;
    error.code = "sandbox.compile_error";
    const char* message = lua_tostring(lua_state_, -1);
    error.message = message != nullptr ? message : "compile error";
    lua_pop(lua_state_, 1);
    return false;
  }
  return true;
}

SandboxOutcome Sandbox::pcall(std::int32_t nargs, std::int32_t nresults,
                              SandboxError& error) {
  // Handler goes below the function + args: push, insert at -nargs-2.
  const int base = lua_gettop(lua_state_) - nargs;
  lua_pushcfunction(lua_state_, host_error_handler);
  lua_insert(lua_state_, base);
  const int status = lua_pcall(lua_state_, nargs, nresults, base);
  lua_remove(lua_state_, base);  // Remove the handler (on success).
  if (status == 0) {
    return SandboxOutcome::Ok;
  }
  const char* message = lua_tostring(lua_state_, -1);
  error.message = message != nullptr ? message : "unknown Lua error";
  lua_pop(lua_state_, 1);
  if (aborted_) {
    error.outcome = SandboxOutcome::BudgetExceeded;
    error.code = "budget.exceeded";
    return SandboxOutcome::BudgetExceeded;
  }
  error.outcome = SandboxOutcome::RuntimeError;
  error.code = "sandbox.runtime_error";
  return SandboxOutcome::RuntimeError;
}

bool Sandbox::call_global(const char* name, std::int32_t nresults,
                          SandboxError& error) {
  const int type = lua_getglobal(lua_state_, name);
  if (type != LUA_TFUNCTION) {
    lua_pop(lua_state_, 1);
    // Missing optional callback is not an error.
    return true;
  }
  begin_callback();
  const SandboxOutcome outcome = pcall(0, nresults, error);
  end_callback();
  return outcome == SandboxOutcome::Ok;
}

void Sandbox::begin_callback() noexcept {
  StateData* data = state_data(lua_state_);
  if (data != nullptr) {
    data->instructions_remaining = budgets_.max_instructions;
    data->deadline = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(budgets_.wall_clock_ms);
    data->in_callback = true;
  }
}

void Sandbox::end_callback() noexcept {
  StateData* data = state_data(lua_state_);
  if (data != nullptr) {
    data->in_callback = false;
  }
}

void Sandbox::mark_aborted() noexcept { aborted_ = true; }

}  // namespace ezcap::drivers::lua
