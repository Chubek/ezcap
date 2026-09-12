#pragma once

#include "common/logging.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

struct lua_State;

namespace ezcap::drivers::lua {

/// Hard budgets enforced by the host for one sandboxed lua_State (AGENTS.md
/// E4.2). These are ceilings, not suggestions: the allocator fails past the
/// memory cap, the instruction hook aborts past the instruction cap, and
/// callback invocation aborts past the wall-clock deadline. Scripts can
/// never read or raise these values.
struct SandboxBudgets {
  std::size_t max_memory_bytes{1 * 1024 * 1024};   ///< Per-state Lua heap.
  std::size_t max_string_bytes{8 * 1024};          ///< Max string to/from Lua.
  std::int64_t max_instructions{2'000'000};        ///< Per callback.
  std::int64_t wall_clock_ms{200};                 ///< Per callback.
};

/// Result of a sandboxed callback invocation.
enum class SandboxOutcome {
  Ok,               ///< Completed without error.
  RuntimeError,     ///< Script raised a Lua error (or returned false + msg).
  BudgetExceeded,   ///< Instruction, memory, or wall-clock budget hit.
};

/// Structured error report for a failed callback. `message` never contains
/// script source text beyond the error location prefix produced by the Lua
/// runtime itself, never variable dumps, and never forbidden values.
struct SandboxError {
  SandboxOutcome outcome{SandboxOutcome::Ok};
  std::string code;       ///< Stable code, e.g. "budget.instructions".
  std::string message;    ///< Human-readable, sanitized.
};

/// One hardened lua_State (AGENTS.md E4). A Sandbox owns its state
/// exclusively; sharing a state between scripts is forbidden (E4.4) and the
/// class is non-copyable by construction.
class Sandbox {
 public:
  /// Create a fresh hardened state. Returns nullptr if the state cannot be
  /// created at all (allocation failure before the custom allocator is in
  /// place); the caller treats that as a load failure, never a crash.
  [[nodiscard]] static Sandbox* create(const SandboxBudgets& budgets);

  ~Sandbox();
  Sandbox(const Sandbox&) = delete;
  Sandbox& operator=(const Sandbox&) = delete;
  Sandbox(Sandbox&&) = delete;
  Sandbox& operator=(Sandbox&&) = delete;

  /// Load a chunk of *source text* (never bytecode) into the state. Returns
  /// false with `error` describing the failure. The first byte of a LuaJIT
  /// bytecode dump is ESC (0x1B); such input is rejected before it reaches
  /// the loader.
  [[nodiscard]] bool load_source(const std::string& name,
                                 const std::string& source,
                                 SandboxError& error);

  /// Invoke the chunk (or a previously loaded function) under lua_pcall with
  /// the host error handler, instruction hook, and wall-clock deadline
  /// installed. The function must already be on the stack. Returns the
  /// outcome; on non-Ok the stack is unwound to the base index.
  [[nodiscard]] SandboxOutcome pcall(std::int32_t nargs, std::int32_t nresults,
                                     SandboxError& error);

  /// Call a global function by name with a single argument table (used for
  /// on_load / on_start / on_event / on_stop). Missing functions are not an
  /// error (except for on_load where the caller checks separately).
  [[nodiscard]] bool call_global(const char* name, std::int32_t nresults,
                                 SandboxError& error);

  /// True when the sandbox has hit a budget and must be torn down rather
  /// than reused mid-callback (the host may still finish the callback's
  /// cleanup, but will not run another one).
  [[nodiscard]] bool aborted() const noexcept { return aborted_; }

  /// Access the raw state. Intended for host binding registration only —
  /// bindings validate every argument themselves.
  [[nodiscard]] lua_State* state() noexcept { return lua_state_; }

  /// Budgets in effect for this state.
  [[nodiscard]] const SandboxBudgets& budgets() const noexcept {
    return budgets_;
  }

  /// Set the per-callback deadline. Called by the host between callbacks so
  /// one callback's deadline never leaks into the next.
  void begin_callback() noexcept;
  void end_callback() noexcept;

  /// Called only from the instruction/deadline hook: record that a budget
  /// was hit so subsequent pcall errors are classified correctly.
  void mark_aborted() noexcept;

 private:
  Sandbox(lua_State* lua_state, const SandboxBudgets& budgets);

  lua_State* lua_state_;
  SandboxBudgets budgets_;
  bool aborted_{false};
};

}  // namespace ezcap::drivers::lua
