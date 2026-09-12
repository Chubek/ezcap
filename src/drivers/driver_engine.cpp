// Lua Driver Engine implementation (AGENTS_LUA_DRIVER.md E6).
//
// The lifecycle is deterministic: discovery -> static validation ->
// sandbox construction -> on_load -> on_start -> on_event* -> on_stop ->
// teardown. Faults accumulate with exponential backoff and quarantine the
// script past the threshold. No code path here can crash, deadlock, or
// starve the daemon because of a misbehaving script: every host->script
// call is a protected pcall under instruction/memory/wall-clock budgets.

#include "drivers/driver_engine.hpp"

#include "common/logging.hpp"
#include "common/sha256.hpp"

#include <ezcap/event_types.hpp>
#include <ezcap/policy.hpp>

#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

namespace ezcap::drivers {
namespace {

using nlohmann::json;

/// Convert a normalized, already-redacted event into the read-only table
/// scripts receive in on_event. Only metadata fields exist in the source
/// struct, so only metadata fields can reach Lua — by construction, not
/// by filtering (E9).
void set_table_string(lua_State* L, const char* key, const std::string& value) {
  if (!value.empty()) {
    lua_pushlstring(L, value.data(), value.size());
    lua_setfield(L, -2, key);
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// DriverInstance
// ---------------------------------------------------------------------------

DriverInstance::DriverInstance(DriverManifest manifest, EngineLimits limits)
    : host_{}, limits_{limits} {
  host_.manifest = std::move(manifest);
  // The manifest may only lower the engine defaults (E6 step 2).
  host_.limits.max_endpoints =
      std::min(limits_.max_endpoints_per_driver, host_.manifest.max_endpoints);
  host_.limits.max_subscriptions = std::min(
      limits_.max_subscriptions_per_driver, host_.manifest.max_subscriptions);
  host_.limits.max_events_per_second = limits_.max_events_per_second_per_driver;
  host_.limits.max_string_bytes = limits_.sandbox_budgets.max_string_bytes;
}

DriverInstance::~DriverInstance() { stop(); }

bool DriverInstance::load(const std::string& script_source,
                          policy::PolicyEngine& policy_engine,
                          std::string& error) {
  if (state_ != DriverState::Discovered) {
    error = "driver is not in the discovered state";
    return false;
  }

  // E6 step 3: fresh hardened state per script.
  sandbox_.reset(lua::Sandbox::create(limits_.sandbox_budgets));
  if (sandbox_ == nullptr) {
    state_ = DriverState::Failed;
    error = "sandbox construction failed";
    return false;
  }

  // E6 step 3b: capability-gated binding registration. Done before the
  // script chunk runs so a script can probe its lezcap table but never
  // see an undeclared module.
  std::string binding_error;
  if (!register_lezcap(*sandbox_, host_.manifest, host_.limits, host_,
                       policy_engine, binding_error)) {
    state_ = DriverState::Failed;
    error = "binding registration failed: " + binding_error;
    sandbox_.reset();
    return false;
  }

  // Load source text only (the sandbox rejects bytecode at the door).
  lua::SandboxError sandbox_error;
  if (!sandbox_->load_source("=@" + host_.manifest.script_path, script_source,
                            sandbox_error)) {
    state_ = DriverState::Failed;
    error = sandbox_error.message;
    sandbox_.reset();
    return false;
  }

  // Run the chunk to define the script's callbacks.
  sandbox_->begin_callback();
  lua::SandboxOutcome outcome = sandbox_->pcall(0, 0, sandbox_error);
  sandbox_->end_callback();
  if (outcome != lua::SandboxOutcome::Ok) {
    state_ = DriverState::Failed;
    error = sandbox_error.message;
    sandbox_.reset();
    return false;
  }

  // E6 step 4: on_load(ctx). The ctx table is manifest-scoped: name,
  // version, capabilities, and the event types the driver subscribed to.
  lua_State* L = sandbox_->state();
  lua_getglobal(L, "on_load");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    state_ = DriverState::Failed;
    error = "script does not define on_load";
    sandbox_.reset();
    return false;
  }
  lua_createtable(L, 0, 4);
  lua_pushlstring(L, host_.manifest.name.data(), host_.manifest.name.size());
  lua_setfield(L, -2, "name");
  lua_pushlstring(L, host_.manifest.version.data(),
                  host_.manifest.version.size());
  lua_setfield(L, -2, "version");
  lua_createtable(L, 0, 10);
  for (const Capability capability : host_.manifest.capabilities) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, capability_name(capability));
  }
  lua_setfield(L, -2, "capabilities");
  if (!host_.manifest.event_types.empty()) {
    lua_createtable(L, static_cast<int>(host_.manifest.event_types.size()), 0);
    int i = 1;
    for (const auto& type : host_.manifest.event_types) {
      lua_pushlstring(L, type.data(), type.size());
      lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "event_types");
  }

  sandbox_->begin_callback();
  outcome = sandbox_->pcall(1, 0, sandbox_error);  // consumes on_load + ctx
  sandbox_->end_callback();
  if (outcome != lua::SandboxOutcome::Ok) {
    record_fault(sandbox_error.code);
    state_ = DriverState::Failed;
    error = sandbox_error.message;
    sandbox_.reset();
    return false;
  }

  state_ = DriverState::Loaded;
  EZCAP_LOG_INFO("lua.driver loaded name={}", host_.manifest.name);
  return true;
}

bool DriverInstance::start(std::string& error) {
  if (state_ != DriverState::Loaded) {
    error = "driver is not in the loaded state";
    return false;
  }
  lua::SandboxError sandbox_error;
  if (!sandbox_->call_global("on_start", 0, sandbox_error)) {
    record_fault(sandbox_error.code);
    error = sandbox_error.message;
    return false;
  }
  state_ = DriverState::Started;
  return true;
}

bool DriverInstance::push_event_table(const ezcap::Event& event) {
  lua_State* L = sandbox_->state();
  lua_createtable(L, 0, 12);

  // Scalar metadata.
  lua_pushlstring(L, event.event_id.data(), event.event_id.size());
  lua_setfield(L, -2, "event_id");
  lua_pushstring(L, event_type_name(event.type));
  lua_setfield(L, -2, "event_type");
  lua_pushstring(L, event_source_name(event.source));
  lua_setfield(L, -2, "source");
  lua_pushstring(L, time_util::to_rfc3339(event.timestamp).c_str());
  lua_setfield(L, -2, "timestamp");
  lua_pushnumber(L, event.confidence);
  lua_setfield(L, -2, "confidence");
  set_table_string(L, "correlation_id", event.correlation_id);
  if (event.privacy.redacted) {
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "redacted");
  }

  // Process metadata (PID, name, uid only).
  if (event.process) {
    lua_createtable(L, 0, 3);
    lua_pushnumber(L, static_cast<double>(static_cast<std::uint32_t>(
                          event.process->pid)));
    lua_setfield(L, -2, "pid");
    set_table_string(L, "name", event.process->name);
    if (event.process->uid) {
      lua_pushnumber(L, static_cast<double>(
                            static_cast<std::uint32_t>(*event.process->uid)));
      lua_setfield(L, -2, "uid");
    }
    lua_setfield(L, -2, "process");
  }

  // Network metadata (already-redacted addresses and DNS names).
  if (event.network) {
    lua_createtable(L, 0, 8);
    lua_pushstring(L, transport_name(event.network->transport));
    lua_setfield(L, -2, "transport");
    if (event.network->direction != ezcap::Direction::Unknown) {
      lua_pushstring(L, direction_name(event.network->direction));
      lua_setfield(L, -2, "direction");
    }
    set_table_string(L, "local_address", event.network->local_address);
    if (!event.network->local_address.empty()) {
      lua_pushnumber(
          L, static_cast<double>(
                 static_cast<std::uint16_t>(event.network->local_port)));
      lua_setfield(L, -2, "local_port");
    }
    set_table_string(L, "remote_address", event.network->remote_address);
    if (!event.network->remote_address.empty()) {
      lua_pushnumber(
          L, static_cast<double>(
                 static_cast<std::uint16_t>(event.network->remote_port)));
      lua_setfield(L, -2, "remote_port");
    }
    set_table_string(L, "dns_query_name", event.network->dns_query_name);
    if (event.network->dns_response_code) {
      lua_pushnumber(L, static_cast<double>(*event.network->dns_response_code));
      lua_setfield(L, -2, "dns_response_code");
    }
    set_table_string(L, "interface", event.network->interface);
    lua_setfield(L, -2, "network");
  }

  // Browser metadata (redacted URL / title with correlation confidence).
  if (event.browser) {
    lua_createtable(L, 0, 5);
    lua_pushnumber(L, static_cast<double>(event.browser->tab_id));
    lua_setfield(L, -2, "tab_id");
    set_table_string(L, "url", event.browser->url);
    set_table_string(L, "title", event.browser->title);
    lua_setfield(L, -2, "browser");
  }
  return true;
}

void DriverInstance::on_event(const ezcap::Event& event) {
  if (state_ != DriverState::Started || sandbox_ == nullptr) {
    return;
  }

  // Subscription check: a driver receives only the event types it
  // declared (a reduction over the pipeline, E9).
  if (!host_.manifest.event_types.empty()) {
    const std::string type_name = event_type_name(event.type);
    bool subscribed = false;
    for (const auto& subscribed_type : host_.manifest.event_types) {
      if (subscribed_type == type_name) {
        subscribed = true;
        break;
      }
    }
    if (!subscribed) {
      return;
    }
  }

  // Capture filters are further reductions.
  for (const auto& filter : host_.capture_filters) {
    if (!filter.event_type.empty() &&
        filter.event_type != event_type_name(event.type)) {
      return;
    }
    if (!filter.transport.empty() && event.network &&
        filter.transport != transport_name(event.network->transport)) {
      return;
    }
    if (filter.min_confidence_permille > 0 &&
        event.confidence * 1000.0 <
            static_cast<double>(filter.min_confidence_permille)) {
      return;
    }
  }

  lua_State* L = sandbox_->state();
  lua_getglobal(L, "on_event");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    return;  // Optional callback.
  }
  push_event_table(event);

  lua::SandboxError sandbox_error;
  sandbox_->begin_callback();
  const lua::SandboxOutcome outcome = sandbox_->pcall(1, 0, sandbox_error);
  sandbox_->end_callback();
  if (outcome != lua::SandboxOutcome::Ok) {
    record_fault(sandbox_error.code);
  }
}

void DriverInstance::stop() noexcept {
  if (state_ == DriverState::Started && sandbox_ != nullptr) {
    lua::SandboxError sandbox_error;
    if (!sandbox_->call_global("on_stop", 0, sandbox_error)) {
      // on_stop must not throw; a fault here is recorded but teardown
      // proceeds regardless (E6 step 7).
      record_fault(sandbox_error.code);
    }
  }
  // E6 step 8: destroy the state; no script-owned closures survive.
  sandbox_.reset();
  if (state_ == DriverState::Started || state_ == DriverState::Loaded) {
    state_ = DriverState::Discovered;  // Instance is spent; not reloadable.
  }
}

void DriverInstance::record_fault(const std::string& code) noexcept {
  faults_ += 1;
  EZCAP_LOG_WARN("lua.driver fault name={} code={} count={}",
                 host_.manifest.name, code, faults_);
  if (faults_ >= limits_.fault_threshold) {
    state_ = DriverState::Quarantined;
    EZCAP_LOG_ERROR("lua.driver quarantined name={} faults={}",
                    host_.manifest.name, faults_);
    return;
  }
  // Exponential backoff between faults: 2^(faults-1) * 25 ms, capped.
  const std::uint64_t backoff_ms =
      std::min<std::uint64_t>(25u << (faults_ - 1), 8000u);
  std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
}

// ---------------------------------------------------------------------------
// DriverEngine
// ---------------------------------------------------------------------------

DriverEngine::DriverEngine(EngineLimits limits,
                           std::vector<std::string> allowdirs)
    : limits_{limits}, allowdirs_{std::move(allowdirs)} {}

void DriverEngine::set_allowdirs(std::vector<std::string> dirs) {
  allowdirs_ = std::move(dirs);
}

std::vector<std::pair<std::string, std::string>>
DriverEngine::discover_manifests() const {
  std::vector<std::pair<std::string, std::string>> found;
  for (const auto& dir : allowdirs_) {
    if (dir.empty()) {
      continue;
    }
    DIR* handle = ::opendir(dir.c_str());
    if (handle == nullptr) {
      continue;
    }
    while (const dirent* entry = ::readdir(handle)) {
      const std::string name = entry->d_name;
      if (name.size() < 14 ||
          name.compare(name.size() - 14, 14, ".manifest.json") != 0) {
        continue;
      }
      const std::string path = dir + (dir.back() == '/' ? "" : "/") + name;
      std::string source;
      std::string error;
      // Manifests are small JSON documents; reuse the defensive reader
      // (O_NOFOLLOW, size cap, canonical-path check).
      if (!read_script_safely(path, source, error)) {
        EZCAP_LOG_WARN("lua.driver manifest unreadable path={} error={}",
                       path, error);
        continue;
      }
      found.emplace_back(path, source);
    }
    ::closedir(handle);
  }
  return found;
}

bool DriverEngine::read_script_safely(const std::string& path,
                                      std::string& source,
                                      std::string& error) {
  // O_NOFOLLOW: refuse to open a symlink's target (E10).
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    error = "cannot open file (symlinks are refused)";
    return false;
  }

  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    ::close(fd);
    error = "cannot stat file";
    return false;
  }
  if (!S_ISREG(st.st_mode)) {
    ::close(fd);
    error = "not a regular file";
    return false;
  }
  if (static_cast<std::size_t>(st.st_size) > kMaxScriptBytes) {
    ::close(fd);
    error = "file exceeds the size cap";
    return false;
  }

  // Canonical path check after the open (defeats renamed-directory TOCTOU:
  // we validate the path we opened via /proc/self/fd).
  char resolved[PATH_MAX];
  const std::string fd_path = "/proc/self/fd/" + std::to_string(fd);
  const ssize_t resolved_len =
      ::readlink(fd_path.c_str(), resolved, sizeof(resolved) - 1);
  if (resolved_len <= 0) {
    ::close(fd);
    error = "cannot resolve canonical path";
    return false;
  }
  resolved[resolved_len] = '\0';
  const std::string canonical(resolved, static_cast<std::size_t>(resolved_len));
  if (canonical != path) {
    ::close(fd);
    error = "path is not canonical";
    return false;
  }

  source.clear();
  source.resize(static_cast<std::size_t>(st.st_size));
  std::size_t total = 0;
  while (total < source.size()) {
    const ssize_t n =
        ::read(fd, source.data() + total, source.size() - total);
    if (n <= 0) {
      ::close(fd);
      error = "short read";
      return false;
    }
    total += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return true;
}

std::unique_ptr<DriverInstance> DriverEngine::load_from_manifest_text(
    const std::string& manifest_text, policy::PolicyEngine& policy_engine,
    std::string& error) const {
  // E6 step 2: static validation.
  DriverManifest manifest;
  if (!DriverManifest::parse(manifest_text, manifest, error)) {
    return nullptr;
  }

  // Resolve the script path relative to nothing: the manifest path must
  // already be usable as-is (absolute or engine-relative). Enforce the
  // allowlist when one is configured.
  if (!allowdirs_.empty() && !path_within_allowlist(manifest.script_path, allowdirs_)) {
    error = "script path is outside the allowlisted directories";
    return nullptr;
  }

  std::string script_source;
  if (!read_script_safely(manifest.script_path, script_source, error)) {
    return nullptr;
  }

  // Integrity pin (E6 step 2): verify the script hash when configured.
  if (!verify_script_hash(manifest, script_source, error)) {
    return nullptr;
  }

  auto instance = std::make_unique<DriverInstance>(std::move(manifest),
                                                   limits_);
  std::string load_error;
  if (!instance->load(script_source, policy_engine, load_error)) {
    error = load_error;
    return nullptr;
  }
  return instance;
}

}  // namespace ezcap::drivers
