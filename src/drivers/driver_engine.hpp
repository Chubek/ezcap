#pragma once

// Lua Driver Engine (AGENTS_LUA_DRIVER.md E3, E6).
//
// Discovers, validates, runs, and tears down sandboxed Lua driver scripts.
// The engine is the only component that constructs Sandboxes and the only
// owner of DriverHostState. Scripts are untrusted input, equal in trust to
// a socket peer: every guarantee below is enforced by code in this
// subsystem, not by convention.

#include "drivers/lua/bindings/lezcap.hpp"
#include "drivers/lua/manifests/manifest.hpp"
#include "drivers/lua/sandbox.hpp"
#include "specgen/model/descriptor.hpp"

#include <ezcap/event.hpp>

#include <memory>
#include <string>
#include <vector>

namespace ezcap::policy {
class PolicyEngine;
}

namespace ezcap::drivers {

/// Engine-wide limits (E7). Conservative defaults; configuration may lower
/// them but a driver may never raise its own limits.
struct EngineLimits {
  std::uint32_t max_concurrent_scripts{16};
  std::uint32_t max_endpoints_per_driver{8};
  std::uint32_t max_subscriptions_per_driver{16};
  std::uint32_t max_events_per_second_per_driver{64};
  std::uint32_t fault_threshold{3};  ///< Faults before quarantine.
  lua::SandboxBudgets sandbox_budgets{};
};

/// Lifecycle state of one loaded script (E6).
enum class DriverState {
  Discovered,   ///< Manifest validated; script not yet loaded.
  Loaded,       ///< on_load returned a descriptor.
  Started,      ///< on_start completed.
  Quarantined,  ///< Fault threshold exceeded; not reloaded automatically.
  Failed,       ///< Unrecoverable load/validate failure.
};

/// A running (or loadable) driver: manifest + sandbox + host state. One
/// instance owns exactly one lua_State for its lifetime (E4.4).
class DriverInstance {
 public:
  DriverInstance(DriverManifest manifest, EngineLimits limits);
  ~DriverInstance();

  DriverInstance(const DriverInstance&) = delete;
  DriverInstance& operator=(const DriverInstance&) = delete;
  DriverInstance(DriverInstance&&) = delete;
  DriverInstance& operator=(DriverInstance&&) = delete;

  /// E6 steps 3–4: build the sandbox, register capability-gated bindings,
  /// load the source, run the chunk, call on_load(ctx). `ctx` contains
  /// only the manifest-declared capabilities.
  [[nodiscard]] bool load(const std::string& script_source,
                          policy::PolicyEngine& policy_engine,
                          std::string& error);

  /// E6 step 5: on_start(ctx). Must be idempotent on retry.
  [[nodiscard]] bool start(std::string& error);

  /// E6 step 6: on_event(event). The event arrives as a Lua table built
  /// from the already-redacted normalized event; blocking or faulting
  /// counts against the fault budget.
  void on_event(const ezcap::Event& event);

  /// E6 step 7: on_stop(ctx). Must not throw; failures are recorded as
  /// faults but cannot prevent teardown.
  void stop() noexcept;

  [[nodiscard]] DriverState state() const noexcept { return state_; }
  [[nodiscard]] const DriverManifest& manifest() const noexcept {
    return host_.manifest;
  }
  [[nodiscard]] const DriverHostState& host_state() const noexcept {
    return host_;
  }

  /// Fault accounting: faults / threshold and the current backoff in ms.
  [[nodiscard]] std::uint32_t faults() const noexcept { return faults_; }
  [[nodiscard]] bool quarantined() const noexcept {
    return state_ == DriverState::Quarantined;
  }

 private:
  void record_fault(const std::string& code) noexcept;
  void push_event_table(const ezcap::Event& event);

  DriverState state_{DriverState::Discovered};
  std::uint32_t faults_{0};
  std::unique_ptr<lua::Sandbox> sandbox_;
  DriverHostState host_{};
  EngineLimits limits_{};
};

/// Discovery + supervision (E6 step 1). The engine enumerates manifests
/// from allowlisted directories, validates them, and hands back loadable
/// instances. Script files are opened with O_NOFOLLOW and the canonical
/// path is checked against the allowlist to defeat symlink escapes and
/// TOCTOU races (E10).
class DriverEngine {
 public:
  explicit DriverEngine(EngineLimits limits, std::vector<std::string> allowdirs);

  /// Set the allowlisted discovery directories (canonical paths).
  void set_allowdirs(std::vector<std::string> dirs);

  /// Discover manifests (JSON files ending in .manifest.json) directly
  /// inside the allowlisted directories. Returns the manifest texts and
  /// their source paths; invalid manifests are skipped with a log line,
  /// never crash the engine.
  [[nodiscard]] std::vector<std::pair<std::string, std::string>>
  discover_manifests() const;

  /// Full load path: parse + validate a manifest, verify the hash pin if
  /// present, read the script safely, construct a DriverInstance, and run
  /// load(). Returns nullptr with `error` on any failure.
  [[nodiscard]] std::unique_ptr<DriverInstance> load_from_manifest_text(
      const std::string& manifest_text, policy::PolicyEngine& policy_engine,
      std::string& error) const;

  /// Read a script file defensively: O_NOFOLLOW open, size cap, canonical
  /// path check. Returns false with `error` on any violation.
  [[nodiscard]] static bool read_script_safely(const std::string& path,
                                               std::string& source,
                                               std::string& error);

  /// Maximum accepted script size (256 KiB of source text).
  static constexpr std::size_t kMaxScriptBytes = 256 * 1024;

 private:
  EngineLimits limits_;
  std::vector<std::string> allowdirs_{};
};

}  // namespace ezcap::drivers
