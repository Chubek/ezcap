#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace ezcap::drivers {

/// Capabilities a driver may request in its manifest. Anything not listed
/// here is not negotiable at load time (AGENTS_LUA_DRIVER.md E5.2, E10).
/// Adding a capability requires additional review (E14).
enum class Capability {
  Events,     ///< lezcap.event: emit normalized events.
  Capture,    ///< lezcap.capture: register metadata-only filters/triggers.
  Dns,        ///< lezcap.dns: observe redacted DNS metadata.
  Process,    ///< lezcap.process: read process metadata.
  Policy,     ///< lezcap.policy: query the active redaction policy.
  Endpoint,   ///< lezcap.endpoint: declare endpoints.
  Spec,       ///< lezcap.spec: invoke specgen.
  Log,        ///< lezcap.log: structured logging.
  Util,       ///< lezcap.util: time/hash/base64/bounded strings.
  Status,     ///< lezcap.status: backend health queries.
};

/// Parse a capability name from manifest JSON. Returns false on names that
/// are not in the enum above.
[[nodiscard]] bool capability_from_name(const std::string& name,
                                        Capability& out);

/// Canonical name for a capability (used in status output and errors).
[[nodiscard]] const char* capability_name(Capability capability) noexcept;

/// A validated driver manifest (AGENTS_LUA_DRIVER.md E6 step 2). Mirrors
/// protocol/drivers/manifest.schema.json. Every field is validated; there
/// is no "repair" of malformed manifests.
struct DriverManifest {
  std::string name;             ///< Unique driver name, [a-z0-9-]{1,64}.
  std::string version;          ///< Semver-ish x.y.z.
  std::string script_path;      ///< Resolved, canonical, inside an allowlist.
  std::string description{""};
  std::set<Capability> capabilities{};
  std::vector<std::string> event_types{};   ///< Subscriptions, bounded.
  std::uint32_t max_endpoints{8};
  std::uint32_t max_subscriptions{16};
  std::string script_sha256{""};  ///< Optional integrity pin (hex).

  /// Parse and validate a manifest from JSON text. All validation failures
  /// are reported through `error`; partial results are never returned.
  [[nodiscard]] static bool parse(const std::string& json_text,
                                  DriverManifest& out, std::string& error);
};

/// Validate that `script_path` (already read) matches the pinned hash.
[[nodiscard]] bool verify_script_hash(const DriverManifest& manifest,
                                      const std::string& script_source,
                                      std::string& error);

/// True when a script path's canonical form is inside one of the
/// allowlisted directories (each entry must itself be canonical).
[[nodiscard]] bool path_within_allowlist(const std::string& canonical_path,
                                         const std::vector<std::string>& dirs);

/// Maximum number of characters in manifest field values. Oversize input
/// is rejected, not truncated.
inline constexpr std::size_t kMaxManifestFieldLength = 512;
inline constexpr std::size_t kMaxManifestEventTypes = 16;

}  // namespace ezcap::drivers
