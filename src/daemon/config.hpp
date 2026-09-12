#pragma once

#include <ezcap/ipc_protocol.hpp>
#include <ezcap/policy.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace ezcap::daemon {

/// Daemon configuration, loaded from a JSON file. All values are validated
/// on load; invalid configurations are rejected with a specific error
/// rather than repaired silently. Storage is disabled by default.
struct Config {
  // IPC.
  std::string socket_path{"/run/ezcap/ezcap.sock"};

  // Logging.
  std::string log_level{"info"};
  std::string log_file{};  ///< Empty = stderr only.

  // Capture.
  bool prefer_ebpf{true};
  bool pcap_fallback{true};
  std::vector<std::string> interfaces{};  ///< Empty = default route interface.
  std::string pcap_filter{"ip or ip6"};

  // Privacy policy defaults (metadata-only is constant).
  ezcap::Policy policy{};

  // Storage (disabled by default).
  bool storage_enabled{false};
  std::string storage_path{"/var/lib/ezcap/events.db"};
  std::chrono::seconds storage_retention{std::chrono::seconds{86400 * 7}};

  // Resource limits.
  std::chrono::milliseconds status_interval{std::chrono::milliseconds{1000}};
  std::uint64_t max_events_per_second{0};  ///< 0 = unlimited.

  /// Load and validate configuration from `path`. Returns false with
  /// `error` describing the first problem found. Unknown top-level keys are
  /// rejected so typos never silently disable a setting.
  [[nodiscard]] static bool load(const std::string& path, Config& out,
                                 std::string& error);

  /// Parse configuration from an in-memory JSON document (used by tests).
  [[nodiscard]] static bool parse(const std::string& json_text, Config& out,
                                  std::string& error);
};

/// Serialize a configuration to a JSON document (used by get_status).
[[nodiscard]] std::string to_json_text(const Config& config);

}  // namespace ezcap::daemon
