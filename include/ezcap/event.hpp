#pragma once

#include <ezcap/event_types.hpp>
#include <ezcap/version.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ezcap {

/// Originating process information, when the operating system exposes it.
struct ProcessInfo {
  ProcessId pid{0};
  std::string name{};  ///< Executable name only, never a command line.
  std::optional<UserId> uid{};
};

/// Network metadata of an observation. Addresses are stored in canonical
/// textual form (as produced by inet_ntop); no packet bytes are retained.
struct NetworkInfo {
  Transport transport{Transport::Other};
  Direction direction{Direction::Unknown};
  std::string local_address{};
  Port local_port{0};
  std::string remote_address{};
  Port remote_port{0};
  std::string dns_query_name{};  ///< Redacted per policy.
  std::optional<std::uint8_t> dns_response_code{};
  std::string interface{};  ///< e.g. "eth0"
  EventSource backend{EventSource::Pcap};
};

/// Browser correlation data. Populated only when reliable browser-level
/// evidence exists; otherwise the correlation is left unset and the event's
/// confidence reflects the weaker evidence.
struct BrowserInfo {
  std::uint64_t tab_id{0};
  std::uint64_t window_id{0};
  std::string url{};      ///< Redacted URL.
  std::string title{};    ///< Page title, subject to redaction.
  std::string navigation_id{};
  std::uint64_t frame_id{0};
};

/// Privacy annotations recorded when redaction was applied.
struct PrivacyInfo {
  bool redacted{false};
  bool metadata_only{true};
  std::array<bool, 5> redactions{};  ///< Ordered as RedactionKind.
};

/// The normalized event model shared by every component. Mirrors
/// protocol/schema/event.schema.json; events carrying payload data cannot be
/// represented in this structure by construction.
struct Event {
  std::uint32_t schema_version{kEventSchemaVersion};
  std::string event_id{};   ///< UUID.
  EventType type{EventType::Connection};
  EventSource source{EventSource::Pcap};
  std::chrono::system_clock::time_point timestamp{};
  double confidence{0.0};
  std::string correlation_id{};

  std::optional<ProcessInfo> process{};
  std::optional<NetworkInfo> network{};
  std::optional<BrowserInfo> browser{};
  PrivacyInfo privacy{};

  // Status event payload.
  struct BackendStatus {
    EventSource name{EventSource::Pcap};
    bool active{false};
    std::string detail{};
  };
  std::vector<BackendStatus> backend_statuses{};

  // Error event payload.
  std::string error_code{};
  std::string error_message{};
};

}  // namespace ezcap
