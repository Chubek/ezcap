#pragma once

#include <cstdint>
#include <string>

namespace ezcap {

/// Strong type for network ports. Valid range 0..65535; an invalid parse
/// yields 0 and must be treated as "unknown" rather than a real port.
enum class Port : std::uint16_t {};

/// Strong type for process identifiers.
enum class ProcessId : std::uint32_t {};

/// Strong type for user identifiers.
enum class UserId : std::uint32_t {};

/// Event category, mirroring the `event_type` enum in
/// protocol/schema/event.schema.json.
enum class EventType {
  Connection,
  Dns,
  Navigation,
  Process,
  Status,
  Error,
};

/// Backend or component that produced an observation, mirroring the `source`
/// enum in the event schema.
enum class EventSource {
  Ebpf,
  Pcap,
  Browser,
};

/// Transport protocol of an observed connection.
enum class Transport {
  Tcp,
  Udp,
  Icmp,
  Other,
};

/// Connection direction, where determinable.
enum class Direction {
  Inbound,
  Outbound,
  Unknown,
};

/// Named attribution confidence bands. The numeric score is authoritative;
/// the band is used for presentation only and must never upgrade a weak or
/// probable association to a definite claim.
enum class ConfidenceBand {
  Weak,       ///< 0.00–0.39
  Probable,   ///< 0.40–0.69
  Strong,     ///< 0.70–0.89
  Direct,     ///< 0.90–1.00
};

/// Map a numeric confidence score to its band.
[[nodiscard]] ConfidenceBand confidence_band(double confidence) noexcept;

/// Lowercase wire name of an event type ("connection", ...).
[[nodiscard]] const char* event_type_name(EventType type) noexcept;

/// Parse a wire event type name; returns false on unknown values.
[[nodiscard]] bool event_type_from_name(const std::string& name, EventType& out) noexcept;

/// Lowercase wire name of an event source ("ebpf", ...).
[[nodiscard]] const char* event_source_name(EventSource source) noexcept;

/// Parse a wire source name; returns false on unknown values.
[[nodiscard]] bool event_source_from_name(const std::string& name, EventSource& out) noexcept;

/// Lowercase wire name of a transport ("tcp", ...).
[[nodiscard]] const char* transport_name(Transport transport) noexcept;

/// Parse a wire transport name; returns false on unknown values.
[[nodiscard]] bool transport_from_name(const std::string& name, Transport& out) noexcept;

/// Lowercase wire name of a direction ("inbound", ...).
[[nodiscard]] const char* direction_name(Direction direction) noexcept;

/// Parse a wire direction name; returns false on unknown values.
[[nodiscard]] bool direction_from_name(const std::string& name, Direction& out) noexcept;

/// String form of a confidence band, used in logs and the extension UI.
[[nodiscard]] const char* confidence_band_name(ConfidenceBand band) noexcept;

}  // namespace ezcap
