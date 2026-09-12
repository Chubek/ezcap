#pragma once

#include <ezcap/event.hpp>

#include "packet_parser.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace ezcap::capture {

/// Converts backend-specific observations (parsed pcap frames, decoded eBPF
/// events) into the normalized shared event model. The only component that
/// constructs Events from raw observations, besides the browser bridge.
class EventNormalizer {
 public:
  explicit EventNormalizer(std::string instance_id);

  /// Build a connection event from parsed packet metadata (pcap source).
  /// Confidence starts at the pcap baseline (weak) and is raised later by
  /// the attribution correlator.
  [[nodiscard]] ezcap::Event from_packet_metadata(
      const PacketMetadata& meta,
      std::chrono::system_clock::time_point timestamp,
      const std::string& interface);

  /// Build a DNS event from parsed packet metadata.
  [[nodiscard]] ezcap::Event dns_from_packet_metadata(
      const PacketMetadata& meta,
      std::chrono::system_clock::time_point timestamp,
      const std::string& interface);

  /// Build a status event.
  [[nodiscard]] ezcap::Event status_event(
      std::vector<ezcap::Event::BackendStatus> backends);

  /// Build an error event.
  [[nodiscard]] ezcap::Event error_event(const std::string& code,
                                         const std::string& message);

 private:
  [[nodiscard]] std::string new_event_id() const;

  std::string instance_id_;
  std::uint64_t sequence_{0};
};

}  // namespace ezcap::capture
