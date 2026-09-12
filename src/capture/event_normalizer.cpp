#include "event_normalizer.hpp"

#include "common/time.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace ezcap::capture {

namespace {

/// Global UUID-v4-style generator seeded per process. Event ids are opaque
/// correlation handles, not security-sensitive values.
std::mutex g_id_mutex;

std::string random_uuid() {
  static std::atomic<std::uint64_t> counter{0};
  std::uint8_t bytes[16];

  std::lock_guard<std::mutex> lock{g_id_mutex};
  std::FILE* f = std::fopen("/dev/urandom", "rb");
  if (f != nullptr) {
    const std::size_t got = std::fread(bytes, 1, sizeof(bytes), f);
    std::fclose(f);
    if (got != sizeof(bytes)) {
      // Fall through to counter fallback.
      for (auto& b : bytes) b = 0;
    }
  } else {
    for (auto& b : bytes) b = 0;
  }

  // Mix in the counter so degenerate randomness still yields unique ids.
  const std::uint64_t seq = counter.fetch_add(1);
  std::memcpy(bytes + 8, &seq, sizeof(seq));

  // Set UUID v4 / variant bits.
  bytes[6] = (bytes[6] & 0x0F) | 0x40;
  bytes[8] = (bytes[8] & 0x3F) | 0x80;

  char out[40];
  std::snprintf(out, sizeof(out),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
  return out;
}

}  // namespace

EventNormalizer::EventNormalizer(std::string instance_id)
    : instance_id_{std::move(instance_id)} {}

std::string EventNormalizer::new_event_id() const { return random_uuid(); }

ezcap::Event EventNormalizer::from_packet_metadata(
    const PacketMetadata& meta, std::chrono::system_clock::time_point timestamp,
    const std::string& interface) {
  ezcap::Event event;
  event.event_id = new_event_id();
  event.type = EventType::Connection;
  event.source = EventSource::Pcap;
  event.timestamp = timestamp;
  // pcap frames have no process or tab evidence: attribution is weak until
  // the correlator upgrades it with socket-table matches.
  event.confidence = 0.1;

  ezcap::NetworkInfo network;
  network.transport = meta.transport;
  network.direction = meta.direction;
  network.local_address = meta.local_address;
  network.local_port = meta.source_port;
  network.remote_address = meta.remote_address;
  network.remote_port = meta.destination_port;
  network.interface = interface;
  network.backend = EventSource::Pcap;
  event.network = std::move(network);

  event.privacy.metadata_only = true;
  return event;
}

ezcap::Event EventNormalizer::dns_from_packet_metadata(
    const PacketMetadata& meta, std::chrono::system_clock::time_point timestamp,
    const std::string& interface) {
  ezcap::Event event;
  event.event_id = new_event_id();
  event.type = EventType::Dns;
  event.source = EventSource::Pcap;
  event.timestamp = timestamp;
  event.confidence = 0.2;

  ezcap::NetworkInfo network;
  network.transport = meta.transport;
  network.direction = meta.direction;
  network.local_address = meta.local_address;
  network.local_port = meta.source_port;
  network.remote_address = meta.remote_address;
  network.remote_port = meta.destination_port;
  network.dns_query_name = meta.dns_query_name;
  if (meta.has_dns_response_code) {
    network.dns_response_code = meta.dns_response_code;
  }
  network.interface = interface;
  network.backend = EventSource::Pcap;
  event.network = std::move(network);

  event.privacy.metadata_only = true;
  return event;
}

ezcap::Event EventNormalizer::status_event(
    std::vector<ezcap::Event::BackendStatus> backends) {
  ezcap::Event event;
  event.event_id = new_event_id();
  event.type = EventType::Status;
  event.source = EventSource::Pcap;  // synthetic status: source is internal
  event.timestamp = time_util::now();
  event.confidence = 1.0;
  event.backend_statuses = std::move(backends);
  event.privacy.metadata_only = true;
  return event;
}

ezcap::Event EventNormalizer::error_event(const std::string& code,
                                          const std::string& message) {
  ezcap::Event event;
  event.event_id = new_event_id();
  event.type = EventType::Error;
  event.source = EventSource::Pcap;
  event.timestamp = time_util::now();
  event.confidence = 1.0;
  event.error_code = code;
  event.error_message = message;
  event.privacy.metadata_only = true;
  return event;
}

}  // namespace ezcap::capture
