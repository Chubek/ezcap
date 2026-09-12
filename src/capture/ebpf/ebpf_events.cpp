#include "ebpf_events.hpp"

#include "capture/packet_parser.hpp"
#include "common/time.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>

namespace ezcap::capture {

namespace {

/// Compute the boot-anchored wall time for a kernel timestamp.
std::chrono::system_clock::time_point wall_time(
    std::uint64_t timestamp_ns,
    std::chrono::system_clock::time_point boot_walltime) noexcept {
  return time_util::from_ktime_ns(timestamp_ns, boot_walltime);
}

/// Bounded copy of an NUL-terminated char array from the kernel event.
std::string bounded_string(const char* src, std::size_t cap) noexcept {
  std::size_t len = 0;
  while (len < cap && src[len] != '\0') {
    ++len;
  }
  return std::string{src, len};
}

}  // namespace

ezcap::Event normalize_connect_event(
    const ezcap_connect_event& raw,
    std::chrono::system_clock::time_point boot_walltime) {
  ezcap::Event event;
  event.type = EventType::Connection;
  event.source = EventSource::Ebpf;
  event.timestamp = wall_time(raw.hdr.timestamp_ns, boot_walltime);
  // eBPF connect events carry the originating pid directly: attribution is
  // reliable at the process level, though not at the tab level.
  event.confidence = 0.95;

  ezcap::ProcessInfo process;
  process.pid = static_cast<ProcessId>(raw.hdr.pid);
  process.uid = static_cast<UserId>(raw.hdr.uid);
  event.process = std::move(process);

  ezcap::NetworkInfo network;
  network.transport = raw.transport == 6   ? Transport::Tcp
                      : raw.transport == 17 ? Transport::Udp
                                            : Transport::Other;
  network.direction = raw.direction == 1   ? Direction::Outbound
                      : raw.direction == 2 ? Direction::Inbound
                                           : Direction::Unknown;
  network.local_port = static_cast<Port>(raw.local_port);
  network.remote_port = static_cast<Port>(raw.remote_port);
  if (raw.is_ipv6 != 0) {
    network.local_address = format_ipv6(raw.local_addr6);
    network.remote_address = format_ipv6(raw.remote_addr6);
  } else {
    network.local_address = format_ipv4(
        reinterpret_cast<const std::uint8_t*>(&raw.local_addr4));
    network.remote_address = format_ipv4(
        reinterpret_cast<const std::uint8_t*>(&raw.remote_addr4));
  }
  network.interface = bounded_string(raw.ifname, EZCAP_IFNAME_MAX);
  network.backend = EventSource::Ebpf;
  event.network = std::move(network);

  event.privacy.metadata_only = true;
  return event;
}

ezcap::Event normalize_dns_event(
    const ezcap_dns_event& raw,
    std::chrono::system_clock::time_point boot_walltime) {
  ezcap::Event event;
  event.type = EventType::Dns;
  event.source = EventSource::Ebpf;
  event.timestamp = wall_time(raw.hdr.timestamp_ns, boot_walltime);
  event.confidence = 0.9;

  ezcap::ProcessInfo process;
  process.pid = static_cast<ProcessId>(raw.hdr.pid);
  process.uid = static_cast<UserId>(raw.hdr.uid);
  event.process = std::move(process);

  ezcap::NetworkInfo network;
  network.transport = raw.transport == 17 ? Transport::Udp : Transport::Other;
  network.local_address = raw.is_ipv6 != 0
                              ? format_ipv6(raw.local_addr6)
                              : format_ipv4(reinterpret_cast<const std::uint8_t*>(
                                    &raw.local_addr4));
  network.local_port = static_cast<Port>(raw.local_port);
  // DNS query names are untrusted input: bounded and validated copy only.
  if (raw.query_len > 0 && raw.query_len <= EZCAP_DNS_NAME_MAX) {
    network.dns_query_name =
        bounded_string(raw.query_name, static_cast<std::size_t>(raw.query_len));
  }
  network.interface = bounded_string(raw.ifname, EZCAP_IFNAME_MAX);
  network.backend = EventSource::Ebpf;
  event.network = std::move(network);

  event.privacy.metadata_only = true;
  return event;
}

ezcap::Event normalize_socket_state_event(
    const ezcap_socket_state_event& raw,
    std::chrono::system_clock::time_point boot_walltime) {
  ezcap::Event event;
  event.type = EventType::Connection;
  event.source = EventSource::Ebpf;
  event.timestamp = wall_time(raw.hdr.timestamp_ns, boot_walltime);
  event.confidence = 0.9;

  ezcap::ProcessInfo process;
  process.pid = static_cast<ProcessId>(raw.hdr.pid);
  process.uid = static_cast<UserId>(raw.hdr.uid);
  event.process = std::move(process);

  ezcap::NetworkInfo network;
  network.transport = Transport::Tcp;
  network.direction = raw.direction == 1   ? Direction::Outbound
                      : raw.direction == 2 ? Direction::Inbound
                                           : Direction::Unknown;
  network.local_port = static_cast<Port>(raw.local_port);
  network.remote_port = static_cast<Port>(raw.remote_port);
  if (raw.is_ipv6 != 0) {
    network.local_address = format_ipv6(raw.local_addr6);
    network.remote_address = format_ipv6(raw.remote_addr6);
  } else {
    network.local_address = format_ipv4(
        reinterpret_cast<const std::uint8_t*>(&raw.local_addr4));
    network.remote_address = format_ipv4(
        reinterpret_cast<const std::uint8_t*>(&raw.remote_addr4));
  }
  network.interface = bounded_string(raw.ifname, EZCAP_IFNAME_MAX);
  network.backend = EventSource::Ebpf;
  event.network = std::move(network);

  event.privacy.metadata_only = true;
  return event;
}

}  // namespace ezcap::capture
