#pragma once

#include <ezcap/event.hpp>

#include <cstdint>
#include <span>

namespace ezcap::capture {

/// Parsed metadata from a link-layer frame. Payload bytes are never copied
/// out of the input span; only header fields are extracted.
struct PacketMetadata {
  bool valid{false};
  Transport transport{Transport::Other};
  Direction direction{Direction::Unknown};
  std::string local_address{};   // For pcap frames: source address.
  std::string remote_address{};  // For pcap frames: destination address.
  Port source_port{0};
  Port destination_port{0};
  std::string dns_query_name{};
  std::uint8_t dns_response_code{0};
  bool has_dns_response_code{false};
};

/// Parse an Ethernet frame carrying IPv4/IPv6 with TCP/UDP, extracting
/// metadata only. `frame` must include the 14-byte Ethernet header.
/// DNS question names on UDP port 53 are decoded when present.
/// Returns metadata with valid=false on any malformation; never throws.
[[nodiscard]] PacketMetadata parse_ethernet_frame(
    std::span<const std::uint8_t> frame) noexcept;

/// Format an IPv4 address (4 bytes, network order) as dotted quad.
[[nodiscard]] std::string format_ipv4(const std::uint8_t bytes[4]) noexcept;

/// Format an IPv6 address (16 bytes, network order) in canonical form.
[[nodiscard]] std::string format_ipv6(const std::uint8_t bytes[16]) noexcept;

}  // namespace ezcap::capture
