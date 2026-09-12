#include "packet_parser.hpp"

#include <arpa/inet.h>

#include <cstring>

namespace ezcap::capture {

namespace {

constexpr std::size_t kEthHeaderLen = 14;
constexpr std::uint16_t kEthTypeIp4 = 0x0800;
constexpr std::uint16_t kEthTypeIp6 = 0x86DD;
constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;
constexpr std::uint16_t kDnsPort = 53;

[[nodiscard]] std::uint16_t read_be16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

/// Decode a DNS question name from a bounded span. Returns empty string on
/// any malformation (compression pointers, overlong labels, truncation).
[[nodiscard]] std::string parse_dns_qname(std::span<const std::uint8_t> data) noexcept {
  std::string out;
  std::size_t i = 0;
  std::size_t labels = 0;
  while (i < data.size() && labels < 128) {
    const std::uint8_t label_len = data[i];
    if (label_len == 0) {
      return out;
    }
    if ((label_len & 0xC0) != 0 || label_len > 63) {
      return {};  // compression pointer or malformed: reject
    }
    if (i + 1 + label_len > data.size()) {
      return {};  // truncated
    }
    if (!out.empty()) {
      if (out.size() + 1 >= 253) return {};
      out.push_back('.');
    }
    for (std::size_t j = 0; j < label_len; ++j) {
      const std::uint8_t ch = data[i + 1 + j];
      // Restrict to a conservative printable subset; DNS names with
      // anything else are treated as malformed rather than passed through.
      if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.')) {
        return {};
      }
      if (out.size() + 1 >= 253) return {};
      out.push_back(static_cast<char>(ch));
    }
    i += 1 + label_len;
    ++labels;
  }
  return {};  // ran out of data before a terminating zero label
}

}  // namespace

std::string format_ipv4(const std::uint8_t bytes[4]) noexcept {
  char buf[INET_ADDRSTRLEN];
  if (::inet_ntop(AF_INET, bytes, buf, sizeof(buf)) == nullptr) {
    return {};
  }
  return buf;
}

std::string format_ipv6(const std::uint8_t bytes[16]) noexcept {
  char buf[INET6_ADDRSTRLEN];
  if (::inet_ntop(AF_INET6, bytes, buf, sizeof(buf)) == nullptr) {
    return {};
  }
  return buf;
}

PacketMetadata parse_ethernet_frame(std::span<const std::uint8_t> frame) noexcept {
  PacketMetadata meta;

  // Ethernet header.
  if (frame.size() < kEthHeaderLen) {
    return meta;
  }
  const std::uint16_t eth_type = read_be16(frame.data() + 12);
  std::size_t offset = kEthHeaderLen;

  std::span<const std::uint8_t> ip;
  if (eth_type == kEthTypeIp4) {
    if (frame.size() < offset + 20) {
      return meta;
    }
    const std::size_t ihl = static_cast<std::size_t>(frame[offset] & 0x0F) * 4;
    if (ihl < 20 || frame.size() < offset + ihl) {
      return meta;
    }
    meta.local_address = format_ipv4(frame.data() + offset + 12);
    meta.remote_address = format_ipv4(frame.data() + offset + 16);
    const std::uint8_t proto = frame[offset + 9];
    if (proto != kProtoTcp && proto != kProtoUdp) {
      return meta;
    }
    meta.transport = proto == kProtoTcp ? Transport::Tcp : Transport::Udp;
    offset += ihl;
  } else if (eth_type == kEthTypeIp6) {
    if (frame.size() < offset + 40) {
      return meta;
    }
    const std::uint8_t next_header = frame[offset + 6];
    // No extension-header walking: only plain TCP/UDP are handled.
    if (next_header != kProtoTcp && next_header != kProtoUdp) {
      return meta;
    }
    meta.local_address = format_ipv6(frame.data() + offset + 8);
    meta.remote_address = format_ipv6(frame.data() + offset + 24);
    meta.transport =
        next_header == kProtoTcp ? Transport::Tcp : Transport::Udp;
    offset += 40;
  } else {
    return meta;
  }

  // Transport header.
  const std::size_t remaining = frame.size() - offset;
  if (meta.transport == Transport::Tcp) {
    if (remaining < 20) {
      meta.transport = Transport::Other;
      return meta;
    }
    meta.source_port = static_cast<Port>(read_be16(frame.data() + offset));
    meta.destination_port =
        static_cast<Port>(read_be16(frame.data() + offset + 2));
    // TCP payload is never inspected.
  } else {  // UDP
    if (remaining < 8) {
      meta.transport = Transport::Other;
      return meta;
    }
    meta.source_port = static_cast<Port>(read_be16(frame.data() + offset));
    meta.destination_port =
        static_cast<Port>(read_be16(frame.data() + offset + 2));
    const std::uint16_t dgram_len = read_be16(frame.data() + offset + 4);
    if (dgram_len < 8 || static_cast<std::size_t>(dgram_len) - 8 > remaining - 8) {
      // Declared length exceeds captured data: accept what we have but do
      // not read past the captured span.
    }
    const std::size_t payload_off = offset + 8;
    // DNS: only on port 53, and only the first question name.
    if (static_cast<std::uint16_t>(meta.destination_port) == kDnsPort ||
        static_cast<std::uint16_t>(meta.source_port) == kDnsPort) {
      auto payload = frame.subspan(
          payload_off, frame.size() - payload_off);
      if (payload.size() >= 12) {
        const std::uint16_t qdcount =
            read_be16(payload.data() + 4);
        const std::uint8_t rcode = payload[3] & 0x0F;
        meta.has_dns_response_code = true;
        meta.dns_response_code = rcode;
        if (qdcount >= 1) {
          meta.dns_query_name = parse_dns_qname(payload.subspan(12));
        }
      }
    }
  }

  meta.valid = true;
  return meta;
}

}  // namespace ezcap::capture
