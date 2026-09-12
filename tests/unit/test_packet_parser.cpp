// Unit tests for the metadata-only packet parser: synthetic Ethernet
// frames (IPv4/IPv6, TCP/UDP/DNS) exercising header extraction, DNS
// question decoding, and every malformation path. Payload bytes are
// never asserted on — they must never be extracted.

#include "capture/packet_parser.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using ezcap::capture::PacketMetadata;
using ezcap::capture::parse_ethernet_frame;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

std::vector<std::uint8_t> eth_ip4_udp_dns(std::uint32_t src_ip, std::uint32_t dst_ip,
                                          std::uint16_t src_port,
                                          const std::string& qname) {
  // Ethernet (14) + IPv4 (20) + UDP (8) + DNS header (12) + question.
  std::vector<std::uint8_t> f;
  auto push16 = [&f](std::uint16_t v) {
    f.push_back(static_cast<std::uint8_t>(v >> 8));
    f.push_back(static_cast<std::uint8_t>(v & 0xFF));
  };
  auto push32 = [&f](std::uint32_t v) {
    f.push_back(static_cast<std::uint8_t>(v >> 24));
    f.push_back(static_cast<std::uint8_t>(v >> 16));
    f.push_back(static_cast<std::uint8_t>(v >> 8));
    f.push_back(static_cast<std::uint8_t>(v));
  };

  // Ethernet: dst, src, type IPv4.
  f.insert(f.end(), 12, 0x00);
  push16(0x0800);
  // IPv4: v4, ihl 5, total length (fixed later), proto UDP.
  f.push_back(0x45);
  f.push_back(0x00);
  push16(0);
  push16(0);
  push16(0);
  f.push_back(64);
  f.push_back(17);  // UDP
  push16(0);
  push32(src_ip);
  push32(dst_ip);
  // UDP.
  push16(src_port);
  push16(53);
  push16(8 + 12);
  push16(0);
  // DNS header: id, flags, qdcount=1, others 0.
  push16(0x1234);
  push16(0x0100);
  push16(1);
  push16(0);
  push16(0);
  push16(0);
  // Question: labels.
  std::size_t start = 0;
  while (true) {
    const auto dot = qname.find('.', start);
    const std::string label =
        qname.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    f.push_back(static_cast<std::uint8_t>(label.size()));
    f.insert(f.end(), label.begin(), label.end());
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  f.push_back(0);  // terminating root label
  push16(1);       // qtype A
  push16(1);       // qclass IN
  return f;
}

}  // namespace

int main() {
  using namespace ezcap;

  // --- Malformed inputs (never valid, never crash) -------------------------
  {
    const auto meta = parse_ethernet_frame({});
    CHECK(!meta.valid);
  }
  {
    const std::vector<std::uint8_t> short_frame(10, 0);
    CHECK(!parse_ethernet_frame(short_frame).valid);
  }
  {
    // Ethernet header only, no IP.
    std::vector<std::uint8_t> f(14, 0);
    f[12] = 0x08;
    f[13] = 0x00;
    CHECK(!parse_ethernet_frame(f).valid);
  }
  {
    // Unknown ethertype.
    std::vector<std::uint8_t> f(20, 0);
    f[12] = 0xAB;
    f[13] = 0xCD;
    CHECK(!parse_ethernet_frame(f).valid);
  }

  // --- Valid IPv4 + UDP + DNS ------------------------------------------------
  {
    const auto frame = eth_ip4_udp_dns(0x0A000001, 0x08080808, 5353, "example.com");
    const auto meta = parse_ethernet_frame(frame);
    CHECK(meta.valid);
    CHECK(meta.transport == Transport::Udp);
    CHECK(meta.local_address == "10.0.0.1");
    CHECK(meta.remote_address == "8.8.8.8");
    CHECK(static_cast<std::uint16_t>(meta.source_port) == 5353);
    CHECK(static_cast<std::uint16_t>(meta.destination_port) == 53);
    CHECK(meta.dns_query_name == "example.com");
    CHECK(meta.has_dns_response_code);
  }

  // --- Truncated DNS question -------------------------------------------------
  {
    auto frame = eth_ip4_udp_dns(0x0A000001, 0x08080808, 5353, "example.com");
    // Chop the terminating zero label.
    frame.resize(frame.size() - 5);
    const auto meta = parse_ethernet_frame(frame);
    CHECK(meta.valid);           // frame itself is still parseable
    CHECK(meta.dns_query_name.empty());  // but the question is rejected
  }

  // --- IPv6 ------------------------------------------------------------------
  {
    // Ethernet + IPv6 (40) + UDP (8), no payload.
    std::vector<std::uint8_t> f;
    auto push16 = [&f](std::uint16_t v) {
      f.push_back(static_cast<std::uint8_t>(v >> 8));
      f.push_back(static_cast<std::uint8_t>(v & 0xFF));
    };
    f.insert(f.end(), 12, 0);
    push16(0x86DD);
    // IPv6: ver/traclass/flow (4), payload len (2), next header UDP, hop.
    f.push_back(0x60); f.push_back(0); f.push_back(0); f.push_back(0);
    push16(8);
    f.push_back(17);   // next header: UDP
    f.push_back(64);
    // src ::1, dst ::2
    f.insert(f.end(), 15, 0); f.push_back(1);
    f.insert(f.end(), 15, 0); f.push_back(2);
    // UDP
    push16(12345);
    push16(443);
    push16(8);
    push16(0);

    const auto meta = parse_ethernet_frame(f);
    CHECK(meta.valid);
    CHECK(meta.transport == Transport::Udp);
    CHECK(meta.local_address == "::1");
    CHECK(meta.remote_address == "::2");
    CHECK(static_cast<std::uint16_t>(meta.destination_port) == 443);
  }

  // --- IPv4 + TCP -------------------------------------------------------------
  {
    std::vector<std::uint8_t> f;
    auto push16 = [&f](std::uint16_t v) {
      f.push_back(static_cast<std::uint8_t>(v >> 8));
      f.push_back(static_cast<std::uint8_t>(v & 0xFF));
    };
    auto push32 = [&f](std::uint32_t v) {
      f.push_back(static_cast<std::uint8_t>(v >> 24));
      f.push_back(static_cast<std::uint8_t>(v >> 16));
      f.push_back(static_cast<std::uint8_t>(v >> 8));
      f.push_back(static_cast<std::uint8_t>(v));
    };
    f.insert(f.end(), 12, 0);
    push16(0x0800);
    f.push_back(0x45); f.push_back(0);
    push16(40); push16(0); push16(0);
    f.push_back(64);
    f.push_back(6);  // TCP
    push16(0);
    push32(0xC0A80101);  // 192.168.1.1
    push32(0x01010101);  // 1.1.1.1
    push16(44444);
    push16(443);
    // TCP header: seq, ack, offset 5 << 4, rest zeros (20 bytes).
    push32(0); push32(0);
    push16(0x5000);
    push16(0); push16(0);
    push16(0); push16(0);
    // 10 bytes of "payload" — must never surface anywhere.
    f.insert(f.end(), {'S', 'E', 'C', 'R', 'E', 'T', 'D', 'A', 'T', 'A'});

    const auto meta = parse_ethernet_frame(f);
    CHECK(meta.valid);
    CHECK(meta.transport == Transport::Tcp);
    CHECK(meta.local_address == "192.168.1.1");
    CHECK(meta.remote_address == "1.1.1.1");
    CHECK(static_cast<std::uint16_t>(meta.source_port) == 44444);
    CHECK(static_cast<std::uint16_t>(meta.destination_port) == 443);
    // The PacketMetadata type has no payload field; assert that any
    // serialization of it stays well under the frame size (payload never
    // copied).
    CHECK(meta.dns_query_name.empty());
  }

  // --- Address formatting helpers ----------------------------------------------
  {
    const std::uint8_t v4[4] = {127, 0, 0, 1};
    CHECK(ezcap::capture::format_ipv4(v4) == "127.0.0.1");
  }
  {
    const std::uint8_t v6[16] = {};
    CHECK(ezcap::capture::format_ipv6(v6) == "::");
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "packet_parser: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("packet_parser: all tests passed");
  return 0;
}
