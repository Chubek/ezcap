// Integration test for the composed event pipeline: packet metadata ->
// normalizer -> correlator -> policy engine -> IPC encoding, asserting the
// invariants that hold at every stage (metadata-only, redaction applied,
// confidence capped for pcap, forbidden fields absent from the encoding).
// Also exercises the SQLite store end-to-end on a temp database.

#include "attribution/correlator.hpp"
#include "capture/event_normalizer.hpp"
#include "capture/packet_parser.hpp"
#include "ipc/ipc_codec.hpp"
#include "policy/policy_engine.hpp"
#include "storage/sqlite_store.hpp"

#include <nlohmann/json.hpp>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using ezcap::attribution::Correlator;
using ezcap::attribution::NavigationObservation;
using ezcap::capture::EventNormalizer;
using ezcap::capture::PacketMetadata;
using ezcap::policy::PolicyEngine;
using ezcap::ipc::IpcCodec;
using ezcap::storage::SqliteStore;
using nlohmann::json;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

PacketMetadata dns_lookup(const std::string& name) {
  PacketMetadata meta;
  meta.valid = true;
  meta.transport = ezcap::Transport::Udp;
  meta.local_address = "10.0.0.2";
  meta.remote_address = "1.1.1.1";
  meta.source_port = static_cast<ezcap::Port>(40000);
  meta.destination_port = static_cast<ezcap::Port>(53);
  meta.dns_query_name = name;
  meta.has_dns_response_code = true;
  return meta;
}

std::string temp_path(const char* tag) {
  char buf[128];
  std::snprintf(buf, sizeof(buf), "/tmp/ezcap-pipeline-%s-XXXXXX", tag);
  std::vector<char> tmpl(buf, buf + std::strlen(buf) + 1);
  const int fd = ::mkstemp(tmpl.data());
  if (fd < 0) return "/tmp/ezcap-pipeline-fallback.db";
  ::close(fd);
  ::unlink(tmpl.data());
  return tmpl.data();
}

}  // namespace

int main() {
  using namespace std::chrono_literals;

  EventNormalizer normalizer{"test"};
  Correlator correlator;
  PolicyEngine policy;

  // Stage a navigation so the correlator has evidence.
  {
    NavigationObservation nav;
    nav.timestamp = std::chrono::system_clock::now();
    nav.host = "example.com";
    nav.tab_id = 7;
    nav.url = "https://example.com/private?token=abc";
    correlator.record_navigation(nav);
  }

  // --- A DNS event for a navigated host --------------------------------------
  auto meta = dns_lookup("example.com");
  auto event = normalizer.dns_from_packet_metadata(
      meta, std::chrono::system_clock::now(), "eth0");

  CHECK(event.type == ezcap::EventType::Dns);
  CHECK(event.source == ezcap::EventSource::Pcap);
  CHECK(event.privacy.metadata_only);
  CHECK(!event.network->dns_query_name.empty());

  // Correlate: pcap event with temporal+host evidence -> probable, capped.
  event = correlator.correlate(event);
  CHECK(event.confidence >= 0.40);
  CHECK(event.confidence <= ezcap::attribution::kPcapAttributionCap);
  CHECK(event.browser.has_value());
  CHECK(event.browser->tab_id == 7);

  // Policy: the navigation URL's query string must be gone by now.
  const auto decision = policy.apply(event);
  CHECK(decision != ezcap::PolicyDecision::Drop);
  CHECK(event.browser->url.find("token=abc") == std::string::npos);
  CHECK(event.browser->url.find('?') == std::string::npos);
  CHECK(event.privacy.metadata_only);

  // IPC encoding: no forbidden fields anywhere.
  const auto encoded = IpcCodec::encode_event(event);
  const auto doc = json::parse(encoded);
  for (const char* forbidden : {"payload", "body", "cookies", "authorization",
                                "password", "api_key"}) {
    CHECK(!doc.contains(forbidden));
  }
  CHECK(doc.at("privacy").at("metadata_only").get<bool>() == true);

  // --- Sensitive domain: the association is dropped entirely ---------------------
  {
    NavigationObservation nav;
    nav.timestamp = std::chrono::system_clock::now();
    nav.host = "secret.bank.example";
    nav.tab_id = 9;
    nav.url = "https://secret.bank.example/login";
    correlator.record_navigation(nav);

    auto meta2 = dns_lookup("secret.bank.example");
    auto event2 = normalizer.dns_from_packet_metadata(
        meta2, std::chrono::system_clock::now(), "eth0");
    event2 = correlator.correlate(event2);

    std::string err;
    CHECK(policy.update_from_json(
        json{{"redaction", {{"sensitive_domains", {"bank.example"}}}}}, err));
    policy.apply(event2);
    // Either the whole association is gone, or nothing sensitive survives.
    if (event2.browser) {
      CHECK(event2.browser->url.empty());
    } else {
      CHECK(!event2.browser.has_value());
    }
    CHECK(event2.network->dns_query_name.empty());
  }

  // --- Storage round-trip on a temp database --------------------------------------
  {
    const std::string path = temp_path("store");
    std::string serr;
    SqliteStore store{path, serr};
    CHECK(serr.empty());

    store.store(event);
    store.store(event);
    // Give the writer thread a moment to drain the queue.
    std::this_thread::sleep_for(200ms);
    CHECK(store.stored_count() == 2);
    CHECK(store.dropped_count() == 0);
    CHECK(store.schema_version() >= 1);

    // Prune with a far-future cutoff clears everything.
    store.prune(std::chrono::seconds{3600});
    std::this_thread::sleep_for(200ms);
    CHECK(store.stored_count() == 0);

    ::unlink(path.c_str());
  }

  // --- The encode -> validate loop: the encoded event parses as JSON with the
  //     expected core fields every time (schema sanity across many events).
  {
    for (int i = 0; i < 50; ++i) {
      auto m = dns_lookup("host" + std::to_string(i) + ".test");
      auto e = normalizer.dns_from_packet_metadata(
          m, std::chrono::system_clock::now(), "eth0");
      e = correlator.correlate(std::move(e));
      policy.apply(e);
      const auto d = json::parse(IpcCodec::encode_event(e));
      CHECK(d.contains("event_id"));
      CHECK(d.contains("timestamp"));
      CHECK(d.at("privacy").at("metadata_only").get<bool>());
    }
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "capture_pipeline: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("capture_pipeline: all tests passed");
  return 0;
}
