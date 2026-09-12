// Unit tests for attribution: evidence scoring, confidence bands, the
// pcap attribution cap, and the correlator's navigation matching.

#include "attribution/confidence.hpp"
#include "attribution/correlator.hpp"

#include <chrono>
#include <cstdio>
#include <string>

using ezcap::attribution::Correlator;
using ezcap::attribution::NavigationObservation;
using ezcap::attribution::score_evidence;
using ezcap::attribution::kPcapAttributionCap;
using ezcap::ConfidenceBand;
using ezcap::EventType;
using ezcap::EventSource;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

ezcap::Event network_event(EventSource source, const std::string& dns_name) {
  ezcap::Event e;
  e.event_id = "00000000-0000-4000-8000-000000000002";
  e.type = EventType::Connection;
  e.source = source;
  e.timestamp = std::chrono::system_clock::now();

  ezcap::NetworkInfo net;
  net.transport = ezcap::Transport::Tcp;
  net.dns_query_name = dns_name;
  e.network = net;
  return e;
}

NavigationObservation nav(std::chrono::system_clock::time_point ts,
                          const std::string& host,
                          std::uint64_t tab_id) {
  NavigationObservation n;
  n.timestamp = ts;
  n.host = host;
  n.tab_id = tab_id;
  n.url = "https://" + host + "/";
  return n;
}

}  // namespace

int main() {
  using namespace std::chrono_literals;

  // --- Evidence scoring: bands ------------------------------------------------
  CHECK(score_evidence(false, false, false, false, false) == 0.0);  // no evidence
  CHECK(score_evidence(true, true, true, false, false) > 0.69);     // all indirect
  CHECK(score_evidence(true, true, true, false, false) < 0.90);     // never direct
  CHECK(score_evidence(false, false, false, true, false) >= 0.90);  // direct band
  CHECK(ezcap::confidence_band(score_evidence(false, false, false, true, false)) ==
        ConfidenceBand::Direct);

  // Temporal alone: weak.
  CHECK(ezcap::confidence_band(score_evidence(false, true, false, false, false)) ==
        ConfidenceBand::Weak);

  // Process alone: 0.40 — bottom of probable.
  CHECK(ezcap::confidence_band(score_evidence(true, false, false, false, false)) ==
        ConfidenceBand::Probable);

  // --- The pcap cap: no combination of indirect evidence escapes probable -----
  const double capped = score_evidence(true, true, true, false, true);
  CHECK(capped <= kPcapAttributionCap);
  CHECK(capped <= 0.69);
  CHECK(ezcap::confidence_band(capped) == ConfidenceBand::Probable);
  // Even a direct event is direct regardless (browser-reported truth).
  CHECK(score_evidence(false, false, false, true, true) >= 0.90);

  // --- Correlator: navigation window ---------------------------------------------
  {
    Correlator c;
    auto now = std::chrono::system_clock::now();
    c.record_navigation(nav(now - 1s, "example.com", 42));

    auto e = network_event(EventSource::Pcap, "example.com");
    e.timestamp = now;
    e = c.correlate(e);
    CHECK(e.browser.has_value());  // temporal + host match reaches probable
    CHECK(e.browser->tab_id == 42);
    CHECK(e.confidence >= 0.40);
    CHECK(e.confidence <= kPcapAttributionCap);  // pcap: capped
  }

  // Stale navigation: outside the window, no association attached.
  {
    Correlator c;
    auto now = std::chrono::system_clock::now();
    c.record_navigation(nav(now - 60s, "example.com", 42));
    auto e = network_event(EventSource::Pcap, "example.com");
    e.timestamp = now;
    e = c.correlate(e);
    CHECK(!e.browser.has_value());
    CHECK(e.confidence < 0.40);
  }

  // No navigations recorded: event passes through untouched.
  {
    Correlator c;
    auto e = network_event(EventSource::Pcap, "example.com");
    e = c.correlate(e);
    CHECK(!e.browser.has_value());
    CHECK(e.confidence == 0.0);
  }

  // Host mismatch lowers confidence: temporal only stays weak.
  {
    Correlator c;
    auto now = std::chrono::system_clock::now();
    c.record_navigation(nav(now - 1s, "other.example", 7));
    auto e = network_event(EventSource::Pcap, "example.com");
    e.timestamp = now;
    e = c.correlate(e);
    CHECK(!e.browser.has_value());  // weak: do not attach a guess
    CHECK(e.confidence < 0.40);
  }

  // --- Correlator: browser process ids --------------------------------------------
  {
    Correlator c;
    c.set_browser_processes({{1234, "firefox"}, {5678, "chromium"}});
    CHECK(c.is_browser_process(1234));
    CHECK(!c.is_browser_process(9999));

    // Process match + temporal + host from an eBPF event: strong band.
    auto now = std::chrono::system_clock::now();
    c.record_navigation(nav(now - 1s, "example.com", 42));
    auto e = network_event(EventSource::Ebpf, "example.com");
    e.timestamp = now;
    ezcap::ProcessInfo proc;
    proc.pid = 1234;
    e.process = proc;
    e = c.correlate(e);
    CHECK(e.confidence > 0.69);
    CHECK(ezcap::confidence_band(e.confidence) == ConfidenceBand::Strong);
  }

  // --- Non-network events are not correlated -----------------------------------------
  {
    Correlator c;
    ezcap::Event e;
    e.type = EventType::Status;
    e.confidence = 0.99;
    auto out = c.correlate(e);
    CHECK(out.confidence == 0.99);  // untouched
  }

  // --- Bounded memory: navigations past the cap are evicted ---------------------------
  {
    Correlator c;
    const auto now = std::chrono::system_clock::now();
    for (std::size_t i = 0; i < Correlator::kMaxNavigations + 100; ++i) {
      c.record_navigation(nav(now, "host" + std::to_string(i) + ".test", i));
    }
    // The most recent navigation (oldest evicted) is still matchable.
    auto e = network_event(EventSource::Pcap,
                           "host" + std::to_string(Correlator::kMaxNavigations + 99) +
                               ".test");
    e.timestamp = now;
    e = c.correlate(e);
    CHECK(e.browser.has_value());
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "correlator: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("correlator: all tests passed");
  return 0;
}
