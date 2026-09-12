// Unit tests for the policy engine: apply() redaction/drop behavior and
// update_from_json validation (including the metadata-only invariant).

#include "policy/policy_engine.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <string>

using ezcap::policy::PolicyEngine;
using ezcap::PolicyDecision;
using ezcap::RedactionMode;
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

ezcap::Event make_event() {
  ezcap::Event e;
  e.event_id = "00000000-0000-4000-8000-000000000001";
  e.type = ezcap::EventType::Connection;
  e.source = ezcap::EventSource::Pcap;
  e.confidence = 0.5;

  ezcap::NetworkInfo net;
  net.transport = ezcap::Transport::Tcp;
  net.remote_address = "93.184.216.34";
  net.remote_port = static_cast<ezcap::Port>(443);
  net.dns_query_name = "example.com";
  e.network = net;

  ezcap::BrowserInfo browser;
  browser.url = "https://example.com/page?session=abc";
  browser.title = "Example";
  e.browser = browser;
  return e;
}

}  // namespace

int main() {
  // --- apply(): redacts URL and DNS name by default -------------------------
  {
    PolicyEngine engine;
    auto event = make_event();
    const auto decision = engine.apply(event);
    CHECK(decision == PolicyDecision::Redact);
    CHECK(event.privacy.redacted);
    CHECK(event.privacy.metadata_only);
    CHECK(event.network->dns_query_name == "example.com");  // unchanged (not sensitive)
    CHECK(event.browser->url == "https://example.com/page");  // query stripped
  }

  // --- apply(): sensitive domain drops the browser association ----------------
  {
    PolicyEngine engine;
    std::string err;
    CHECK(engine.update_from_json(
        json{{"redaction", {{"sensitive_domains", {"example.com"}}}}}, err));
    auto event = make_event();
    engine.apply(event);
    // URL domain excluded: association removed, DNS name cleared.
    CHECK(!event.browser.has_value());
    CHECK(event.network->dns_query_name.empty());
    CHECK(event.privacy.redacted);
  }

  // --- apply(): metadata_only=false cannot be represented, but if it were,
  //     the event would be dropped (defensive invariant).
  {
    PolicyEngine engine;
    auto event = make_event();
    event.privacy.metadata_only = false;
    CHECK(engine.apply(event) == PolicyDecision::Drop);
  }

  // --- update_from_json: metadata_only is not disableable ----------------------
  {
    PolicyEngine engine;
    std::string err;
    CHECK(!engine.update_from_json(json{{"metadata_only", false}}, err));
    CHECK(!engine.update_from_json(json{{"metadata_only", "yes"}}, err));
    CHECK(engine.update_from_json(json{{"metadata_only", true}}, err));
  }

  // --- update_from_json: valid mode change ---------------------------------------
  {
    PolicyEngine engine;
    std::string err;
    CHECK(engine.update_from_json(
        json{{"redaction", {{"mode", "domain-hash"}}}}, err));
    CHECK(engine.policy().redaction_mode == RedactionMode::DomainHash);
    CHECK(engine.to_json()["redaction"]["mode"] == "domain-hash");
  }

  // --- update_from_json: rejections -----------------------------------------------
  {
    PolicyEngine engine;
    std::string err;
    CHECK(!engine.update_from_json(json{{"redaction", {{"mode", "no-such-mode"}}}}, err));
    CHECK(!engine.update_from_json(json{{"redaction", 5}}, err));
    CHECK(!engine.update_from_json(json::array(), err));
    CHECK(!engine.update_from_json(
        json{{"redaction", {{"sensitive_domains", {"ok.test", 7}}}}}, err));
    CHECK(!engine.update_from_json(
        json{{"persistence", {{"retention_seconds", 1}}}}, err));  // below floor
    CHECK(!engine.update_from_json(
        json{{"persistence", {{"retention_seconds", 999999999}}}}, err));  // above cap
  }

  // --- update_from_json: retention bounds include valid values ---------------------
  {
    PolicyEngine engine;
    std::string err;
    CHECK(engine.update_from_json(
        json{{"persistence", {{"retention_seconds", 3600}}}}, err));
    CHECK(engine.policy().retention.count() == 3600);
  }

  // --- to_json: metadata_only always true --------------------------------------------
  {
    PolicyEngine engine;
    const auto doc = engine.to_json();
    CHECK(doc.value("metadata_only", false) == true);
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "policy: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("policy: all tests passed");
  return 0;
}
