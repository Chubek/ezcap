// Unit tests for the centralized redactor: query/fragment stripping,
// sensitive-domain exclusion (exact and subdomain), hostname hash/mask
// modes, and DNS name handling.

#include "policy/redactor.hpp"

#include <cstdio>
#include <string>

using ezcap::Redactor;
using ezcap::RedactionMode;
using ezcap::RedactionKind;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

#define CHECK_EQ(a, b)                                                  \
  do {                                                                  \
    const auto va_ = (a);                                               \
    const auto vb_ = (b);                                               \
    if (!(va_ == vb_)) {                                                \
      std::fprintf(stderr, "FAIL %s:%d: %s == %s (%s vs %s)\n",          \
                   __FILE__, __LINE__, #a, #b,                          \
                   std::to_string(va_).c_str(),                          \
                   std::to_string(vb_).c_str());                        \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

}  // namespace

int main() {
  // --- Defaults: strip query + fragment -----------------------------------
  {
    ezcap::Policy p;
    Redactor r{p};
    CHECK(r.redact_url("https://example.com/path?a=1&token=xyz#frag") ==
          "https://example.com/path");
    CHECK(r.redact_url("https://example.com/#section") == "https://example.com/");
    CHECK(r.redact_url("https://example.com") == "https://example.com");
    // Redaction annotations.
    const auto kinds = r.last_redactions();
    CHECK(kinds[static_cast<std::size_t>(RedactionKind::QueryString)]);
    CHECK(kinds[static_cast<std::size_t>(RedactionKind::Fragment)]);
  }

  // --- Flags off: query preserved when explicitly allowed ------------------
  {
    ezcap::Policy p;
    p.strip_query_string = false;
    p.strip_fragment = false;
    Redactor r{p};
    CHECK(r.redact_url("https://example.com/p?a=1#f") == "https://example.com/p?a=1#f");
  }

  // --- Sensitive domains: exact and subdomain, case-insensitive -------------
  {
    ezcap::Policy p;
    p.sensitive_domains = {"accounts.google.com", "bank.example"};
    Redactor r{p};
    CHECK(r.redact_url("https://accounts.google.com/signin?continue=x").empty());
    CHECK(r.redact_url("https://mail.accounts.google.com/inbox").empty());
    CHECK(r.redact_url("https://ACCOUNTS.GOOGLE.COM/").empty());
    // Not a subdomain: no dot boundary.
    CHECK(!r.redact_url("https://fakeaccounts.google.com.evil.test/").empty());
    // Unrelated domain untouched.
    CHECK(r.redact_url("https://example.com/") == "https://example.com/");
  }

  // --- DNS names: sensitive domains excluded ---------------------------------
  {
    ezcap::Policy p;
    p.sensitive_domains = {"bank.example"};
    Redactor r{p};
    CHECK(r.redact_dns_name("www.bank.example").empty());
    CHECK(r.redact_dns_name("example.com") == "example.com");
    CHECK(r.redact_dns_name("").empty());
  }

  // --- Hostname-only mode -----------------------------------------------------
  {
    ezcap::Policy p;
    p.redaction_mode = RedactionMode::HostnameOnly;
    Redactor r{p};
    CHECK(r.redact_url("https://example.com/deep/path/one") == "https://example.com");
  }

  // --- Domain-hash mode --------------------------------------------------------
  {
    ezcap::Policy p;
    p.redaction_mode = RedactionMode::DomainHash;
    Redactor r{p};
    const auto out = r.redact_url("https://example.com/path");
    // Host replaced by a 16-hex-char FNV-1a digest, path kept.
    CHECK(out.size() > 8);
    CHECK(out.find("example.com") == std::string::npos);
    CHECK(out.compare(0, 8, "https://") == 0);
    CHECK(out.find("/path") != std::string::npos);
    CHECK(r.redact_dns_name("example.com").size() == 16);
    const auto kinds = r.last_redactions();
    CHECK(kinds[static_cast<std::size_t>(RedactionKind::HostnameHash)]);
  }

  // --- Domain-mask mode ----------------------------------------------------------
  {
    ezcap::Policy p;
    p.redaction_mode = RedactionMode::DomainMask;
    Redactor r{p};
    const auto out = r.redact_dns_name("www.example.org");
    // First char kept, interior masked, suffix kept.
    CHECK(out.find("www") == std::string::npos);
    CHECK(out.find("example.org") != std::string::npos);
    CHECK(out.front() == 'w');
    CHECK(out.find('*') != std::string::npos);
  }

  // --- Hash determinism ------------------------------------------------------------
  {
    ezcap::Policy p;
    p.redaction_mode = RedactionMode::DomainHash;
    Redactor r{p};
    CHECK(r.redact_dns_name("a.test") == r.redact_dns_name("a.test"));
    CHECK(r.redact_dns_name("a.test") != r.redact_dns_name("b.test"));
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "redactor: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("redactor: all tests passed");
  return 0;
}
