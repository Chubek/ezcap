#include "redactor.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string_view>

namespace ezcap {

namespace {

/// FNV-1a hash for hostname hashing. Not a keyed hash: hostname hashing is
/// a display-privacy feature (preventing casual reading of hostnames), not
/// an anonymization guarantee against a determined adversary; this limit
/// is documented in docs/privacy.md.
std::string fnv1a_hex(std::string_view data) {
  std::uint64_t hash = 14695981039346656037ULL;
  for (char c : data) {
    hash ^= static_cast<std::uint8_t>(c);
    hash *= 1099511628211ULL;
  }
  char out[17];
  std::snprintf(out, sizeof(out), "%016llx",
                static_cast<unsigned long long>(hash));
  return out;
}

/// Lowercase ASCII, bounded.
std::string to_lower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    out.push_back(c >= 'A' && c <= 'Z'
                      ? static_cast<char>(c - 'A' + 'a')
                      : c);
  }
  return out;
}

/// True when `host` equals `domain` or is a subdomain of it.
bool host_under_domain(std::string_view host, std::string_view domain) {
  if (host == domain) return true;
  if (host.size() <= domain.size()) return false;
  const auto suffix = host.substr(host.size() - domain.size());
  if (suffix != domain) return false;
  return host[host.size() - domain.size() - 1] == '.';
}

}  // namespace

Redactor::Redactor(const Policy& policy) : policy_{policy} {}

bool Redactor::domain_excluded(std::string_view host) const noexcept {
  const std::string lower = to_lower(host);
  return std::any_of(
      policy_.sensitive_domains.begin(), policy_.sensitive_domains.end(),
      [&](const std::string& domain) {
        return host_under_domain(lower, to_lower(domain));
      });
}

std::string Redactor::transform_hostname(std::string_view host) const {
  switch (policy_.redaction_mode) {
    case RedactionMode::DomainHash:
      return fnv1a_hex(host);
    case RedactionMode::DomainMask: {
      // Keep first char, last label, mask the rest: "h*****.example.org"
      std::string masked{host};
      const auto last_dot = masked.find_last_of('.');
      const auto second_dot =
          last_dot == std::string::npos
              ? std::string::npos
              : masked.find_last_of('.', last_dot - 1);
      const auto end =
          second_dot == std::string::npos ? last_dot : second_dot;
      if (end != std::string::npos && end > 1) {
        std::fill(masked.begin() + 1, masked.begin() + static_cast<long>(end),
                  '*');
      }
      return masked;
    }
    default:
      return std::string{host};
  }
}

std::string Redactor::redact_url(std::string_view url) const {
  std::array<bool, static_cast<std::size_t>(RedactionKind::Count)> redactions{};
  std::string result{url};

  // Extract host for the exclusion check.
  const auto scheme = result.find("://");
  const auto host_start = scheme == std::string::npos ? 0 : scheme + 3;
  const auto host_end = result.find_first_of("/?#", host_start);
  const std::string host = result.substr(
      host_start, host_end == std::string::npos ? std::string::npos
                                                : host_end - host_start);

  if (!host.empty() && domain_excluded(host)) {
    redactions[static_cast<std::size_t>(RedactionKind::DomainExcluded)] = true;
    last_redactions_ = redactions;
    return {};
  }

  // Fragment removal first, then query string.
  if (policy_.strip_fragment) {
    const auto frag = result.find('#');
    if (frag != std::string::npos) {
      result.resize(frag);
      redactions[static_cast<std::size_t>(RedactionKind::Fragment)] = true;
    }
  }
  if (policy_.strip_query_string) {
    const auto query = result.find('?');
    if (query != std::string::npos) {
      result.resize(query);
      redactions[static_cast<std::size_t>(RedactionKind::QueryString)] = true;
    }
  }

  if (policy_.redaction_mode == RedactionMode::HostnameOnly) {
    // Scheme + host only.
    if (scheme != std::string::npos) {
      const auto path_start = result.find('/', host_start);
      if (path_start != std::string::npos) {
        result.resize(path_start);
      }
      redactions[static_cast<std::size_t>(RedactionKind::QueryString)] = true;
    }
  }

  // Hostname transforms apply in hash/mask modes.
  if (policy_.redaction_mode == RedactionMode::DomainHash ||
      policy_.redaction_mode == RedactionMode::DomainMask) {
    if (scheme != std::string::npos) {
      const auto new_host = transform_hostname(host);
      const auto host_end2 =
          result.find_first_of("/?#", host_start);
      const std::string prefix = result.substr(0, host_start);
      const std::string suffix =
          host_end2 == std::string::npos
              ? std::string{}
              : result.substr(host_end2);
      result = prefix + new_host + suffix;
      redactions[static_cast<std::size_t>(
          policy_.redaction_mode == RedactionMode::DomainHash
              ? RedactionKind::HostnameHash
              : RedactionKind::HostnameMask)] = true;
    }
  }

  last_redactions_ = redactions;
  return result;
}

std::string Redactor::redact_dns_name(std::string_view name) const {
  std::array<bool, static_cast<std::size_t>(RedactionKind::Count)> redactions{};

  if (name.empty()) {
    last_redactions_ = redactions;
    return {};
  }
  if (domain_excluded(name)) {
    redactions[static_cast<std::size_t>(RedactionKind::DomainExcluded)] = true;
    last_redactions_ = redactions;
    return {};
  }

  std::string result;
  switch (policy_.redaction_mode) {
    case RedactionMode::DomainHash:
      result = fnv1a_hex(name);
      redactions[static_cast<std::size_t>(RedactionKind::HostnameHash)] = true;
      break;
    case RedactionMode::DomainMask:
      result = transform_hostname(name);
      redactions[static_cast<std::size_t>(RedactionKind::HostnameMask)] = true;
      break;
    default:
      result = std::string{name};
      break;
  }

  last_redactions_ = redactions;
  return result;
}

// ---- Policy static helpers ----

const char* Policy::redaction_mode_name(RedactionMode mode) noexcept {
  switch (mode) {
    case RedactionMode::HostnameOnly:
      return "hostname-only";
    case RedactionMode::QueryStringRemoval:
      return "query-string-removal";
    case RedactionMode::FullHostname:
      return "full-hostname";
    case RedactionMode::DomainHash:
      return "domain-hash";
    case RedactionMode::DomainMask:
      return "domain-mask";
  }
  return "query-string-removal";
}

bool Policy::redaction_mode_from_name(std::string_view name,
                                      RedactionMode& out) noexcept {
  if (name == "hostname-only") {
    out = RedactionMode::HostnameOnly;
  } else if (name == "query-string-removal") {
    out = RedactionMode::QueryStringRemoval;
  } else if (name == "full-hostname") {
    out = RedactionMode::FullHostname;
  } else if (name == "domain-hash") {
    out = RedactionMode::DomainHash;
  } else if (name == "domain-mask") {
    out = RedactionMode::DomainMask;
  } else {
    return false;
  }
  return true;
}

}  // namespace ezcap
