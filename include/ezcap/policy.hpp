#pragma once

#include <array>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace ezcap {

/// Kinds of redaction that can be applied to URLs and DNS names. The order
/// matches PrivacyInfo::redactions.
enum class RedactionKind {
  QueryString,     ///< Strip everything from '?' onward.
  Fragment,        ///< Strip everything from '#' onward.
  HostnameHash,    ///< Replace hostname with a salted hash.
  HostnameMask,    ///< Replace hostname with a masked form (h**n.example.org).
  DomainExcluded,  ///< Field omitted entirely for sensitive domains.
  Count,
};

/// URL/DNS redaction mode. Mirrors the enum in
/// protocol/schema/daemon_request.schema.json.
enum class RedactionMode {
  HostnameOnly,        ///< Scheme + host only.
  QueryStringRemoval,  ///< Keep path, drop query and fragment.
  FullHostname,        ///< Keep path; may still drop query/fragment per flags.
  DomainHash,          ///< Hash hostnames.
  DomainMask,          ///< Mask hostnames.
};

/// The capture and privacy policy. Metadata-only is not configurable: it is
/// a constant of the system and attempts to disable it are rejected.
struct Policy {
  // Redaction settings.
  RedactionMode redaction_mode{RedactionMode::QueryStringRemoval};
  bool strip_query_string{true};
  bool strip_fragment{true};
  std::vector<std::string> sensitive_domains{};  ///< Excluded entirely.

  // Persistence (disabled by default).
  bool persistence_enabled{false};
  std::chrono::seconds retention{std::chrono::seconds{86400 * 7}};

  // Capture settings.
  std::vector<std::string> capture_interfaces{};  ///< Empty = default route.
  std::string pcap_filter{"ip or ip6"};           ///< Applied early (BPF).

  /// Metadata-only mode. Always true; the setter enforces this.
  [[nodiscard]] static constexpr bool metadata_only() noexcept { return true; }

  /// Parse a redaction mode wire name; false on unknown values.
  [[nodiscard]] static bool redaction_mode_from_name(std::string_view name,
                                                     RedactionMode& out) noexcept;

  /// Wire name of a redaction mode.
  [[nodiscard]] static const char* redaction_mode_name(RedactionMode mode) noexcept;
};

/// Decision produced by the policy engine for an event.
enum class PolicyDecision {
  Allow,
  Redact,
  Drop,
};

/// Centralized redaction interface. All URL/DNS redaction must go through
/// src/policy/redactor.* — no component may implement its own redaction.
class Redactor {
 public:
  explicit Redactor(const Policy& policy);

  /// Redact a URL according to the policy. Returns the redacted URL, or
  /// std::nullopt-equivalent empty string when the domain is excluded.
  [[nodiscard]] std::string redact_url(std::string_view url) const;

  /// Redact a DNS query name according to the policy. Returns an empty
  /// string when the domain is excluded.
  [[nodiscard]] std::string redact_dns_name(std::string_view name) const;

  /// Which redaction kinds were applied to the last value. Populated by the
  /// redact calls; exposed for the event's privacy annotations.
  [[nodiscard]] std::array<bool, static_cast<std::size_t>(RedactionKind::Count)>
  last_redactions() const noexcept {
    return last_redactions_;
  }

 private:
  [[nodiscard]] bool domain_excluded(std::string_view host) const noexcept;
  [[nodiscard]] std::string transform_hostname(std::string_view host) const;

  Policy policy_;
  std::array<bool, static_cast<std::size_t>(RedactionKind::Count)> last_redactions_{};
};

}  // namespace ezcap
