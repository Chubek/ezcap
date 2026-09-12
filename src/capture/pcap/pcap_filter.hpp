#pragma once

#include <string>
#include <vector>

namespace ezcap::capture {

/// Validation of user-supplied BPF filter expressions before they ever
/// reach libpcap. Filter strings are untrusted input: only the restricted
/// ezcap filter grammar is accepted (proto/host/port/dns terms combined
/// with and/or/not), which prevents both filter-injection oddities and
/// accidentally capturing more than intended.
class PcapFilterValidator {
 public:
  /// Validate a filter expression. Returns true when it uses only the
  /// allowed grammar. `error` receives a reason on failure.
  [[nodiscard]] static bool validate(const std::string& filter,
                                     std::string& error);

  /// The default metadata filter: IP traffic only.
  [[nodiscard]] static const char* default_filter() noexcept {
    return "ip or ip6";
  }
};

}  // namespace ezcap::capture
