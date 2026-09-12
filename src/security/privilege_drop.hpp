#pragma once

#include <string>
#include <vector>

namespace ezcap::security {

/// Drops the capabilities the daemon does not need after privileged setup
/// (loading eBPF, opening capture devices). Keeps only the minimum
/// capability set for the remaining work (typically none for pcap
/// operation; CAP_BPF/CAP_PERFMON only while the eBPF backend holds its
/// objects).
class PrivilegeDropper {
 public:
  /// Drop all capabilities except `keep`. Returns false with `error` when
  /// libcap is unavailable or the drop fails. Fails closed: on failure the
  /// caller must not continue with elevated privileges.
  [[nodiscard]] static bool drop_to(const std::vector<std::string>& keep,
                                    std::string& error) noexcept;

  /// Drop every capability. Used when no privileged resources remain.
  [[nodiscard]] static bool drop_all(std::string& error) noexcept;

  /// True when the process still holds any capability (for status checks).
  [[nodiscard]] static bool has_capabilities() noexcept;
};

}  // namespace ezcap::security
