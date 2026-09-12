#pragma once

#include <string>
#include <vector>

namespace ezcap::security {

/// Seccomp filter for the post-setup daemon: the IPC, capture, and logging
/// syscalls the daemon legitimately needs, and nothing else. Applied after
/// all setup (socket bound, backends started); a failure to install the
/// filter is fatal-by-choice — fail closed.
class Sandbox {
 public:
  /// Install the default allowlist filter. Returns false with `error`
  /// when libseccomp is unavailable or installation fails.
  [[nodiscard]] static bool install(std::string& error) noexcept;
};

}  // namespace ezcap::security
