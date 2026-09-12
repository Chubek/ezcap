#pragma once

#include <ezcap/event.hpp>

#include "attribution/confidence.hpp"

#include <chrono>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ezcap::attribution {

/// A browser navigation observation supplied by the extension through the
/// native host. These are direct browser events: they carry real tab
/// identity but no packet-level information.
struct NavigationObservation {
  std::chrono::system_clock::time_point timestamp{};
  std::uint64_t tab_id{0};
  std::uint64_t window_id{0};
  std::string host{};   ///< Redacted hostname of the navigation.
  std::string url{};    ///< Redacted URL.
  std::string title{};
  std::string navigation_id{};
  std::uint64_t frame_id{0};
};

/// A known browser process (pid) supplied by the extension at handshake.
struct BrowserProcess {
  ProcessId pid{0};
  std::string name{};
};

/// Correlates network observations with browser activity. All correlation
/// is best-effort: results always carry an explicit confidence score and
/// are never presented as definite tab attribution unless the browser
/// reported the activity itself.
class Correlator {
 public:
  /// How long navigation observations stay eligible for correlation.
  static constexpr auto kNavigationWindow = std::chrono::seconds{10};
  /// Maximum retained navigations (bounded memory).
  static constexpr std::size_t kMaxNavigations = 512;

  /// Attach browser info to a network event when evidence exists.
  /// Returns the (possibly upgraded) event; confidence is only ever
  /// computed from evidence, never defaulted upward.
  ezcap::Event correlate(ezcap::Event event);

  /// Record a navigation observation from the browser.
  void record_navigation(NavigationObservation observation);

  /// Record the set of browser process ids (replaces the previous set).
  void set_browser_processes(std::vector<BrowserProcess> processes);

  /// True when the pid belongs to a known browser process.
  [[nodiscard]] bool is_browser_process(ProcessId pid) const;

 private:
  [[nodiscard]] std::optional<NavigationObservation> best_match(
      const ezcap::Event& event) const;

  mutable std::mutex mutex_;
  std::deque<NavigationObservation> navigations_;
  std::vector<BrowserProcess> browser_processes_;
};

}  // namespace ezcap::attribution
