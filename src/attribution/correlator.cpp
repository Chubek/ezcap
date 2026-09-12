#include "correlator.hpp"

#include <algorithm>
#include <cstdlib>
#include <utility>

namespace ezcap::attribution {

namespace {

/// Extract the host from a redacted URL, if present.
std::string url_host(const std::string& url) {
  const auto scheme = url.find("://");
  if (scheme == std::string::npos) {
    return {};
  }
  const auto host_start = scheme + 3;
  const auto host_end = url.find('/', host_start);
  std::string host =
      url.substr(host_start, host_end == std::string::npos
                                 ? std::string::npos
                                 : host_end - host_start);
  // Strip userinfo (should not appear post-redaction, but be defensive).
  const auto at = host.find('@');
  if (at != std::string::npos) {
    host.erase(0, at + 1);
  }
  const auto colon = host.find(':');
  if (colon != std::string::npos) {
    host.erase(colon);
  }
  return host;
}

/// Absolute duration between two time points.
std::chrono::system_clock::duration abs_delta(
    std::chrono::system_clock::time_point a,
    std::chrono::system_clock::time_point b) {
  return a > b ? a - b : b - a;
}

}  // namespace

void Correlator::record_navigation(NavigationObservation observation) {
  std::lock_guard<std::mutex> lock{mutex_};
  navigations_.push_back(std::move(observation));
  while (navigations_.size() > kMaxNavigations) {
    navigations_.pop_front();
  }
}

void Correlator::set_browser_processes(std::vector<BrowserProcess> processes) {
  std::lock_guard<std::mutex> lock{mutex_};
  browser_processes_ = std::move(processes);
}

bool Correlator::is_browser_process(ProcessId pid) const {
  std::lock_guard<std::mutex> lock{mutex_};
  return std::any_of(browser_processes_.begin(), browser_processes_.end(),
                     [pid](const BrowserProcess& p) { return p.pid == pid; });
}

std::optional<NavigationObservation> Correlator::best_match(
    const ezcap::Event& event) const {
  // Caller holds mutex_.
  std::optional<NavigationObservation> best;
  auto best_delta = std::chrono::system_clock::duration::max();
  bool best_host_match = false;

  const std::string event_host =
      event.network ? event.network->dns_query_name : std::string{};

  for (const auto& nav : navigations_) {
    const auto delta = abs_delta(nav.timestamp, event.timestamp);
    if (delta > kNavigationWindow) {
      continue;
    }
    // Host evidence: only when we have both a DNS name and a navigation
    // host to compare. Never guess.
    const bool host_match =
        !event_host.empty() && !nav.host.empty() && event_host == nav.host;

    const bool better =
        !best || (host_match && !best_host_match) ||
        (host_match == best_host_match && delta < best_delta);
    if (better) {
      best = nav;
      best_delta = delta;
      best_host_match = host_match;
    }
  }
  return best;
}

ezcap::Event Correlator::correlate(ezcap::Event event) {
  // Only network-flavored events participate in correlation.
  if (event.type != EventType::Connection && event.type != EventType::Dns) {
    return event;
  }

  const bool pcap_only = event.source == EventSource::Pcap;
  const bool process_match =
      event.process.has_value() && is_browser_process(event.process->pid);

  std::optional<NavigationObservation> match;
  {
    std::lock_guard<std::mutex> lock{mutex_};
    // Prune expired navigations opportunistically.
    const auto now = std::chrono::system_clock::now();
    while (!navigations_.empty() &&
           now - navigations_.front().timestamp > kNavigationWindow * 4) {
      navigations_.pop_front();
    }
    match = best_match(event);
  }

  const bool temporal_match = match.has_value();
  const bool host_match =
      match.has_value() && event.network &&
      !event.network->dns_query_name.empty() &&
      event.network->dns_query_name == match->host;

  const double confidence = score_evidence(
      process_match, temporal_match, host_match,
      /*direct_browser_event=*/false, pcap_only);

  event.confidence = confidence;

  if (match && confidence >= 0.40) {
    ezcap::BrowserInfo browser;
    browser.tab_id = match->tab_id;
    browser.window_id = match->window_id;
    browser.url = match->url;
    browser.title = match->title;
    browser.navigation_id = match->navigation_id;
    browser.frame_id = match->frame_id;
    event.browser = std::move(browser);
  }
  // Below the probable threshold the association is too weak to attach:
  // the event ships without tab info rather than with a guess.

  return event;
}

}  // namespace ezcap::attribution
