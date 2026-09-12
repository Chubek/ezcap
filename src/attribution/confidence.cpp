#include "confidence.hpp"

#include <algorithm>

namespace ezcap::attribution {

namespace {

// Evidence weights. Sum of all indirect evidence stays below the direct
// band threshold (0.90) by construction; only a direct browser event can
// cross it.
constexpr double kWeightProcess = 0.40;
constexpr double kWeightTemporal = 0.12;
constexpr double kWeightHost = 0.18;
constexpr double kWeightDirect = 0.95;

}  // namespace

double score_evidence(bool process_match, bool temporal_match,
                      bool host_match, bool direct_browser_event,
                      bool pcap_only) noexcept {
  if (direct_browser_event) {
    // The browser itself reported the activity: reliable.
    return kWeightDirect;
  }

  double score = 0.0;
  if (process_match) {
    score += kWeightProcess;
  }
  if (temporal_match) {
    score += kWeightTemporal;
  }
  if (host_match) {
    score += kWeightHost;
  }

  if (pcap_only) {
    // pcap frames carry no process identity; correlation can at best be
    // probable, never strong or direct.
    score = std::min(score, kPcapAttributionCap);
  }

  return std::clamp(score, kNoEvidenceScore, 1.0);
}

}  // namespace ezcap::attribution
