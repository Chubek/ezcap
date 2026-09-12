#pragma once

#include <ezcap/event_types.hpp>

namespace ezcap::attribution {

/// Evidence kinds contributing to an attribution score. Each carries a
/// fixed weight; the sum is clamped to [0, 1].
enum class EvidenceKind {
  ProcessMatch,      ///< Socket table or eBPF pid matches a known browser pid.
  TemporalProximity, ///< Network event close in time to a browser navigation.
  HostCorrelation,   ///< Remote host matches the navigation's host.
  DirectBrowserEvent,///< The browser itself reported the activity.
  PcapOnly,          ///< Only pcap evidence: no process identity.
};

/// Score a single evidence combination into a confidence value. Explicit
/// and conservative: pcap-only evidence can never exceed the weak band,
/// and no combination of indirect evidence reaches the direct band.
[[nodiscard]] double score_evidence(bool process_match,
                                    bool temporal_match,
                                    bool host_match,
                                    bool direct_browser_event,
                                    bool pcap_only) noexcept;

/// Cap for pcap-derived tab attribution. libpcap cannot identify browser
/// tabs, so pcap-based correlation is capped at the top of the probable
/// band by construction.
inline constexpr double kPcapAttributionCap = 0.69;

/// Confidence floor for events with no evidence at all.
inline constexpr double kNoEvidenceScore = 0.0;

}  // namespace ezcap::attribution
