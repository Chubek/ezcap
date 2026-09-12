#pragma once

// Host-side state one driver's lezcap bindings operate on (E5, E7).
// The Lua side never sees this object — only its effects.

#include "drivers/lua/manifests/manifest.hpp"
#include "specgen/model/descriptor.hpp"

#include <ezcap/event.hpp>
#include <ezcap/policy.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace ezcap::drivers {

/// Per-driver runtime limits enforced by the bindings (E7). Endpoints and
/// subscriptions start from the engine defaults, lowered by the manifest;
/// no driver may raise a limit.
struct DriverResourceLimits {
  std::uint32_t max_endpoints{8};
  std::uint32_t max_subscriptions{16};
  std::uint32_t max_events_per_second{64};
  std::size_t max_string_bytes{8 * 1024};  ///< Mirrors SandboxBudgets.
};

/// A metadata-only capture filter a script registered via lezcap.capture.
/// Filters are reductions over the existing pipeline (E9): they can only
/// narrow which events the driver receives.
struct CaptureFilter {
  std::string event_type{};   ///< Wire name; empty = all subscribed types.
  std::string transport{};    ///< Optional: "tcp" | "udp" | "icmp".
  std::uint32_t min_confidence_permille{0};  ///< 0..1000.
};

/// Host-side state one driver's bindings operate on. Owned exclusively by
/// the driver engine; the engine is the writer and the bindings read
/// through a per-callback pointer.
struct DriverHostState {
  DriverManifest manifest{};
  DriverResourceLimits limits{};

  // Declared endpoints (E8.1), validated at declaration time.
  std::vector<specgen::EndpointDescriptor> endpoints{};

  // Registered capture filters (E9): reductions only.
  std::vector<CaptureFilter> capture_filters{};

  // Event-rate accounting with drop counts (E7).
  std::uint64_t events_emitted{0};
  std::uint64_t events_dropped{0};
  std::int64_t last_event_window_start_ms{0};
  std::uint32_t events_in_window{0};
};

/// Capability-gated `lezcap` registration (E5.1, E10).
///
/// Registers exactly the modules the manifest declared — a capability not
/// in the set is simply absent from the script's lezcap table, enforced at
/// binding-registration time. Returns false with `error` if the sandboxed
/// state is not usable.
[[nodiscard]] bool register_lezcap(lua::Sandbox& sandbox,
                                   const DriverManifest& manifest,
                                   const DriverResourceLimits& limits,
                                   DriverHostState& host_state,
                                   policy::PolicyEngine& policy_engine,
                                   std::string& error);

}  // namespace ezcap::drivers
