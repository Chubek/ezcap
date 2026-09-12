#pragma once

// C-compatible eBPF event structures shared with the kernel-side programs.
// This header simply re-exports the canonical definitions from ebpf/include
// so daemon sources can include it without C-only flags.
#include <linux/types.h>

#include "ebpf_events.h"

#include <ezcap/event.hpp>

namespace ezcap::capture {

/// Convert a kernel connect event into a normalized event.
/// `boot_walltime` anchors ktime to wall clock.
[[nodiscard]] ezcap::Event normalize_connect_event(
    const ezcap_connect_event& raw,
    std::chrono::system_clock::time_point boot_walltime);

/// Convert a kernel DNS event into a normalized event.
[[nodiscard]] ezcap::Event normalize_dns_event(
    const ezcap_dns_event& raw,
    std::chrono::system_clock::time_point boot_walltime);

/// Convert a kernel socket-state event into a normalized event.
[[nodiscard]] ezcap::Event normalize_socket_state_event(
    const ezcap_socket_state_event& raw,
    std::chrono::system_clock::time_point boot_walltime);

}  // namespace ezcap::capture
