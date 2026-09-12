#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace ezcap::time_util {

/// Wall-clock now, single source so tests can be deterministic where needed.
[[nodiscard]] std::chrono::system_clock::time_point now() noexcept;

/// Format a time point as an RFC 3339 UTC timestamp with milliseconds,
/// e.g. "2026-09-12T07:41:03.512Z".
[[nodiscard]] std::string to_rfc3339(
    std::chrono::system_clock::time_point tp) noexcept;

/// Parse an RFC 3339 timestamp; returns epoch==0 time point on failure.
[[nodiscard]] std::chrono::system_clock::time_point from_rfc3339(
    const std::string& text) noexcept;

/// Convert a monotonic-ish nanosecond counter (e.g. ktime) plus the daemon
/// boot offset into a wall-clock time point.
[[nodiscard]] std::chrono::system_clock::time_point from_ktime_ns(
    std::uint64_t ktime_ns,
    std::chrono::system_clock::time_point boot_walltime) noexcept;

}  // namespace ezcap::time_util
