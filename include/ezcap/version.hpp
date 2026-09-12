#pragma once

#include <cstdint>

namespace ezcap {

/// Protocol and event schema version. Breaking changes to any of the
/// protocol/*.schema.json documents require incrementing this value together
/// with the schemas.
inline constexpr std::uint32_t kProtocolVersion = 1;

/// Event schema version carried by every normalized event.
inline constexpr std::uint32_t kEventSchemaVersion = 1;

/// Daemon project version (major.minor.patch).
inline constexpr std::uint32_t kVersionMajor = 0;
inline constexpr std::uint32_t kVersionMinor = 1;
inline constexpr std::uint32_t kVersionPatch = 0;

inline constexpr const char* kVersionString = "0.1.0";

/// Human-readable version string helper.
[[nodiscard]] inline constexpr const char* version_string() noexcept {
  return kVersionString;
}

/// Default path of the daemon's Unix-domain IPC socket.
inline constexpr const char* kDefaultSocketPath = "/run/ezcap/ezcap.sock";

}  // namespace ezcap
