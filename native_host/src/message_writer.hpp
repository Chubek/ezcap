#pragma once

#include <string>

namespace ezcap::native_host {

/// Writes Native Messaging frames to stdout: a 4-byte little-endian length
/// prefix followed by the UTF-8 JSON payload. Output is flushed per frame.
/// Only ever writes to stdout — never to a socket, file, or terminal.
class MessageWriter {
 public:
  /// Write one frame to `fd`. Returns false on write error (the browser
  /// has likely disconnected; the host should exit).
  [[nodiscard]] static bool write(int fd, const std::string& payload) noexcept;
};

}  // namespace ezcap::native_host
