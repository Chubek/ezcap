#pragma once

#include <cstdint>
#include <string>

namespace ezcap::native_host {

/// Reads Native Messaging frames from stdin: a 4-byte little-endian length
/// prefix followed by that many bytes of UTF-8 JSON. The browser caps
/// messages at 1 MiB; the reader enforces the same bound locally so a
/// buggy host can never try to buffer unbounded input.
class MessageReader {
 public:
  /// Maximum accepted message size (browser-enforced ceiling).
  static constexpr std::uint32_t kMaxMessageBytes = 1024 * 1024;

  /// Read one message from `fd`. Returns false on EOF, read error,
  /// invalid framing, or oversize — `error` describes which. A framing
  /// error is terminal: the browser cannot resynchronize the stream.
  [[nodiscard]] static bool read(int fd, std::string& out,
                                 std::string& error) noexcept;

 private:
  /// Read exactly `count` bytes into `buf`. Returns false on EOF or error.
  [[nodiscard]] static bool read_exact(int fd, void* buf,
                                       std::size_t count) noexcept;
};

}  // namespace ezcap::native_host
