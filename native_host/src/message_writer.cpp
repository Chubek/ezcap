#include "message_writer.hpp"

#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

namespace ezcap::native_host {

bool MessageWriter::write(int fd, const std::string& payload) noexcept {
  // Enforce the browser's 1 MiB ceiling on our own output too.
  if (payload.empty() || payload.size() > 1024 * 1024) {
    return false;
  }

  const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
  const std::uint8_t prefix[4] = {
      static_cast<std::uint8_t>(length & 0xFF),
      static_cast<std::uint8_t>((length >> 8) & 0xFF),
      static_cast<std::uint8_t>((length >> 16) & 0xFF),
      static_cast<std::uint8_t>((length >> 24) & 0xFF),
  };

  // Single buffer, single write: browsers may split reads, but a
  // well-formed frame is always prefix+payload together.
  std::string frame;
  frame.reserve(payload.size() + sizeof(prefix));
  frame.append(reinterpret_cast<const char*>(prefix), sizeof(prefix));
  frame.append(payload);

  std::size_t sent = 0;
  while (sent < frame.size()) {
    const ssize_t n = ::write(fd, frame.data() + sent, frame.size() - sent);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace ezcap::native_host
