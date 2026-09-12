#include "message_reader.hpp"

#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

namespace ezcap::native_host {

bool MessageReader::read_exact(int fd, void* buf, std::size_t count) noexcept {
  auto* out = static_cast<char*>(buf);
  std::size_t done = 0;
  while (done < count) {
    const ssize_t n = ::read(fd, out + done, count - done);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) {
      return false;  // EOF mid-frame or empty read.
    }
    done += static_cast<std::size_t>(n);
  }
  return true;
}

bool MessageReader::read(int fd, std::string& out, std::string& error) noexcept {
  std::uint8_t prefix[4];
  if (!read_exact(fd, prefix, sizeof(prefix))) {
    error = "eof";
    return false;
  }

  // Little-endian length.
  std::uint32_t length = 0;
  length |= static_cast<std::uint32_t>(prefix[0]);
  length |= static_cast<std::uint32_t>(prefix[1]) << 8;
  length |= static_cast<std::uint32_t>(prefix[2]) << 16;
  length |= static_cast<std::uint32_t>(prefix[3]) << 24;

  if (length == 0) {
    error = "invalid_framing";
    return false;
  }
  if (length > kMaxMessageBytes) {
    error = "message_too_large";
    return false;
  }

  out.resize(length);
  if (!read_exact(fd, out.data(), length)) {
    error = "eof";
    return false;
  }

  // UTF-8 validation: reject invalid sequences rather than forwarding
  // malformed bytes to a JSON parser.
  for (std::size_t i = 0; i < out.size();) {
    const unsigned char c = static_cast<unsigned char>(out[i]);
    std::size_t extra = 0;
    if (c < 0x80) {
      i += 1;
      continue;
    } else if ((c & 0xE0) == 0xC0) {
      extra = 1;
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
    } else {
      error = "invalid_json";
      return false;
    }
    if (i + extra >= out.size()) {
      error = "invalid_json";
      return false;
    }
    for (std::size_t j = 1; j <= extra; ++j) {
      const unsigned char cc = static_cast<unsigned char>(out[i + j]);
      if ((cc & 0xC0) != 0x80) {
        error = "invalid_json";
        return false;
      }
    }
    i += extra + 1;
  }

  return true;
}

}  // namespace ezcap::native_host
