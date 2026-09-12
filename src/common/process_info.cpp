// Process metadata lookup: executable name for a PID.
//
// Only the executable name is read (never the command line, which can
// contain credentials or URLs). Values come from /proc and are treated as
// untrusted input: they are length-bounded and NUL-terminated.
#include <ezcap/event.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace ezcap {

namespace {

/// Read the executable name for a PID from /proc/<pid>/comm. Returns an
/// empty string when the process has exited or the read fails.
std::string read_process_comm(ProcessId pid) {
  if (static_cast<std::uint32_t>(pid) == 0) {
    return {};
  }

  char path[64];
  std::snprintf(path, sizeof(path), "/proc/%u/comm",
                static_cast<std::uint32_t>(pid));

  int fd = ::open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return {};
  }

  std::array<char, 64> buf{};
  ssize_t n = ::read(fd, buf.data(), buf.size() - 1);
  ::close(fd);
  if (n <= 0) {
    return {};
  }

  // comm includes a trailing newline; strip it.
  while (n > 0 && (buf[static_cast<std::size_t>(n) - 1] == '\n' ||
                   buf[static_cast<std::size_t>(n) - 1] == '\0')) {
    --n;
  }
  buf[static_cast<std::size_t>(n)] = '\0';
  return std::string{buf.data(), static_cast<std::size_t>(n)};
}

}  // namespace

/// Public entry point: populate the process name for an event's ProcessInfo.
void lookup_process_name(ProcessInfo& info) {
  info.name = read_process_comm(info.pid);
  // Bound the stored name defensively; comm is at most 15 chars + NUL on
  // Linux, but stay strict in case the platform differs.
  if (info.name.size() > 64) {
    info.name.resize(64);
  }
}

}  // namespace ezcap
