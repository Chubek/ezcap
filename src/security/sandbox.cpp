#include "sandbox.hpp"

#include "common/logging.hpp"

#include <seccomp.h>

#include <cerrno>
#include <cstring>

namespace ezcap::security {

namespace {

// Syscalls the daemon needs after setup: memory, file I/O on open fds,
// socket I/O, threading, clocks, and epoll/poll.
const int kAllowed[] = {
    SCMP_SYS(accept4),    SCMP_SYS(bind),         SCMP_SYS(brk),
    SCMP_SYS(clock_gettime), SCMP_SYS(close),     SCMP_SYS(connect),
    SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_pwait),
    SCMP_SYS(epoll_wait), SCMP_SYS(exit),         SCMP_SYS(exit_group),
    SCMP_SYS(fcntl),      SCMP_SYS(fstat),        SCMP_SYS(futex),
    SCMP_SYS(getpid),     SCMP_SYS(getsockname),  SCMP_SYS(getsockopt),
    SCMP_SYS(listen),     SCMP_SYS(lseek),        SCMP_SYS(madvise),
    SCMP_SYS(mmap),       SCMP_SYS(mprotect),     SCMP_SYS(munmap),
    SCMP_SYS(nanosleep),  SCMP_SYS(openat),       SCMP_SYS(pipe2),
    SCMP_SYS(poll),       SCMP_SYS(ppoll),        SCMP_SYS(read),
    SCMP_SYS(readv),      SCMP_SYS(recvfrom),     SCMP_SYS(recvmmsg),
    SCMP_SYS(recvmsg),    SCMP_SYS(send),         SCMP_SYS(sendmmsg),
    SCMP_SYS(sendmsg),    SCMP_SYS(sendto),       SCMP_SYS(setsockopt),
    SCMP_SYS(shutdown),   SCMP_SYS(sigaction),    SCMP_SYS(sigprocmask),
    SCMP_SYS(socket),     SCMP_SYS(write),        SCMP_SYS(writev),
};

}  // namespace

bool Sandbox::install(std::string& error) noexcept {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
  if (ctx == nullptr) {
    error = "seccomp_init failed";
    return false;
  }

  bool ok = true;
  for (int syscall : kAllowed) {
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall, 0) != 0) {
      error = "seccomp_rule_add failed";
      ok = false;
      break;
    }
  }

  if (ok) {
    if (seccomp_load(ctx) != 0) {
      error = "seccomp_load failed";
      ok = false;
    }
  }

  seccomp_release(ctx);

  if (ok) {
    EZCAP_LOG_INFO("seccomp sandbox installed");
  } else {
    EZCAP_LOG_ERROR("seccomp sandbox installation failed");
  }
  return ok;
}

}  // namespace ezcap::security
