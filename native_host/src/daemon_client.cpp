#include "daemon_client.hpp"

#include <ezcap/version.hpp>

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <poll.h>

namespace ezcap::native_host {

namespace {

/// Split complete newline-terminated frames out of the receive buffer.
/// Leaves any incomplete tail in place.
void extract_frames(std::string& buffer, std::vector<std::string>& frames) {
  std::size_t start = 0;
  while (true) {
    const std::size_t newline = buffer.find('\n', start);
    if (newline == std::string::npos) {
      break;
    }
    frames.emplace_back(buffer, start, newline - start);
    start = newline + 1;
  }
  buffer.erase(0, start);
}

}  // namespace

bool DaemonClient::connect(std::string& error) noexcept {
  if (fd_ >= 0) {
    return true;
  }

  fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd_ < 0) {
    error = "socket creation failed";
    return false;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string path{ezcap::kDefaultSocketPath};
  if (path.size() >= sizeof(addr.sun_path)) {
    error = "socket path too long";
    close();
    return false;
  }
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

  if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    error = errno == ENOENT   ? "daemon not running (socket missing)"
            : errno == EACCES ? "permission denied connecting to daemon"
                              : "connect failed";
    close();
    return false;
  }

  // Verify the peer is our own user (defense in depth; the daemon checks
  // SO_PEERCRED on its side).
  struct ucred cred {};
  socklen_t len = sizeof(cred);
  if (::getsockopt(fd_, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 &&
      cred.uid != ::geteuid()) {
    error = "daemon socket peer uid mismatch";
    close();
    return false;
  }

  return true;
}

bool DaemonClient::connected() const noexcept { return fd_ >= 0; }

bool DaemonClient::send_request(const ipc::Request& request) noexcept {
  if (fd_ < 0) {
    return false;
  }

  // Fixed, allowlisted operation set — enforced by the schema parse in
  // main.cpp before a request ever reaches here.
  nlohmann::json doc;
  doc["protocol_version"] = request.protocol_version;
  doc["operation"] = ezcap::ipc::operation_name(request.operation);
  doc["request_id"] = request.request_id;
  if (!request.params_json.empty()) {
    doc["params"] = nlohmann::json::parse(request.params_json, nullptr,
                                          false);
  }
  std::string frame = doc.dump();
  if (frame.size() > ezcap::ipc::kMaxRequestBytes) {
    return false;
  }
  frame.push_back('\n');

  std::size_t sent = 0;
  while (sent < frame.size()) {
    const ssize_t n = ::send(fd_, frame.data() + sent, frame.size() - sent,
                             MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

bool DaemonClient::poll(int timeout_ms, std::vector<std::string>& frames,
                        std::string& error) noexcept {
  if (fd_ < 0) {
    error = "not connected";
    return false;
  }
  frames.clear();

  struct pollfd pfd{};
  pfd.fd = fd_;
  pfd.events = POLLIN;

  // First, drain anything already buffered.
  extract_frames(rx_buffer_, frames);
  if (!frames.empty()) {
    return true;
  }

  const int rc = ::poll(&pfd, 1, timeout_ms);
  if (rc < 0) {
    if (errno == EINTR) {
      return true;  // spurious wakeup: no frames, no error
    }
    error = "poll failed";
    return false;
  }
  if (rc == 0) {
    return true;  // timeout: no frames, no error
  }
  if (pfd.revents & (POLLHUP | POLLERR)) {
    error = "daemon closed the connection";
    return false;
  }

  char buf[8192];
  const ssize_t n = ::recv(fd_, buf, sizeof(buf), MSG_DONTWAIT);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return true;
    }
    error = "recv failed";
    return false;
  }
  if (n == 0) {
    error = "daemon closed the connection";
    return false;
  }

  rx_buffer_.append(buf, static_cast<std::size_t>(n));
  if (rx_buffer_.size() > ezcap::ipc::kMaxEventBytes) {
    error = "oversized frame from daemon";
    return false;
  }
  extract_frames(rx_buffer_, frames);
  return true;
}

void DaemonClient::close() noexcept {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  rx_buffer_.clear();
}

DaemonClient::~DaemonClient() { close(); }

}  // namespace ezcap::native_host
