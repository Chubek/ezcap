#pragma once

#include <ezcap/ipc_protocol.hpp>

#include <optional>
#include <string>
#include <vector>

namespace ezcap::native_host {

/// Connection to the daemon's Unix-domain IPC socket. The host is a thin,
/// validated pipe: it forwards allowlisted operations from the browser to
/// the daemon and streams subscription events back. It performs no
/// privileged actions of its own.
///
/// Rules enforced here (not delegated to the daemon):
///   - `shutdown` is never forwarded (not in the native schema at all);
///   - messages larger than the IPC frame limit are rejected locally;
///   - the socket path is fixed to the daemon's documented path.
class DaemonClient {
 public:
  /// Connect to the daemon socket. Returns false with `error` when the
  /// daemon is not running or the peer is not the same user.
  [[nodiscard]] bool connect(std::string& error) noexcept;

  /// True while connected.
  [[nodiscard]] bool connected() const noexcept;

  /// Send one newline-terminated request frame. Returns false on write
  /// errors (connection lost).
  [[nodiscard]] bool send_request(const ipc::Request& request) noexcept;

  /// Wait for the daemon to deliver pending frames. Returns false with
  /// `error` on read errors or timeout; `frames` receives complete
  /// newline-terminated frames (responses and events alike).
  [[nodiscard]] bool poll(int timeout_ms, std::vector<std::string>& frames,
                          std::string& error) noexcept;

  /// Disconnect.
  void close() noexcept;

  ~DaemonClient();
  DaemonClient() = default;
  DaemonClient(const DaemonClient&) = delete;
  DaemonClient& operator=(const DaemonClient&) = delete;

 private:
  int fd_{-1};
  std::string rx_buffer_;
};

}  // namespace ezcap::native_host
