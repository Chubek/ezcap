#include "unix_socket_server.hpp"

#include "common/logging.hpp"
#include "ipc/ipc_codec.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <vector>

namespace ezcap::ipc {

namespace {

bool send_all(int fd, const std::string& data) noexcept {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent,
                             MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

/// Peer credentials check: the connecting client must run under the same
/// effective UID as the daemon (the service owner). This is the
/// authentication boundary for the IPC channel.
bool peer_authorized(int fd) noexcept {
  struct ucred cred {};
  socklen_t len = sizeof(cred);
  if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    return false;
  }
  return cred.uid == ::geteuid();
}

}  // namespace

UnixSocketServer::UnixSocketServer(std::string socket_path,
                                   RequestHandler handler)
    : socket_path_{std::move(socket_path)}, handler_{std::move(handler)} {}

UnixSocketServer::~UnixSocketServer() { stop(); }

bool UnixSocketServer::start(std::string& error) {
  if (running_) {
    return true;
  }

  // Remove a stale socket only if it is actually a socket; never unlink
  // arbitrary files.
  struct stat st{};
  if (::lstat(socket_path_.c_str(), &st) == 0) {
    if (!S_ISSOCK(st.st_mode)) {
      error = "socket path exists and is not a socket";
      return false;
    }
    if (::unlink(socket_path_.c_str()) != 0) {
      error = "failed to remove stale socket";
      return false;
    }
  }

  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) {
    error = "socket creation failed";
    return false;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (socket_path_.size() >= sizeof(addr.sun_path)) {
    error = "socket path too long";
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

  // Restrictive umask for socket creation: owner-only access.
  const mode_t old_umask = ::umask(S_IRWXG | S_IRWXO);
  const int bind_rc = ::bind(listen_fd_,
                             reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  ::umask(old_umask);
  if (bind_rc != 0) {
    error = "bind failed (directory permissions?)";
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  // Belt and braces: force owner-only mode.
  ::chmod(socket_path_.c_str(), S_IRUSR | S_IWUSR);

  if (::listen(listen_fd_, 8) != 0) {
    error = "listen failed";
    ::unlink(socket_path_.c_str());
    ::close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }

  running_ = true;
  accept_thread_ =
      std::make_unique<std::thread>(&UnixSocketServer::accept_loop, this);
  EZCAP_LOG_INFO("ipc server listening");
  return true;
}

void UnixSocketServer::stop() noexcept {
  if (!running_) {
    return;
  }
  running_ = false;
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
  if (accept_thread_ && accept_thread_->joinable()) {
    accept_thread_->join();
  }
  accept_thread_.reset();

  // Disconnect all clients; their loops observe running_ == false.
  std::map<int, std::shared_ptr<Client>> to_close;
  {
    std::lock_guard<std::mutex> lock{clients_mutex_};
    to_close.swap(clients_);
  }
  for (auto& [fd, client] : to_close) {
    ::shutdown(fd, SHUT_RDWR);
  }
  // Client threads own their fds and close them on exit; give them a
  // moment by shutting down. Any still-joined threads finish on their own.
  ::unlink(socket_path_.c_str());
  EZCAP_LOG_INFO("ipc server stopped");
}

std::uint64_t UnixSocketServer::dropped_events() const noexcept {
  return dropped_events_.load();
}

void UnixSocketServer::accept_loop() {
  while (running_) {
    const int fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) {
      if (errno == EINTR) continue;
      if (!running_) break;
      EZCAP_LOG_WARN("ipc accept failed");
      continue;
    }

    // Peer authentication: same effective UID only.
    if (!peer_authorized(fd)) {
      EZCAP_LOG_WARN("ipc connection rejected: unauthorized peer");
      ::close(fd);
      continue;
    }

    auto client = std::make_shared<Client>();
    client->fd = fd;

    {
      std::lock_guard<std::mutex> lock{clients_mutex_};
      if (clients_.size() >= kMaxClients) {
        // Too many clients: reject cleanly.
        ::close(fd);
        continue;
      }
      clients_[fd] = client;
    }

    try {
      std::thread(&UnixSocketServer::client_loop, this, fd).detach();
    } catch (...) {
      std::lock_guard<std::mutex> lock{clients_mutex_};
      clients_.erase(fd);
      ::close(fd);
    }
  }
}

void UnixSocketServer::client_loop(int fd) {
  std::shared_ptr<Client> client;
  {
    std::lock_guard<std::mutex> lock{clients_mutex_};
    const auto it = clients_.find(fd);
    if (it == clients_.end()) {
      return;
    }
    client = it->second;
  }

  char buf[4096];
  while (running_) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) {
      break;  // clean disconnect
    }
    client->rx_buffer.append(buf, static_cast<std::size_t>(n));

    std::vector<std::string> frames;
    IpcError err;
    if (!IpcCodec::split_frames(client->rx_buffer, kMaxRequestBytes, frames,
                                err)) {
      // Oversized or malformed framing: structured error, then disconnect
      // (the client is misbehaving).
      deliver(*client, IpcCodec::encode_error("", err));
      break;
    }
    for (const auto& frame : frames) {
      if (!handle_frame(*client, frame)) {
        running_ = false;  // shutdown requested
        break;
      }
    }
    if (!running_) break;
  }

  // Clean disconnect handling: erase and close.
  {
    std::lock_guard<std::mutex> lock{clients_mutex_};
    clients_.erase(fd);
  }
  ::close(fd);
}

bool UnixSocketServer::handle_frame(Client& client, const std::string& frame) {
  Request request;
  IpcError error;
  if (!IpcCodec::parse_request(frame, kMaxRequestBytes, request, error)) {
    deliver(client, IpcCodec::encode_error("", error));
    return true;  // malformed request: error, but stay connected
  }

  // Per-client subscription caps.
  if (request.operation == Operation::Subscribe) {
    std::lock_guard<std::mutex> lock{client.out_mutex};
    if (client.subscriptions.size() >= kMaxSubscriptionsPerClient) {
      deliver(client,
              IpcCodec::encode_error(request.request_id,
                                     {ErrorCode::TooManySubscriptions,
                                      "subscription limit reached"}));
      return true;
    }
  }

  if (request.operation == Operation::Shutdown) {
    // Dangerous operation: requires additional authorization. The IPC
    // channel only serves the same-UID native host; even so, shutdown is
    // restricted to a direct, local request carrying an explicit flag —
    // never forwardable from the browser (the native host strips it).
    // Here: allow, as the peer is already UID-authenticated and local.
    deliver(client,
            IpcCodec::encode_error(request.request_id,
                                   {ErrorCode::OperationNotAllowed,
                                    "shutdown must be issued by the service "
                                    "owner locally"}));
    return true;
  }

  const Response response = handler_(request);

  if (request.operation == Operation::Subscribe && response.ok) {
    std::lock_guard<std::mutex> lock{client.out_mutex};
    client.subscriptions.insert(request.request_id);
  } else if (request.operation == Operation::Unsubscribe) {
    std::lock_guard<std::mutex> lock{client.out_mutex};
    client.subscriptions.erase(request.request_id);
  }

  deliver(client, IpcCodec::encode_response(response));
  return true;
}

void UnixSocketServer::deliver(Client& client, const std::string& encoded) {
  // Bounded outgoing queue: drop for slow consumers, account the drop.
  {
    std::lock_guard<std::mutex> lock{client.out_mutex};
    if (client.out_queue.size() >= kMaxOutgoingQueue) {
      client.out_queue.clear();  // drop oldest batch
      dropped_events_.fetch_add(1);
      return;
    }
    client.out_queue.push_back(encoded + "\n");
  }
  // Writes happen inline on the caller's thread with a short blocking
  // send; MSG_NOSIGNAL prevents SIGPIPE on disconnects. A stuck socket
  // drops events via the queue bound rather than blocking capture.
  std::vector<std::string> to_send;
  {
    std::lock_guard<std::mutex> lock{client.out_mutex};
    to_send.swap(client.out_queue);
  }
  for (const auto& msg : to_send) {
    if (!send_all(client.fd, msg)) {
      dropped_events_.fetch_add(to_send.size());
      return;
    }
  }
}

void UnixSocketServer::broadcast(const ezcap::Event& event) {
  std::vector<std::shared_ptr<Client>> subscribers;
  {
    std::lock_guard<std::mutex> lock{clients_mutex_};
    for (auto& [fd, client] : clients_) {
      std::lock_guard<std::mutex> cl{client->out_mutex};
      if (!client->subscriptions.empty()) {
        subscribers.push_back(client);
      }
    }
  }

  const std::string encoded = IpcCodec::encode_event(event);
  for (auto& client : subscribers) {
    deliver(*client, encoded);
  }
}

}  // namespace ezcap::ipc
