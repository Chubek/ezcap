#pragma once

#include <ezcap/event.hpp>
#include <ezcap/error.hpp>
#include <ezcap/ipc_protocol.hpp>

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace ezcap::ipc {

/// Handles one connected IPC client: reads newline-delimited frames,
/// validates them, dispatches allowlisted operations, and delivers
/// subscription events with bounded queues.
class UnixSocketServer {
 public:
  /// Called to execute a validated request. Runs on the client's reader
  /// thread; must be cheap or enqueue work.
  using RequestHandler =
      std::function<Response(const Request&)>;

  /// Called when a client subscribes; the returned callback receives
  /// events for that subscription.
  using EventSink = std::function<void(const ezcap::Event&)>;

  UnixSocketServer(std::string socket_path, RequestHandler handler);
  ~UnixSocketServer();

  UnixSocketServer(const UnixSocketServer&) = delete;
  UnixSocketServer& operator=(const UnixSocketServer&) = delete;

  /// Bind and listen. Returns false with `error` populated when the socket
  /// path is unusable or permissions are wrong. The socket is created with
  /// owner-only permissions (0700 directory, 0600 socket).
  bool start(std::string& error);

  /// Stop accepting connections, disconnect clients, unlink the socket.
  void stop() noexcept;

  /// Broadcast an event to subscribed clients. Bounded queues: slow
  /// consumers get events dropped (accounted) rather than blocking the
  /// capture pipeline.
  void broadcast(const ezcap::Event& event);

  /// Count of events dropped for slow consumers since start.
  [[nodiscard]] std::uint64_t dropped_events() const noexcept;

 private:
  struct Client {
    int fd{-1};
    std::string rx_buffer;
    std::set<std::string> subscriptions;
    std::mutex out_mutex;
    std::vector<std::string> out_queue;  // bounded by kMaxOutgoingQueue
  };

  void accept_loop();
  void client_loop(int fd);
  bool handle_frame(Client& client, const std::string& frame);
  void deliver(Client& client, const std::string& encoded);

  std::string socket_path_;
  RequestHandler handler_;
  int listen_fd_{-1};
  std::atomic<bool> running_{false};
  std::unique_ptr<std::thread> accept_thread_;

  std::mutex clients_mutex_;
  std::map<int, std::shared_ptr<Client>> clients_;
  std::atomic<std::uint64_t> dropped_events_{0};
};

}  // namespace ezcap::ipc
