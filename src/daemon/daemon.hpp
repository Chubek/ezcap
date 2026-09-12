#pragma once

#include <ezcap/event.hpp>
#include <ezcap/ipc_protocol.hpp>

#include "attribution/correlator.hpp"
#include "capture/pcap/pcap_capture.hpp"
#include "daemon/config.hpp"
#include "ipc/unix_socket_server.hpp"
#include "policy/policy_engine.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>

namespace ezcap::storage {
class SqliteStore;
}

namespace ezcap::daemon {

/// The daemon core: composes capture backends, the attribution correlator,
/// the policy engine, optional storage, and the IPC server. Every event
/// flows through the same pipeline regardless of backend:
///
///   capture backend -> normalize -> correlate -> policy(redact) ->
///   { broadcast to subscribers, optional storage }
///
/// No payload data ever enters the pipeline; backends only emit normalized
/// metadata events.
class Daemon {
 public:
  explicit Daemon(Config config);
  ~Daemon();

  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  /// Start backends and the IPC server. Returns false with `error` on
  /// failure; the daemon is stopped in that case (fail closed).
  [[nodiscard]] bool start(std::string& error);

  /// Stop everything and release resources. Idempotent.
  void stop() noexcept;

  /// True between successful start() and stop().
  [[nodiscard]] bool running() const noexcept;

  /// Run until stop() is requested (SIGTERM/SIGINT handlers may call it).
  void run();

  /// Request a graceful stop from any thread.
  void request_stop() noexcept;

  /// Handle one decoded IPC request (the allowlisted dispatch). Called on
  /// the IPC client thread.
  [[nodiscard]] ipc::Response handle_request(const ipc::Request& request);

  /// Receive a browser observation (navigation/process) from the native
  /// host channel. Used by the native host bridge.
  void record_navigation(attribution::NavigationObservation observation);
  void set_browser_processes(std::vector<attribution::BrowserProcess> processes);

 private:
  void on_capture_event(const ezcap::Event& event);
  void publish_status();
  [[nodiscard]] std::string build_status_json() const;
  [[nodiscard]] std::string default_interface() const;

  Config config_;
  policy::PolicyEngine policy_engine_;
  attribution::Correlator correlator_;

  std::unique_ptr<capture::CaptureBackend> backend_;
  std::unique_ptr<ipc::UnixSocketServer> server_;
  std::unique_ptr<storage::SqliteStore> store_;

  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::chrono::steady_clock::time_point started_at_{};

  // Counters for status reporting.
  std::atomic<std::uint64_t> events_seen_{0};
  std::atomic<std::uint64_t> events_published_{0};
  std::atomic<std::uint64_t> events_dropped_{0};
  std::chrono::steady_clock::time_point last_prune_{};
};

}  // namespace ezcap::daemon
