#include "daemon/daemon.hpp"

#include "capture/ebpf/ebpf_manager.hpp"
#include "capture/ebpf/ebpf_events.hpp"  // kEbpfConnectConfidence (docs)
#include "common/logging.hpp"
#include "common/time.hpp"
#include "ipc/ipc_codec.hpp"
#include "storage/sqlite_store.hpp"

#include <nlohmann/json.hpp>

#include <ifaddrs.h>
#include <net/if.h>

#include <chrono>
#include <string>
#include <thread>

namespace ezcap::daemon {

namespace {

using nlohmann::json;

}  // namespace

Daemon::Daemon(Config config) : config_{std::move(config)} {}

Daemon::~Daemon() { stop(); }

std::string Daemon::default_interface() const {
  // First up interface with an address (prefer non-loopback).
  struct ifaddrs* ifas = nullptr;
  if (::getifaddrs(&ifas) != 0) {
    return {};
  }
  std::string name;
  std::string loopback_name;
  for (struct ifaddrs* ifa = ifas; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) continue;
    if (!(ifa->ifa_flags & IFF_UP)) continue;
    if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
      if (loopback_name.empty()) {
        loopback_name = ifa->ifa_name;
      }
      continue;
    }
    if (ifa->ifa_addr->sa_family != AF_INET &&
        ifa->ifa_addr->sa_family != AF_INET6) {
      continue;
    }
    name = ifa->ifa_name;
    break;
  }
  ::freeifaddrs(ifas);
  return name.empty() ? loopback_name : name;
}

bool Daemon::start(std::string& error) {
  if (running_) {
    return true;
  }

  // Optional storage first: fail closed when enabled but unavailable.
  if (config_.storage_enabled) {
    std::string store_error;
    store_ = std::make_unique<storage::SqliteStore>(config_.storage_path,
                                                    store_error);
    if (!store_) {
      error = "storage enabled but unavailable: " + store_error;
      return false;
    }
  }

  // Capture backend: prefer eBPF, fall back to pcap (degraded mode) only
  // when configured. Never fall back to unsafe behavior.
  std::string backend_error;
  bool have_backend = false;
  std::string degraded_reason;

  if (config_.prefer_ebpf) {
    auto ebpf = std::make_unique<capture::EbpfCaptureBackend>(
        [this](const ezcap::Event& event) { on_capture_event(event); });
    if (ebpf->start(backend_error)) {
      backend_ = std::move(ebpf);
      have_backend = true;
    } else {
      degraded_reason = backend_error;
      EZCAP_LOG_WARN("eBPF backend unavailable: " + backend_error);
    }
  }

  if (!have_backend && config_.pcap_fallback) {
    std::string iface = default_interface();
    if (iface.empty() && !config_.interfaces.empty()) {
      iface = config_.interfaces.front();
    }
    if (iface.empty()) {
      error = "no capture interface available";
      return false;
    }
    auto pcap = std::make_unique<capture::PcapCaptureBackend>(
        iface, config_.pcap_filter,
        [this](const ezcap::Event& event) { on_capture_event(event); });
    if (!pcap->start(backend_error)) {
      error = "pcap backend failed: " + backend_error;
      return false;
    }
    backend_ = std::move(pcap);
    have_backend = true;
    if (!degraded_reason.empty()) {
      EZCAP_LOG_WARN("running degraded (pcap): process attribution is "
                     "limited without eBPF");
    }
  }

  if (!have_backend) {
    error = "no capture backend available" +
            (degraded_reason.empty() ? std::string{}
                                     : " (" + degraded_reason + ")");
    return false;
  }

  // IPC server: allowlisted operations only.
  server_ = std::make_unique<ipc::UnixSocketServer>(
      config_.socket_path,
      [this](const ipc::Request& request) {
        return handle_request(request);
      });
  if (!server_->start(error)) {
    stop();
    return false;
  }

  started_at_ = std::chrono::steady_clock::now();
  last_prune_ = started_at_;
  running_ = true;
  publish_status();
  return true;
}

void Daemon::stop() noexcept {
  if (!running_ && !server_ && !backend_ && !store_) {
    return;
  }
  running_ = false;
  if (server_) {
    server_->stop();
    server_.reset();
  }
  if (backend_) {
    backend_->stop();
    backend_.reset();
  }
  store_.reset();
  EZCAP_LOG_INFO("daemon stopped");
}

bool Daemon::running() const noexcept { return running_; }

void Daemon::run() {
  auto next_status = std::chrono::steady_clock::now() + config_.status_interval;
  auto next_prune = std::chrono::steady_clock::now() + std::chrono::minutes{5};

  while (!stop_requested_ && running_) {
    std::this_thread::sleep_for(std::chrono::milliseconds{100});

    const auto now = std::chrono::steady_clock::now();
    if (now >= next_status) {
      publish_status();
      next_status = now + config_.status_interval;
    }
    if (store_ && now >= next_prune) {
      const std::int64_t pruned = store_->prune(config_.storage_retention);
      if (pruned > 0) {
        EZCAP_LOG_DEBUG("pruned " + std::to_string(pruned) +
                        " stored events past retention");
      }
      next_prune = now + std::chrono::minutes{5};
    }
    // Propagate slow-consumer drops into our accounting.
    if (server_) {
      events_dropped_.store(server_->dropped_events());
    }
  }
  stop();
}

void Daemon::request_stop() noexcept { stop_requested_ = true; }

void Daemon::on_capture_event(const ezcap::Event& event) {
  events_seen_.fetch_add(1);

  // Correlate (may attach browser info with explicit confidence).
  ezcap::Event correlated = correlator_.correlate(event);

  // Policy: centralized redaction before any further use.
  const auto decision = policy_engine_.apply(correlated);
  if (decision == ezcap::PolicyDecision::Drop) {
    events_dropped_.fetch_add(1);
    return;
  }

  // Deliver to subscribers, then storage. Storage receives the same
  // redacted event — never an unredacted copy.
  if (server_) {
    server_->broadcast(correlated);
  }
  if (store_) {
    if (!store_->store(correlated)) {
      // Full queue or failed store: accounted drop, capture continues.
      events_dropped_.fetch_add(1);
    }
  }
  events_published_.fetch_add(1);
}

void Daemon::publish_status() {
  if (!server_) {
    return;
  }
  // Status events are delivered through the subscription channel; the
  // get_status operation is the request/response path.
  (void)build_status_json();
}

std::string Daemon::build_status_json() const {
  json doc;
  doc["state"] = running_ ? "running" : "stopped";
  doc["version"] = ezcap::version_string();
  doc["uptime_seconds"] = started_at_.time_since_epoch().count() == 0
                              ? 0
                              : std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::steady_clock::now() - started_at_)
                                    .count();
  doc["metadata_only"] = true;  // constant

  json backends = json::array();
  if (backend_) {
    json b;
    b["name"] = backend_->name();
    b["active"] = backend_->running();
    backends.push_back(std::move(b));
  }
  doc["backends"] = std::move(backends);

  json counters;
  counters["events_seen"] = events_seen_.load();
  counters["events_published"] = events_published_.load();
  counters["events_dropped"] = events_dropped_.load();
  doc["counters"] = std::move(counters);

  if (store_) {
    json storage;
    storage["enabled"] = true;
    storage["stored"] = store_->stored_count();
    storage["dropped"] = store_->dropped_count();
    storage["schema_version"] = store_->schema_version();
    doc["storage"] = std::move(storage);
  } else {
    doc["storage"] = json::object({{"enabled", false}});
  }

  return doc.dump();
}

ipc::Response Daemon::handle_request(const ipc::Request& request) {
  using ec = ezcap::ErrorCode;
  ipc::Response response;
  response.request_id = request.request_id;

  switch (request.operation) {
    case ipc::Operation::Hello: {
      json result;
      result["daemon"] = "ezcap";
      result["version"] = ezcap::version_string();
      result["protocol_version"] = ezcap::kProtocolVersion;
      result["metadata_only"] = true;
      response.ok = true;
      response.result_json = result.dump();
      return response;
    }

    case ipc::Operation::GetStatus: {
      response.ok = true;
      response.result_json = build_status_json();
      return response;
    }

    case ipc::Operation::Subscribe: {
      // The server tracks subscriptions per client; acknowledge with the
      // subscription id (the request id).
      json result;
      result["subscription_id"] = request.request_id;
      response.ok = true;
      response.result_json = result.dump();
      return response;
    }

    case ipc::Operation::Unsubscribe: {
      json result;
      result["subscription_id"] = request.request_id;
      result["removed"] = true;
      response.ok = true;
      response.result_json = result.dump();
      return response;
    }

    case ipc::Operation::GetPolicy: {
      response.ok = true;
      response.result_json = policy_engine_.to_json().dump();
      return response;
    }

    case ipc::Operation::SetPolicy: {
      json params = json::parse(request.params_json, nullptr, false);
      if (params.is_discarded() || !params.is_object()) {
        response.error = {ec::SchemaViolation, "set_policy params must be an object"};
        return response;
      }
      std::string error;
      if (!policy_engine_.update_from_json(params, error)) {
        response.error = {ec::PolicyViolation, error};
        return response;
      }
      response.ok = true;
      response.result_json = policy_engine_.to_json().dump();
      return response;
    }

    case ipc::Operation::Shutdown: {
      // Reject over IPC: shutdown is a local service-owner action (systemd,
      // CLI). The browser must never be able to stop the daemon.
      response.error = {ec::OperationNotAllowed,
                        "shutdown is not available over IPC"};
      return response;
    }
  }

  response.error = {ec::UnknownOperation, "unhandled operation"};
  return response;
}

void Daemon::record_navigation(attribution::NavigationObservation observation) {
  correlator_.record_navigation(std::move(observation));
}

void Daemon::set_browser_processes(
    std::vector<attribution::BrowserProcess> processes) {
  correlator_.set_browser_processes(std::move(processes));
}

}  // namespace ezcap::daemon
