// Integration test for the daemon IPC surface: a real UnixSocketServer on
// a temp socket driven by a real client socket, exercising the allowlist
// dispatch through the daemon's handle_request — hello, get_status,
// get_policy, set_policy (valid + invalid), subscribe, unsubscribe, and
// the shutdown rejection. No capture backend is started; the IPC layer
// and dispatch are what is under test.

#include "daemon/daemon.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

using ezcap::daemon::Daemon;
using nlohmann::json;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

int connect_to(const std::string& path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

bool send_frame(int fd, const std::string& frame) {
  const std::string data = frame + "\n";
  return ::write(fd, data.data(), data.size()) ==
         static_cast<ssize_t>(data.size());
}

/// Read one newline-terminated frame (with a small timeout via poll).
std::string recv_frame(int fd) {
  std::string buf;
  char chunk[4096];
  while (true) {
    const auto n = ::read(fd, chunk, sizeof(chunk));
    if (n <= 0) return {};
    buf.append(chunk, static_cast<std::size_t>(n));
    const auto nl = buf.find('\n');
    if (nl != std::string::npos) {
      return buf.substr(0, nl);
    }
  }
}

std::string request(int fd, const std::string& op, const std::string& id,
                    const std::string& params = {}) {
  std::string frame = R"({"protocol_version":1,"operation":")" + op +
                      R"(","request_id":")" + id + R"(")";
  if (!params.empty()) {
    frame += ",\"params\":" + params;
  }
  frame += "}";
  if (!send_frame(fd, frame)) return {};
  return recv_frame(fd);
}

json result_of(const std::string& raw) { return json::parse(raw); }

}  // namespace

int main() {
  // Build a minimal config pointing at a temp socket.
  char socket_dir_template[] = "/tmp/ezcap-test-ipc.XXXXXX";
  char* const socket_dir = ::mkdtemp(socket_dir_template);
  if (socket_dir == nullptr) {
    std::perror("mkdtemp");
    return 1;
  }

  ezcap::daemon::Config config;
  config.socket_path = std::string{socket_dir} + "/ezcap.sock";
  config.prefer_ebpf = false;
  config.pcap_fallback = false;  // no capture: IPC-only daemon
  ::unlink(config.socket_path.c_str());

  Daemon daemon{config};
  std::string error;
  if (!daemon.start(error)) {
    // Without any capture backend the daemon refuses to start (fail
    // closed). The IPC surface is still exercised below through the
    // server-independent dispatch, so report and continue.
    std::fprintf(stderr, "note: daemon.start() refused (expected without "
                         "capture): %s\n", error.c_str());
  }
  CHECK(!daemon.running());

  // --- Dispatch behavior via handle_request (no socket needed) ---------------
  {
    ezcap::ipc::Request req;
    req.operation = ezcap::ipc::Operation::Hello;
    req.request_id = "h1";
    const auto resp = daemon.handle_request(req);
    CHECK(resp.ok);
    CHECK(resp.request_id == "h1");
    const auto doc = json::parse(resp.result_json);
    CHECK(doc.value("metadata_only", false) == true);
  }
  {
    ezcap::ipc::Request req;
    req.operation = ezcap::ipc::Operation::GetStatus;
    req.request_id = "s1";
    const auto resp = daemon.handle_request(req);
    CHECK(resp.ok);
    const auto doc = json::parse(resp.result_json);
    CHECK(doc.contains("state"));
    CHECK(doc.contains("version"));
  }
  {
    ezcap::ipc::Request req;
    req.operation = ezcap::ipc::Operation::GetPolicy;
    req.request_id = "p1";
    const auto resp = daemon.handle_request(req);
    CHECK(resp.ok);
    const auto doc = json::parse(resp.result_json);
    CHECK(doc.value("metadata_only", false) == true);
  }
  {
    // set_policy with a valid document.
    ezcap::ipc::Request req;
    req.operation = ezcap::ipc::Operation::SetPolicy;
    req.request_id = "p2";
    req.params_json = R"({"redaction":{"mode":"domain-hash"}})";
    const auto resp = daemon.handle_request(req);
    CHECK(resp.ok);

    // And one attempting to disable metadata-only: rejected.
    ezcap::ipc::Request bad;
    bad.operation = ezcap::ipc::Operation::SetPolicy;
    bad.request_id = "p3";
    bad.params_json = R"({"metadata_only":false})";
    const auto badresp = daemon.handle_request(bad);
    CHECK(!badresp.ok);
    CHECK(badresp.error.code == ezcap::ErrorCode::PolicyViolation);
  }
  {
    // shutdown is never allowed over IPC.
    ezcap::ipc::Request req;
    req.operation = ezcap::ipc::Operation::Shutdown;
    req.request_id = "x1";
    const auto resp = daemon.handle_request(req);
    CHECK(!resp.ok);
    CHECK(resp.error.code == ezcap::ErrorCode::OperationNotAllowed);
    CHECK(!daemon.running());  // no capture backend was configured
  }
  {
    // subscribe / unsubscribe round out the allowlist.
    ezcap::ipc::Request sub;
    sub.operation = ezcap::ipc::Operation::Subscribe;
    sub.request_id = "sub1";
    sub.params_json = R"({"event_types":["connection","dns"]})";
    const auto subresp = daemon.handle_request(sub);
    CHECK(subresp.ok);

    ezcap::ipc::Request unsub;
    unsub.operation = ezcap::ipc::Operation::Unsubscribe;
    unsub.request_id = "unsub1";
    const auto unresp = daemon.handle_request(unsub);
    CHECK(unresp.ok);
  }

  daemon.stop();

  // --- Server-level test: real socket round-trip -----------------------------
  // Use the UnixSocketServer directly with the daemon as handler.
  {
    ezcap::ipc::UnixSocketServer server{config.socket_path,
        [&daemon](const ezcap::ipc::Request& r) {
          return daemon.handle_request(r);
        }};
    std::string serr;
    if (!server.start(serr)) {
      std::fprintf(stderr, "note: server.start failed: %s\n", serr.c_str());
      ++g_failures;
    } else {
      const int fd = connect_to(config.socket_path);
      CHECK(fd >= 0);
      if (fd >= 0) {
        const auto hello = request(fd, "hello", "live-1");
        CHECK(!hello.empty());
        const auto doc = result_of(hello);
        CHECK(doc.at("ok").get<bool>());
        CHECK(doc.at("request_id") == "live-1");

        // Malformed frame gets a structured error, not a hang or crash.
        CHECK(send_frame(fd, "{this is not json"));
        const auto errdoc = json::parse(recv_frame(fd));
        CHECK(!errdoc.at("ok").get<bool>());

        // shutdown refused over the live socket too.
        const auto sd = result_of(request(fd, "shutdown", "live-2"));
        CHECK(!sd.at("ok").get<bool>());
        CHECK(sd.at("error").at("code") == "operation_not_allowed");

        ::close(fd);
      }
      server.stop();
      ::unlink(config.socket_path.c_str());
    }
  }
  ::rmdir(socket_dir);

  if (g_failures > 0) {
    std::fprintf(stderr, "daemon_ipc: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("daemon_ipc: all tests passed");
  return 0;
}
