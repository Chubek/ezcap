#include "daemon/daemon.hpp"
#include "security/privilege_drop.hpp"
#include "security/sandbox.hpp"

#include "common/logging.hpp"

#include <csignal>
#include <cstring>

#include <fstream>
#include <iostream>

namespace {

ezcap::daemon::Daemon* g_daemon = nullptr;

void handle_signal(int sig) {
  // Async-signal-safe: flip a flag the run loop observes.
  if (g_daemon != nullptr) {
    g_daemon->request_stop();
  }
  (void)sig;
}

void print_usage(const char* argv0) {
  std::cerr << "usage: " << argv0 << " [--config PATH] [--check-config PATH]\n";
}

}  // namespace

int main(int argc, char** argv) {
  using namespace ezcap;

  std::string config_path = "/etc/ezcap/ezcap.conf.json";
  bool check_config_only = false;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--config" && i + 1 < argc) {
      config_path = argv[++i];
    } else if (arg == "--check-config" && i + 1 < argc) {
      config_path = argv[++i];
      check_config_only = true;
    } else if (arg == "--help" || arg == "-h") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "unknown argument: " << arg << "\n";
      print_usage(argv[0]);
      return 2;
    }
  }

  daemon::Config config;
  std::string error;
  if (!daemon::Config::load(config_path, config, error)) {
    std::cerr << "ezcap-daemon: invalid configuration: " << error << "\n";
    return 2;
  }
  if (check_config_only) {
    std::cout << "configuration ok\n";
    return 0;
  }

  ezcap::logging::Level log_level = ezcap::logging::Level::Info;
  if (!ezcap::logging::level_from_name(config.log_level, log_level)) {
    std::cerr << "ezcap-daemon: invalid log level in configuration\n";
    return 2;
  }
  ezcap::logging::initialize(log_level, config.log_file);

  // Install signal handlers before anything starts.
  struct sigaction sa{};
  sa.sa_handler = handle_signal;
  ::sigaction(SIGTERM, &sa, nullptr);
  ::sigaction(SIGINT, &sa, nullptr);
  ::signal(SIGPIPE, SIG_IGN);

  daemon::Daemon daemon{std::move(config)};
  g_daemon = &daemon;

  if (!daemon.start(error)) {
    EZCAP_LOG_ERROR("startup failed: " + error);
    std::cerr << "ezcap-daemon: startup failed: " << error << "\n";
    g_daemon = nullptr;
    return 1;
  }

  // Privileged setup is done (capture objects opened, socket bound): drop
  // everything we no longer need. eBPF objects pin their maps, so no
  // capability needs to persist.
  if (!security::PrivilegeDropper::drop_all(error)) {
    EZCAP_LOG_ERROR("refusing to run with elevated privileges: " + error);
    daemon.stop();
    g_daemon = nullptr;
    return 1;
  }

  // Restrict the syscall surface. Failure is fatal (fail closed).
  if (!security::Sandbox::install(error)) {
    EZCAP_LOG_ERROR("refusing to run without the seccomp sandbox: " + error);
    daemon.stop();
    g_daemon = nullptr;
    return 1;
  }

  EZCAP_LOG_INFO("ezcap daemon " + std::string{version_string()} +
                 " started (metadata-only)");
  daemon.run();
  g_daemon = nullptr;
  EZCAP_LOG_INFO("ezcap daemon exited");
  return 0;
}
