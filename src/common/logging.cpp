#include "logging.hpp"

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <mutex>

namespace ezcap::logging {

namespace {

std::mutex g_logger_mutex;
std::shared_ptr<spdlog::logger> g_logger;
Level g_level = Level::Info;

spdlog::level::level_enum to_spdlog(Level level) noexcept {
  switch (level) {
    case Level::Trace:
      return spdlog::level::trace;
    case Level::Debug:
      return spdlog::level::debug;
    case Level::Info:
      return spdlog::level::info;
    case Level::Warn:
      return spdlog::level::warn;
    case Level::Error:
      return spdlog::level::err;
    case Level::Critical:
      return spdlog::level::critical;
  }
  return spdlog::level::info;
}

}  // namespace

void initialize(Level level, const std::string& log_path) {
  std::lock_guard<std::mutex> lock{g_logger_mutex};
  g_level = level;

  try {
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    if (!log_path.empty()) {
      // File logs use append mode with restricted permissions (0600)
      // enforced by the caller creating the parent directory.
      sinks.push_back(
          std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_path, true));
    }

    auto logger = std::make_shared<spdlog::logger>(
        "ezcap", sinks.begin(), sinks.end());
    logger->set_level(to_spdlog(level));
    // Structured pattern: no message bodies, no raw buffers — callers
    // supply only stable event names and metadata.
    logger->set_pattern("%Y-%m-%dT%H:%M:%S.%e%z [%l] [%t] %v");
    spdlog::set_default_logger(logger);
    g_logger = std::move(logger);
  } catch (...) {
    // Logging must never take the daemon down; fall back to a null logger.
    g_logger.reset();
  }
}

const char* level_name(Level level) noexcept {
  switch (level) {
    case Level::Trace:
      return "trace";
    case Level::Debug:
      return "debug";
    case Level::Info:
      return "info";
    case Level::Warn:
      return "warn";
    case Level::Error:
      return "error";
    case Level::Critical:
      return "critical";
  }
  return "info";
}

bool level_from_name(const std::string& name, Level& out) noexcept {
  if (name == "trace") {
    out = Level::Trace;
  } else if (name == "debug") {
    out = Level::Debug;
  } else if (name == "info") {
    out = Level::Info;
  } else if (name == "warn" || name == "warning") {
    out = Level::Warn;
  } else if (name == "error") {
    out = Level::Error;
  } else if (name == "critical") {
    out = Level::Critical;
  } else {
    return false;
  }
  return true;
}

std::shared_ptr<spdlog::logger> logger() noexcept { return g_logger; }

void shutdown() noexcept {
  std::lock_guard<std::mutex> lock{g_logger_mutex};
  if (g_logger) {
    g_logger->flush();
  }
  spdlog::shutdown();
  g_logger.reset();
}

}  // namespace ezcap::logging
