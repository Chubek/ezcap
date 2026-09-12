#pragma once

#include <spdlog/spdlog.h>

#include <memory>
#include <string>

namespace ezcap::logging {

/// Severity levels exposed in configuration.
enum class Level {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
  Critical,
};

/// Initialize structured logging. Must be called once at startup.
/// `log_path` may be empty, in which case logs go to stderr only.
void initialize(Level level, const std::string& log_path);

/// Severity name for a level ("info", ...).
[[nodiscard]] const char* level_name(Level level) noexcept;

/// Parse a severity name; returns false on unknown values.
[[nodiscard]] bool level_from_name(const std::string& name, Level& out) noexcept;

/// The shared logger. Returns a null logger before initialize() is called,
/// so library code can log unconditionally.
[[nodiscard]] std::shared_ptr<spdlog::logger> logger() noexcept;

/// Shutdown and flush. Called at daemon exit.
void shutdown() noexcept;

}  // namespace ezcap::logging

// Stable log-call macros. Callers must never pass raw packet buffers,
// complete URLs, or other forbidden values to these macros.
#define EZCAP_LOG_TRACE(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->trace(__VA_ARGS__); } while (0)
#define EZCAP_LOG_DEBUG(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->debug(__VA_ARGS__); } while (0)
#define EZCAP_LOG_INFO(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->info(__VA_ARGS__); } while (0)
#define EZCAP_LOG_WARN(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->warn(__VA_ARGS__); } while (0)
#define EZCAP_LOG_ERROR(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->error(__VA_ARGS__); } while (0)
#define EZCAP_LOG_CRITICAL(...) \
  do { if (auto l = ::ezcap::logging::logger()) l->critical(__VA_ARGS__); } while (0)
