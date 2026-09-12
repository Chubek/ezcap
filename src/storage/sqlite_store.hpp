#pragma once

#include <ezcap/event.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace ezcap::storage {

/// SQLite-backed event store. Optional and disabled by default: the daemon
/// only constructs a store when the configuration explicitly enables it.
///
/// All statements are parameterized; no user-derived text is ever spliced
/// into SQL. Writes are decoupled from the capture path through a bounded
/// queue — a full queue drops events and accounts the drop rather than
/// blocking capture. Retention is bounded and pruned periodically.
class SqliteStore {
 public:
  /// Open (creating if necessary) the database at `path` and apply all
  /// pending migrations inside a transaction. Returns false with `error`
  /// on any failure; the store is unusable in that case.
  SqliteStore(std::string path, std::string& error);

  ~SqliteStore();
  SqliteStore(const SqliteStore&) = delete;
  SqliteStore& operator=(const SqliteStore&) = delete;

  /// Queue an event for persistence. Returns false when the bounded queue
  /// is full (the event is dropped by the caller's accounting) or the
  /// store has failed permanently. Never blocks for long.
  [[nodiscard]] bool store(const ezcap::Event& event) noexcept;

  /// Delete events older than `retention`. Called periodically.
  /// Returns the number of pruned rows, or -1 on failure.
  [[nodiscard]] std::int64_t prune(std::chrono::seconds retention) noexcept;

  /// Total events persisted since open (post-restart count resets; the
  /// store is not a statistics authority).
  [[nodiscard]] std::uint64_t stored_count() const noexcept;

  /// Number of events dropped due to a full write queue.
  [[nodiscard]] std::uint64_t dropped_count() const noexcept;

  /// Current schema version of the open database.
  [[nodiscard]] std::uint32_t schema_version() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ezcap::storage
