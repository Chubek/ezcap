#include "storage/sqlite_store.hpp"

#include "common/logging.hpp"
#include "common/time.hpp"
#include "ipc/ipc_codec.hpp"
#include "storage/migrations.hpp"

#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace ezcap::storage {

namespace {

/// Bounded write queue: capture must never block on storage.
constexpr std::size_t kMaxQueuedWrites = 4096;

/// A serialized event awaiting the writer thread.
struct PendingWrite {
  std::string event_id;
  std::uint32_t schema_version;
  std::string event_type;
  std::string source;
  double confidence;
  std::int64_t timestamp_ms;
  std::string process_name;  ///< Empty when absent.
  std::string remote_address;
  std::int64_t remote_port;  ///< -1 when absent.
  std::string url;
  std::string event_json;
};

}  // namespace

struct SqliteStore::Impl {
  std::string path;
  sqlite3* db{nullptr};

  // Bounded queue + dedicated writer thread.
  std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::vector<PendingWrite> queue;
  bool shutdown{false};
  bool failed{false};
  std::unique_ptr<std::thread> writer;

  std::atomic<std::uint64_t> stored{0};
  std::atomic<std::uint64_t> dropped{0};
  std::atomic<std::uint32_t> version{0};

  /// Writer thread entry point. A static member so it can name the private
  /// nested type without widening the class's public interface.
  static void writer_loop(Impl* impl);

  ~Impl() {
    {
      std::lock_guard<std::mutex> lock{queue_mutex};
      shutdown = true;
    }
    queue_cv.notify_all();
    if (writer && writer->joinable()) {
      writer->join();
    }
    if (db != nullptr) {
      ::sqlite3_close_v2(db);
    }
  }
};

namespace {

/// Execute one SQL statement (no parameters) with the error string set on
/// failure. Used only for migration DDL from the fixed, in-repo migration
/// list — never for anything derived from input.
bool exec_fixed(sqlite3* db, const std::string& sql, std::string& error) {
  char* errmsg = nullptr;
  if (::sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg) !=
      SQLITE_OK) {
    error = errmsg ? errmsg : "sqlite3_exec failed";
    ::sqlite3_free(errmsg);
    return false;
  }
  return true;
}

/// Read PRAGMA user_version.
std::uint32_t read_version(sqlite3* db) noexcept {
  sqlite3_stmt* stmt = nullptr;
  if (::sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return 0;
  }
  std::uint32_t version = 0;
  if (::sqlite3_step(stmt) == SQLITE_ROW) {
    version = static_cast<std::uint32_t>(::sqlite3_column_int64(stmt, 0));
  }
  ::sqlite3_finalize(stmt);
  return version;
}

/// Apply pending migrations inside one transaction, bumping user_version
/// per migration. Forward-only.
bool apply_migrations(sqlite3* db, std::string& error) {
  const std::uint32_t from = read_version(db);
  const std::uint32_t target = current_version();

  if (from > target) {
    error = "database schema version " + std::to_string(from) +
            " is newer than this daemon supports (" +
            std::to_string(target) + ")";
    return false;
  }
  if (from == target) {
    return true;
  }

  if (!exec_fixed(db, "BEGIN", error)) return false;
  for (const auto& migration : migrations()) {
    if (migration.version <= from) continue;
    for (const auto& sql : migration.statements) {
      if (!exec_fixed(db, sql, error)) {
        exec_fixed(db, "ROLLBACK", error);
        return false;
      }
    }
    const std::string pragma =
        "PRAGMA user_version = " + std::to_string(migration.version);
    if (!exec_fixed(db, pragma, error)) {
      exec_fixed(db, "ROLLBACK", error);
      return false;
    }
  }
  if (!exec_fixed(db, "COMMIT", error)) {
    exec_fixed(db, "ROLLBACK", error);
    return false;
  }
  return true;
}

/// Persist one queued event using a parameterized insert.
bool write_one(sqlite3* db, const PendingWrite& w) noexcept {
  static const char* kInsert =
      "INSERT INTO events (event_id, schema_version, event_type, source, "
      "confidence, timestamp_unix_ms, process_name, remote_address, "
      "remote_port, url, event_json) "
      "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";

  sqlite3_stmt* stmt = nullptr;
  if (::sqlite3_prepare_v2(db, kInsert, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  ::sqlite3_bind_text(stmt, 1, w.event_id.c_str(), -1, SQLITE_TRANSIENT);
  ::sqlite3_bind_int(stmt, 2, static_cast<int>(w.schema_version));
  ::sqlite3_bind_text(stmt, 3, w.event_type.c_str(), -1, SQLITE_TRANSIENT);
  ::sqlite3_bind_text(stmt, 4, w.source.c_str(), -1, SQLITE_TRANSIENT);
  ::sqlite3_bind_double(stmt, 5, w.confidence);
  ::sqlite3_bind_int64(stmt, 6, w.timestamp_ms);
  if (w.process_name.empty()) {
    ::sqlite3_bind_null(stmt, 7);
  } else {
    ::sqlite3_bind_text(stmt, 7, w.process_name.c_str(), -1,
                        SQLITE_TRANSIENT);
  }
  if (w.remote_address.empty()) {
    ::sqlite3_bind_null(stmt, 8);
  } else {
    ::sqlite3_bind_text(stmt, 8, w.remote_address.c_str(), -1,
                        SQLITE_TRANSIENT);
  }
  if (w.remote_port < 0) {
    ::sqlite3_bind_null(stmt, 9);
  } else {
    ::sqlite3_bind_int(stmt, 9, static_cast<int>(w.remote_port));
  }
  if (w.url.empty()) {
    ::sqlite3_bind_null(stmt, 10);
  } else {
    ::sqlite3_bind_text(stmt, 10, w.url.c_str(), -1, SQLITE_TRANSIENT);
  }
  ::sqlite3_bind_text(stmt, 11, w.event_json.c_str(), -1, SQLITE_TRANSIENT);

  const int rc = ::sqlite3_step(stmt);
  ::sqlite3_finalize(stmt);
  return rc == SQLITE_DONE;
}

}  // namespace

void SqliteStore::Impl::writer_loop(Impl* impl) {
  std::vector<PendingWrite> batch;
  while (true) {
    {
      std::unique_lock<std::mutex> lock{impl->queue_mutex};
      impl->queue_cv.wait(lock, [impl] {
        return impl->shutdown || !impl->queue.empty();
      });
      if (impl->queue.empty() && impl->shutdown) {
        return;
      }
      batch.swap(impl->queue);
    }

    bool ok = true;
    for (const auto& w : batch) {
      if (!write_one(impl->db, w)) {
        ok = false;
        break;
      }
      impl->stored.fetch_add(1);
    }
    if (!ok) {
      EZCAP_LOG_ERROR("storage write failed; disabling store");
      impl->failed = true;
      return;
    }
  }
}

SqliteStore::SqliteStore(std::string path, std::string& error)
    : impl_{std::make_unique<Impl>()} {
  impl_->path = std::move(path);

  const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                    SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOMUTEX;
  if (::sqlite3_open_v2(impl_->path.c_str(), &impl_->db, flags, nullptr) !=
      SQLITE_OK) {
    error = impl_->db != nullptr ? ::sqlite3_errmsg(impl_->db)
                                 : "sqlite3_open failed";
    impl_.reset();
    return;
  }

  // Hardening: no journal leftovers, no shared cache, no URI tricks.
  (void)::sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
  if (!exec_fixed(impl_->db, "PRAGMA journal_mode = TRUNCATE", error) ||
      !exec_fixed(impl_->db, "PRAGMA synchronous = NORMAL", error) ||
      !exec_fixed(impl_->db, "PRAGMA foreign_keys = ON", error)) {
    impl_.reset();
    return;
  }

  if (!apply_migrations(impl_->db, error)) {
    impl_.reset();
    return;
  }
  impl_->version.store(read_version(impl_->db));

  impl_->queue.reserve(64);
  try {
    impl_->writer =
        std::make_unique<std::thread>(Impl::writer_loop, impl_.get());
  } catch (...) {
    error = "cannot start storage writer thread";
    impl_.reset();
    return;
  }
  EZCAP_LOG_INFO("storage opened (schema v" +
                 std::to_string(impl_->version.load()) + ")");
}

SqliteStore::~SqliteStore() = default;

bool SqliteStore::store(const ezcap::Event& event) noexcept {
  if (!impl_ || impl_->failed) {
    return false;
  }

  PendingWrite w;
  w.event_id = event.event_id;
  w.schema_version = event.schema_version;
  w.event_type = event_type_name(event.type);
  w.source = event_source_name(event.source);
  w.confidence = event.confidence;
  w.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       event.timestamp.time_since_epoch())
                       .count();
  if (event.process) {
    w.process_name = event.process->name;
  }
  if (event.network) {
    w.remote_address = event.network->remote_address;
    w.remote_port = static_cast<std::int64_t>(event.network->remote_port);
  }
  if (event.browser) {
    w.url = event.browser->url;
  }
  w.event_json = ezcap::ipc::IpcCodec::encode_event(event);

  {
    std::lock_guard<std::mutex> lock{impl_->queue_mutex};
    if (impl_->queue.size() >= kMaxQueuedWrites) {
      impl_->dropped.fetch_add(1);
      return false;
    }
    impl_->queue.push_back(std::move(w));
  }
  impl_->queue_cv.notify_one();
  return true;
}

std::int64_t SqliteStore::prune(std::chrono::seconds retention) noexcept {
  if (!impl_ || impl_->failed) {
    return -1;
  }
  const auto cutoff = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch() -
                          retention)
                          .count();

  static const char* kPrune =
      "DELETE FROM events WHERE timestamp_unix_ms < ?1";
  sqlite3_stmt* stmt = nullptr;
  if (::sqlite3_prepare_v2(impl_->db, kPrune, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return -1;
  }
  ::sqlite3_bind_int64(stmt, 1, cutoff);
  const int rc = ::sqlite3_step(stmt);
  ::sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE) {
    return -1;
  }
  return ::sqlite3_changes(impl_->db);
}

std::uint64_t SqliteStore::stored_count() const noexcept {
  return impl_ ? impl_->stored.load() : 0;
}

std::uint64_t SqliteStore::dropped_count() const noexcept {
  return impl_ ? impl_->dropped.load() : 0;
}

std::uint32_t SqliteStore::schema_version() const noexcept {
  return impl_ ? impl_->version.load() : 0;
}

}  // namespace ezcap::storage
