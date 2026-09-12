#include "storage/migrations.hpp"

namespace ezcap::storage {

namespace {

// Schema v1: the events table. Only metadata columns exist by design —
// there is no column that could hold a payload, cookie, or body, so the
// metadata-only invariant is enforced at the storage layer too.
//
// Events are stored in their normalized JSON form for replay/inspection;
// the indexed columns support retention pruning and coarse queries.
const std::vector<Migration> kMigrations{
    {1,
     {R"SQL(
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  schema_version INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL,
  confidence REAL NOT NULL,
  timestamp_unix_ms INTEGER NOT NULL,
  process_name TEXT,
  remote_address TEXT,
  remote_port INTEGER,
  url TEXT,
  event_json TEXT NOT NULL
)
)SQL",
      R"SQL(CREATE INDEX IF NOT EXISTS idx_events_timestamp
  ON events (timestamp_unix_ms))SQL",
      R"SQL(CREATE INDEX IF NOT EXISTS idx_events_type
  ON events (event_type, timestamp_unix_ms))SQL"}},

    // Schema v2: user_version bookkeeping lives in SQLite's own
    // PRAGMA user_version (not a table); this migration adds the
    // retention bookkeeping table used by pruning.
    {2,
     {R"SQL(CREATE TABLE IF NOT EXISTS storage_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
))SQL",
      R"SQL(INSERT OR REPLACE INTO storage_meta (key, value)
  VALUES ('created_by', 'ezcap-daemon'))SQL"}},
};

}  // namespace

const std::vector<Migration>& migrations() noexcept { return kMigrations; }

std::uint32_t current_version() noexcept {
  return kMigrations.empty() ? 0 : kMigrations.back().version;
}

}  // namespace ezcap::storage
