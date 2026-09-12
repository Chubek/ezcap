#pragma once

#include <cstdint>
#include <string>
#include <vector>

/// Opaque SQLite connection handle (sqlite3* without leaking the header).
using sqlite3_handle = struct sqlite3;

namespace ezcap::storage {

/// One schema migration: an ordered version number and the SQL statements
/// that move the database to that version. Migrations are forward-only;
/// there is no down-migration.
struct Migration {
  std::uint32_t version;
  std::vector<std::string> statements;
};

/// The ordered list of migrations. Version 0 is the empty database; each
/// entry describes how to reach `version` from `version - 1`.
[[nodiscard]] const std::vector<Migration>& migrations() noexcept;

/// The current (highest) schema version.
[[nodiscard]] std::uint32_t current_version() noexcept;

}  // namespace ezcap::storage
