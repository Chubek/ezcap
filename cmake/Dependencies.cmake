# Dependency resolution for ezcap.
#
# Strategy: system packages where they are commonly distro-packaged
# (libpcap, libbpf, elfutils' libelf, sqlite3, libcap, libseccomp, zlib),
# and third_party/ submodules for header-heavy libraries that must stay
# version-consistent (nlohmann_json, asio, spdlog, fmt).

find_package(PkgConfig QUIET)

# ---------------------------------------------------------------------------
# nlohmann/json — always from the submodule (header-only single include).
# ---------------------------------------------------------------------------
add_library(ezcap_nlohmann_json INTERFACE)
add_library(ezcap::nlohmann_json ALIAS ezcap_nlohmann_json)
target_include_directories(ezcap_nlohmann_json INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann_json/single_include")

# ---------------------------------------------------------------------------
# asio — submodule, header-only (not currently required by the daemon's
# hand-rolled event loop, but available for future IPC work).
# ---------------------------------------------------------------------------
add_library(ezcap_asio INTERFACE)
add_library(ezcap::asio ALIAS ezcap_asio)
target_compile_definitions(ezcap_asio INTERFACE ASIO_STANDALONE)
target_include_directories(ezcap_asio INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/asio/asio/include")

# ---------------------------------------------------------------------------
# spdlog + fmt — system packages when present (they usually are), else
# the submodules.
# ---------------------------------------------------------------------------
find_package(spdlog QUIET)
if(TARGET spdlog::spdlog)
  add_library(ezcap_spdlog INTERFACE)
  add_library(ezcap::spdlog ALIAS ezcap_spdlog)
  target_link_libraries(ezcap_spdlog INTERFACE spdlog::spdlog)
else()
  add_library(ezcap_spdlog INTERFACE)
  add_library(ezcap::spdlog ALIAS ezcap_spdlog)
  target_include_directories(ezcap_spdlog INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/spdlog/include")
  find_package(fmt QUIET)
  if(TARGET fmt::fmt)
    target_link_libraries(ezcap_spdlog INTERFACE fmt::fmt)
  else()
    target_include_directories(ezcap_spdlog INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/third_party/fmt/include")
  endif()
endif()

# ---------------------------------------------------------------------------
# sqlite3 — system package.
# ---------------------------------------------------------------------------
find_package(SQLite3 REQUIRED)
add_library(ezcap_sqlite3 INTERFACE)
add_library(ezcap::sqlite3 ALIAS ezcap_sqlite3)
target_link_libraries(ezcap_sqlite3 INTERFACE SQLite::SQLite3)

# ---------------------------------------------------------------------------
# libpcap — system package.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPCAP REQUIRED IMPORTED_TARGET libpcap)
add_library(ezcap_libpcap INTERFACE)
add_library(ezcap::libpcap ALIAS ezcap_libpcap)
target_link_libraries(ezcap_libpcap INTERFACE PkgConfig::LIBPCAP)

# ---------------------------------------------------------------------------
# libbpf + libelf (from elfutils, never "libelf" spelled another way) —
# system packages.
# ---------------------------------------------------------------------------
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
add_library(ezcap_libbpf INTERFACE)
add_library(ezcap::libbpf ALIAS ezcap_libbpf)
target_link_libraries(ezcap_libbpf INTERFACE PkgConfig::LIBBPF PkgConfig::LIBELF)

# ---------------------------------------------------------------------------
# libcap — system package.
# ---------------------------------------------------------------------------
pkg_check_modules(LIBCAP REQUIRED IMPORTED_TARGET libcap)
add_library(ezcap_libcap INTERFACE)
add_library(ezcap::libcap ALIAS ezcap_libcap)
target_link_libraries(ezcap_libcap INTERFACE PkgConfig::LIBCAP)

# ---------------------------------------------------------------------------
# libseccomp — system package.
# ---------------------------------------------------------------------------
pkg_check_modules(LIBSECCOMP REQUIRED IMPORTED_TARGET libseccomp)
add_library(ezcap_libseccomp INTERFACE)
add_library(ezcap::libseccomp ALIAS ezcap_libseccomp)
target_link_libraries(ezcap_libseccomp INTERFACE PkgConfig::LIBSECCOMP)
