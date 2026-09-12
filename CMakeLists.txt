cmake_minimum_required(VERSION 3.24)

project(ezcap
  VERSION 0.1.0
  DESCRIPTION "Local browser network observability (metadata-only)"
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(EzcapOptions)

find_package(Threads REQUIRED)
include(CTest)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
include(Dependencies)

# ---------------------------------------------------------------------------
# Core library: everything except daemon main()
# ---------------------------------------------------------------------------
add_library(ezcap_core STATIC
  src/common/error.cpp
  src/common/event_types.cpp
  src/common/logging.cpp
  src/common/time.cpp
  src/common/process_info.cpp
  src/capture/packet_parser.cpp
  src/capture/event_normalizer.cpp
  src/capture/pcap/pcap_capture.cpp
  src/capture/pcap/pcap_filter.cpp
  src/capture/ebpf/ebpf_events.cpp
  src/capture/ebpf/ebpf_manager.cpp
  src/attribution/confidence.cpp
  src/attribution/correlator.cpp
  src/policy/redactor.cpp
  src/policy/policy_engine.cpp
  src/ipc/ipc_codec.cpp
  src/ipc/ipc_protocol.cpp
  src/ipc/unix_socket_server.cpp
  src/security/privilege_drop.cpp
  src/security/sandbox.cpp
  src/daemon/config.cpp
  src/daemon/daemon.cpp
  src/storage/migrations.cpp
  src/storage/sqlite_store.cpp
  src/common/sha256.cpp
  src/drivers/lua/manifests/manifest.cpp
  src/drivers/lua/manifests/manifest_hash.cpp
  src/drivers/lua/sandbox.cpp
  src/drivers/lua/bindings/lezcap.cpp
  src/drivers/driver_engine.cpp
  src/specgen/model/descriptor.cpp
  src/specgen/emitters/emitters.cpp
  src/specgen/specgen.cpp
)

target_include_directories(ezcap_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include"
)
target_link_libraries(ezcap_core PUBLIC
  ezcap::nlohmann_json
  ezcap::spdlog
  ezcap::sqlite3
  ezcap::libpcap
  ezcap::libbpf
  ezcap::libcap
  ezcap::libseccomp
  ezcap::luajit
)

# The eBPF object is loaded from a fixed install path, never configurable.
target_compile_definitions(ezcap_core PUBLIC
  EZCAP_EBPF_OBJECT_PATH="${EZCAP_EBPF_OBJECT_PATH}")
target_compile_options(ezcap_core PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)

find_package(Threads REQUIRED)
target_link_libraries(ezcap_core PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# Daemon executable
# ---------------------------------------------------------------------------
add_executable(ezcap-daemon src/daemon/main.cpp)
target_link_libraries(ezcap-daemon PRIVATE ezcap_core)
target_compile_options(ezcap-daemon PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)

# ---------------------------------------------------------------------------
# Native messaging host
# ---------------------------------------------------------------------------
add_executable(ezcap-native-host
  native_host/src/main.cpp
  native_host/src/message_reader.cpp
  native_host/src/message_writer.cpp
  native_host/src/daemon_client.cpp
  src/ipc/ipc_protocol.cpp
)
target_include_directories(ezcap-native-host PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(ezcap-native-host PRIVATE
  ezcap::nlohmann_json)
target_compile_options(ezcap-native-host PRIVATE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)

# ---------------------------------------------------------------------------
# eBPF compilation (optional, toolchain-dependent)
# ---------------------------------------------------------------------------
if(EZCAP_WITH_EBPF AND EZCAP_EBPF_SUPPORTED)
  add_subdirectory(ebpf)
endif()

# ---------------------------------------------------------------------------
# Browser extension (optional, node/npm-dependent)
# ---------------------------------------------------------------------------
add_subdirectory(extension)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(TARGETS ezcap-daemon ezcap-native-host
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

# Native messaging manifests (configured with real paths / extension ids).
configure_file(
  native_host/manifests/com.ezcap.host.chrome.json.in
  "${CMAKE_CURRENT_BINARY_DIR}/manifests/com.ezcap.host.chrome.json" @ONLY)
configure_file(
  native_host/manifests/com.ezcap.host.firefox.json.in
  "${CMAKE_CURRENT_BINARY_DIR}/manifests/com.ezcap.host.firefox.json" @ONLY)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/manifests/com.ezcap.host.chrome.json"
  "${CMAKE_CURRENT_BINARY_DIR}/manifests/com.ezcap.host.firefox.json"
  DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/ezcap/manifests")

# eBPF objects to the fixed load path.
if(EZCAP_WITH_EBPF AND EZCAP_EBPF_SUPPORTED)
  install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ebpf/"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/ezcap"
    FILES_MATCHING PATTERN "*.o")
endif()

# Packaging support files.
if(UNIX)
  configure_file(
    packaging/systemd/ezcap.service
    "${CMAKE_CURRENT_BINARY_DIR}/ezcap.service" @ONLY)
  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ezcap.service"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system")
  install(FILES packaging/systemd/ezcap.conf.sample.json
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/ezcap" RENAME ezcap.conf.json
    OPTIONAL)
  install(PROGRAMS
    "${CMAKE_CURRENT_SOURCE_DIR}/native_host/install/install-linux.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/native_host/install/uninstall-linux.sh"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/ezcap")
  # First-party bundled Lua drivers + manifests.
  install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/lua/dns-summary.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/lua/dns-summary.manifest.json"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/ezcap/drivers")
endif()
