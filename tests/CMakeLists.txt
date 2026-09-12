# ezcap test suite.
#
# Unit tests link only the pieces they exercise (plus ezcap_core where
# simpler); integration tests link the full core library. All tests are
# plain executables returning non-zero on failure — no external test
# framework dependency, so the suite runs anywhere the daemon builds.

# --- Unit tests -------------------------------------------------------------

add_executable(test_packet_parser tests/unit/test_packet_parser.cpp
  src/capture/packet_parser.cpp
  src/common/process_info.cpp
  src/common/logging.cpp)
target_include_directories(test_packet_parser PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_packet_parser PRIVATE ezcap::spdlog)
add_test(NAME packet_parser COMMAND test_packet_parser)

add_executable(test_ipc_codec tests/unit/test_ipc_codec.cpp
  src/ipc/ipc_codec.cpp
  src/common/logging.cpp)
target_include_directories(test_ipc_codec PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_ipc_codec PRIVATE ezcap::spdlog ezcap::nlohmann_json)
add_test(NAME ipc_codec COMMAND test_ipc_codec)

add_executable(test_redactor tests/unit/test_redactor.cpp
  src/policy/redactor.cpp
  src/common/logging.cpp)
target_include_directories(test_redactor PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_redactor PRIVATE ezcap::spdlog)
add_test(NAME redactor COMMAND test_redactor)

add_executable(test_policy tests/unit/test_policy.cpp
  src/policy/redactor.cpp
  src/policy/policy_engine.cpp
  src/common/logging.cpp)
target_include_directories(test_policy PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_policy PRIVATE ezcap::spdlog ezcap::nlohmann_json)
add_test(NAME policy COMMAND test_policy)

add_executable(test_correlator tests/unit/test_correlator.cpp
  src/attribution/confidence.cpp
  src/attribution/correlator.cpp
  src/common/logging.cpp)
target_include_directories(test_correlator PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_correlator PRIVATE ezcap::spdlog)
add_test(NAME correlator COMMAND test_correlator)

# --- Integration tests -------------------------------------------------------
# These link the whole core and exercise the composed system.

add_executable(test_native_host tests/integration/test_native_host.cpp
  native_host/src/message_reader.cpp
  native_host/src/message_writer.cpp
  native_host/src/daemon_client.cpp)
target_include_directories(test_native_host PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/native_host/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(test_native_host PRIVATE ezcap::nlohmann_json Threads::Threads)
add_test(NAME native_host COMMAND test_native_host)

add_executable(test_daemon_ipc tests/integration/test_daemon_ipc.cpp)
target_link_libraries(test_daemon_ipc PRIVATE ezcap_core)
add_test(NAME daemon_ipc COMMAND test_daemon_ipc)

add_executable(test_capture_pipeline tests/integration/test_capture_pipeline.cpp)
target_link_libraries(test_capture_pipeline PRIVATE ezcap_core)
add_test(NAME capture_pipeline COMMAND test_capture_pipeline)

foreach(_t test_packet_parser test_ipc_codec test_redactor test_policy
               test_correlator test_native_host test_daemon_ipc
               test_capture_pipeline)
  target_compile_options(${_t} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()
