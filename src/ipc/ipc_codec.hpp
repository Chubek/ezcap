#pragma once

#include <ezcap/error.hpp>
#include <ezcap/event.hpp>
#include <ezcap/ipc_protocol.hpp>

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace ezcap::ipc {

/// JSON codec for the daemon IPC protocol. All parsing validates size,
/// structure, enums, and protocol version; malformed input produces
/// structured errors, never exceptions propagated to callers.
class IpcCodec {
 public:
  /// Parse a request frame (JSON document). Returns false and fills
  /// `error` on any violation; never throws.
  [[nodiscard]] static bool parse_request(const std::string& frame,
                                          std::size_t max_bytes,
                                          Request& out, IpcError& error) noexcept;

  /// Serialize a response.
  [[nodiscard]] static std::string encode_response(const Response& response);

  /// Serialize an event as a subscription delivery frame.
  [[nodiscard]] static std::string encode_event(const ezcap::Event& event);

  /// Encode a structured error response for a request (known id) or an
  /// unframed error (empty id).
  [[nodiscard]] static std::string encode_error(const std::string& request_id,
                                                const IpcError& error);

  /// Split newline-delimited frames out of a receive buffer. Leaves any
  /// incomplete trailing frame in the buffer. Returns frames in order.
  /// Oversized frames (no newline within max_bytes) are reported via error.
  static bool split_frames(std::string& buffer, std::size_t max_bytes,
                           std::vector<std::string>& frames, IpcError& error);
};

}  // namespace ezcap::ipc
