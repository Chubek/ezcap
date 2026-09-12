#pragma once

#include <ezcap/error.hpp>
#include <ezcap/version.hpp>

#include <chrono>
#include <cstddef>
#include <string>

namespace ezcap::ipc {

/// Hard frame limits. Requests above the limit are rejected with
/// MessageTooLarge; the connection is not terminated.
inline constexpr std::size_t kMaxRequestBytes = 64 * 1024;  // 64 KiB
inline constexpr std::size_t kMaxEventBytes = 256 * 1024;   // 256 KiB

/// Native Messaging framing limits (browser-enforced 1 MiB ceiling).
inline constexpr std::size_t kMaxNativeMessageBytes = 1024 * 1024;

/// Backpressure limits: bounded queues, per-client caps, timeouts.
inline constexpr std::size_t kMaxClients = 16;
inline constexpr std::size_t kMaxSubscriptionsPerClient = 8;
inline constexpr std::size_t kMaxOutgoingQueue = 1024;
inline constexpr auto kClientReadTimeout = std::chrono::seconds{30};
inline constexpr auto kClientWriteTimeout = std::chrono::seconds{10};

/// Allowlisted daemon operations. There is deliberately no generic
/// execute/run/eval operation.
enum class Operation {
  Hello,
  GetStatus,
  Subscribe,
  Unsubscribe,
  SetPolicy,
  GetPolicy,
  Shutdown,
};

/// Wire names for operations.
[[nodiscard]] const char* operation_name(Operation op) noexcept;

/// Parse an operation name; returns false on unknown values. Unknown values
/// map to a rejection with UnknownOperation, never to a default handler.
[[nodiscard]] bool operation_from_name(const std::string& name, Operation& out) noexcept;

/// An incoming daemon request after framing and JSON parsing.
struct Request {
  std::uint32_t protocol_version{kProtocolVersion};
  Operation operation{Operation::Hello};
  std::string request_id{};
  std::string params_json{};  ///< Raw params object; validated per-operation.
};

/// A daemon response: either a result document or a structured error.
struct Response {
  std::string request_id{};
  bool ok{false};
  std::string result_json{};      ///< Serialized result object when ok.
  IpcError error{};               ///< Populated when !ok.
};

}  // namespace ezcap::ipc
