#pragma once

#include <string>
#include <utility>

namespace ezcap {

/// Stable, machine-readable error codes shared across components. Codes are
/// part of the protocol surface: never rename an existing code, only add.
enum class ErrorCode {
  // Framing and encoding.
  InvalidFraming,
  MessageTooLarge,
  InvalidJson,
  InvalidUtf8,

  // Schema and protocol.
  SchemaViolation,
  UnsupportedVersion,
  UnknownOperation,
  OperationNotAllowed,
  MissingField,

  // Resource and backpressure limits.
  TooManySubscriptions,
  QueueOverflow,
  ClientTimeout,

  // Transport.
  DaemonUnavailable,
  SocketPermission,
  ConnectionClosed,

  // Capture backends.
  BackendUnavailable,
  MissingPermission,
  CaptureFilterError,
  BackendLoadFailure,

  // Internal.
  StorageError,
  PolicyViolation,
  InternalError,
};

/// Structured error with a stable code and a human-readable message that
/// must never contain sensitive values (URLs, hostnames, payload bytes).
struct IpcError {
  ErrorCode code{ErrorCode::InternalError};
  std::string message{};

  IpcError() = default;
  IpcError(ErrorCode c, std::string m) : code{c}, message{std::move(m)} {}
};

/// Stable string form of an error code, used in JSON error payloads.
[[nodiscard]] const char* error_code_name(ErrorCode code) noexcept;

/// Default human-readable description for an error code.
[[nodiscard]] const char* error_code_description(ErrorCode code) noexcept;

}  // namespace ezcap
