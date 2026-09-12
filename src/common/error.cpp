#include <ezcap/error.hpp>

namespace ezcap {

const char* error_code_name(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::InvalidFraming:
      return "invalid_framing";
    case ErrorCode::MessageTooLarge:
      return "message_too_large";
    case ErrorCode::InvalidJson:
      return "invalid_json";
    case ErrorCode::InvalidUtf8:
      return "invalid_utf8";
    case ErrorCode::SchemaViolation:
      return "schema_violation";
    case ErrorCode::UnsupportedVersion:
      return "unsupported_version";
    case ErrorCode::UnknownOperation:
      return "unknown_operation";
    case ErrorCode::OperationNotAllowed:
      return "operation_not_allowed";
    case ErrorCode::MissingField:
      return "missing_field";
    case ErrorCode::TooManySubscriptions:
      return "too_many_subscriptions";
    case ErrorCode::QueueOverflow:
      return "queue_overflow";
    case ErrorCode::ClientTimeout:
      return "client_timeout";
    case ErrorCode::DaemonUnavailable:
      return "daemon_unavailable";
    case ErrorCode::SocketPermission:
      return "socket_permission";
    case ErrorCode::ConnectionClosed:
      return "connection_closed";
    case ErrorCode::BackendUnavailable:
      return "backend_unavailable";
    case ErrorCode::MissingPermission:
      return "missing_permission";
    case ErrorCode::CaptureFilterError:
      return "capture_filter_error";
    case ErrorCode::BackendLoadFailure:
      return "backend_load_failure";
    case ErrorCode::StorageError:
      return "storage_error";
    case ErrorCode::PolicyViolation:
      return "policy_violation";
    case ErrorCode::InternalError:
      return "internal_error";
  }
  return "internal_error";
}

const char* error_code_description(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::InvalidFraming:
      return "message framing is invalid";
    case ErrorCode::MessageTooLarge:
      return "message exceeds the size limit";
    case ErrorCode::InvalidJson:
      return "message is not valid JSON";
    case ErrorCode::InvalidUtf8:
      return "message contains invalid UTF-8";
    case ErrorCode::SchemaViolation:
      return "message does not match the protocol schema";
    case ErrorCode::UnsupportedVersion:
      return "protocol version is not supported";
    case ErrorCode::UnknownOperation:
      return "operation is not recognised";
    case ErrorCode::OperationNotAllowed:
      return "operation is not allowed";
    case ErrorCode::MissingField:
      return "a required field is missing";
    case ErrorCode::TooManySubscriptions:
      return "too many subscriptions for this client";
    case ErrorCode::QueueOverflow:
      return "client queue overflowed";
    case ErrorCode::ClientTimeout:
      return "client timed out";
    case ErrorCode::DaemonUnavailable:
      return "daemon is unavailable";
    case ErrorCode::SocketPermission:
      return "socket permission denied";
    case ErrorCode::ConnectionClosed:
      return "connection closed";
    case ErrorCode::BackendUnavailable:
      return "capture backend is unavailable";
    case ErrorCode::MissingPermission:
      return "capture permission is missing";
    case ErrorCode::CaptureFilterError:
      return "capture filter could not be applied";
    case ErrorCode::BackendLoadFailure:
      return "capture backend failed to load";
    case ErrorCode::StorageError:
      return "storage operation failed";
    case ErrorCode::PolicyViolation:
      return "policy rejected the request";
    case ErrorCode::InternalError:
      return "internal error";
  }
  return "internal error";
}

}  // namespace ezcap
