/// ezcap Native Messaging host.
///
/// A thin, validated pipe between the browser extension and the daemon's
/// Unix-domain IPC socket:
///
///   browser stdin (4-byte LE framed JSON) -> validate -> daemon socket
///   daemon socket -> browser stdout (4-byte LE framed JSON)
///
/// The host performs no privileged work, executes nothing, and forwards
/// only allowlisted operations. `shutdown` does not exist in its schema
/// and is rejected as unknown before any forwarding happens.

#include "daemon_client.hpp"
#include "message_reader.hpp"
#include "message_writer.hpp"

#include <ezcap/version.hpp>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

using nlohmann::json;

/// Operations the extension may ask the daemon to perform. This list is
/// the security boundary on the browser side: anything else is rejected
/// with unknown_operation and never sent to the daemon.
const char* const kAllowedOperations[] = {
    "hello",     "get_status", "subscribe", "unsubscribe",
    "set_policy", "get_policy",
};

bool operation_allowed(const std::string& name) {
  for (const char* op : kAllowedOperations) {
    if (name == op) {
      return true;
    }
  }
  return false;
}

/// Write an envelope message to the browser.
bool send_envelope(const std::string& kind, const json& payload) {
  json envelope;
  envelope["protocol_version"] = ezcap::kProtocolVersion;
  envelope["kind"] = kind;
  envelope["payload"] = payload;
  return ezcap::native_host::MessageWriter::write(STDOUT_FILENO,
                                                  envelope.dump());
}

bool send_error(const std::string& request_id, const std::string& code,
                const std::string& message) {
  json error;
  if (!request_id.empty()) {
    error["request_id"] = request_id;
  }
  error["code"] = code;
  error["message"] = message.substr(0, 256);
  return send_envelope("error", std::move(error));
}

/// Handle one browser message document. Returns false only on terminal
/// protocol violations (bad framing, forbidden fields) that require the
/// host to exit; recoverable errors are reported as error envelopes.
bool handle_message(const json& doc) {
  // Envelope validation.
  if (!doc.is_object() || doc.value("protocol_version", 0) != 1 ||
      !doc.contains("kind") || !doc["kind"].is_string() ||
      !doc.contains("payload") || !doc["payload"].is_object()) {
    send_error("", "schema_violation", "malformed envelope");
    return false;
  }
  const std::string kind = doc["kind"].get<std::string>();
  const json& payload = doc["payload"];

  if (kind != "request") {
    // Only requests flow browser -> daemon. Anything else is out of
    // protocol for this direction.
    send_error("", "schema_violation", "only 'request' messages are accepted");
    return true;
  }

  // Request validation.
  if (!payload.contains("operation") || !payload["operation"].is_string() ||
      !payload.contains("request_id") || !payload["request_id"].is_string()) {
    send_error("", "schema_violation", "request requires operation and request_id");
    return true;
  }
  const std::string operation = payload["operation"].get<std::string>();
  const std::string request_id = payload["request_id"].get<std::string>();
  if (request_id.empty() || request_id.size() > 64) {
    send_error("", "schema_violation", "request_id must be 1-64 characters");
    return true;
  }

  // Forbidden-field check regardless of the rest of the document.
  static const char* const kForbidden[] = {
      "payload", "body", "cookies", "authorization", "password", "api_key",
      "execute", "run", "eval", "command", "shell",
  };
  for (const auto& [key, value] : payload.items()) {
    for (const char* bad : kForbidden) {
      if (key == bad) {
        send_error(request_id, "schema_violation",
                   std::string{"forbidden field: "} + bad);
        return true;
      }
    }
  }

  // Allowlist check (this is where `shutdown` and anything unknown die).
  if (!operation_allowed(operation)) {
    send_error(request_id, "unknown_operation",
               "operation not available through the native host");
    return true;
  }

  // Forward to the daemon.
  ezcap::native_host::DaemonClient client;
  std::string error;
  if (!client.connect(error)) {
    send_error(request_id, "daemon_unavailable", error);
    return true;
  }

  ezcap::ipc::Request request;
  request.protocol_version = ezcap::kProtocolVersion;
  ezcap::ipc::Operation op{};
  if (!ezcap::ipc::operation_from_name(operation, op)) {
    // Should be unreachable (allowlist checked above), but never forward
    // an unparsable operation.
    send_error(request_id, "unknown_operation", operation);
    return true;
  }
  request.operation = op;
  request.request_id = request_id;
  if (payload.contains("params") && payload["params"].is_object() &&
      payload["params"].size() <= 8) {
    request.params_json = payload["params"].dump();
  }

  if (!client.send_request(request)) {
    send_error(request_id, "daemon_unavailable",
               "failed to send request to daemon");
    return true;
  }

  // Wait briefly for the response frame(s) and relay them back.
  std::vector<std::string> frames;
  if (!client.poll(5000, frames, error)) {
    send_error(request_id, "daemon_error", error);
    return true;
  }
  for (const auto& frame : frames) {
    const json parsed = json::parse(frame, nullptr, false);
    if (parsed.is_discarded()) {
      continue;  // daemon output is trusted but must parse; skip anomalies
    }
    const bool is_event = !parsed.contains("ok") &&
                          parsed.contains("event_type");
    if (is_event) {
      send_envelope("event", parsed);
    } else {
      // Response: rewrap per the native schema.
      json response;
      response["request_id"] = request_id;
      response["ok"] = parsed.value("ok", false);
      if (parsed.contains("result")) {
        response["result"] = parsed["result"];
      }
      send_envelope("response", std::move(response));
    }
  }
  return true;
}

}  // namespace

int main() {
  // Native Messaging hosts must not buffer stdin/stdout beyond the
  // framed protocol; disable C stdio sync to keep the descriptors clean.
  std::ios::sync_with_stdio(false);

  // Optional handshake: browsers pass the origin as argv[1]; we accept
  // any origin because the manifest pins the allowed extension ids.
  const char* origin = std::getenv("EZCAP_NATIVE_ORIGIN");
  (void)origin;

  while (true) {
    std::string message;
    std::string error;
    if (!ezcap::native_host::MessageReader::read(STDIN_FILENO, message,
                                                 error)) {
      // EOF: the browser closed the port (normal shutdown). Framing or
      // size errors are terminal by protocol definition.
      return 0;
    }

    const json doc = json::parse(message, nullptr, false);
    if (doc.is_discarded()) {
      send_error("", "invalid_json", "message is not valid JSON");
      return 0;  // cannot trust the stream after garbage input
    }

    if (!handle_message(doc)) {
      return 0;
    }
  }
}
