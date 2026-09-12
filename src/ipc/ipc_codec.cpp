#include "ipc_codec.hpp"

#include "common/time.hpp"

#include <ezcap/policy.hpp>
#include <ezcap/version.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace ezcap::ipc {

using nlohmann::json;

namespace {

bool has_forbidden_field(const json& doc) {
  static const char* kForbidden[] = {"payload", "body",   "cookies",
                                     "authorization", "password", "api_key"};
  return std::any_of(std::begin(kForbidden), std::end(kForbidden),
                     [&](const char* f) { return doc.contains(f); });
}

}  // namespace

bool IpcCodec::parse_request(const std::string& frame, std::size_t max_bytes,
                             Request& out, IpcError& error) noexcept {
  try {
    if (frame.size() > max_bytes) {
      error = {ErrorCode::MessageTooLarge, "request exceeds frame limit"};
      return false;
    }

    // UTF-8 validation: json::parse rejects invalid UTF-8 byte sequences
    // with an exception, handled below.
    const json doc = json::parse(frame, nullptr, false);
    if (doc.is_discarded()) {
      error = {ErrorCode::InvalidJson, "request is not valid JSON"};
      return false;
    }
    if (!doc.is_object()) {
      error = {ErrorCode::SchemaViolation, "request must be a JSON object"};
      return false;
    }
    if (has_forbidden_field(doc)) {
      error = {ErrorCode::SchemaViolation, "request contains forbidden fields"};
      return false;
    }

    if (!doc.contains("protocol_version") ||
        !doc.at("protocol_version").is_number_integer()) {
      error = {ErrorCode::MissingField, "protocol_version missing"};
      return false;
    }
    const auto version = doc.at("protocol_version").get<std::int64_t>();
    if (version != static_cast<std::int64_t>(kProtocolVersion)) {
      error = {ErrorCode::UnsupportedVersion, "unsupported protocol version"};
      return false;
    }

    if (!doc.contains("operation") || !doc.at("operation").is_string()) {
      error = {ErrorCode::MissingField, "operation missing"};
      return false;
    }
    Operation op{};
    if (!operation_from_name(doc.at("operation").get<std::string>(), op)) {
      error = {ErrorCode::UnknownOperation, "unknown operation"};
      return false;
    }

    if (!doc.contains("request_id") || !doc.at("request_id").is_string()) {
      error = {ErrorCode::MissingField, "request_id missing"};
      return false;
    }
    const auto request_id = doc.at("request_id").get<std::string>();
    if (request_id.empty() || request_id.size() > 64) {
      error = {ErrorCode::SchemaViolation, "request_id must be 1-64 chars"};
      return false;
    }

    out.protocol_version = kProtocolVersion;
    out.operation = op;
    out.request_id = request_id;
    out.params_json.clear();
    if (doc.contains("params")) {
      const auto& params = doc.at("params");
      if (!params.is_object()) {
        error = {ErrorCode::SchemaViolation, "params must be an object"};
        return false;
      }
      if (params.size() > 8) {
        error = {ErrorCode::SchemaViolation, "too many params"};
        return false;
      }
      out.params_json = params.dump();
    }
    return true;
  } catch (const json::exception&) {
    error = {ErrorCode::InvalidJson, "request failed JSON validation"};
    return false;
  } catch (...) {
    error = {ErrorCode::InternalError, "unexpected parse failure"};
    return false;
  }
}

std::string IpcCodec::encode_response(const Response& response) {
  json doc;
  doc["request_id"] = response.request_id;
  doc["ok"] = response.ok;
  if (response.ok) {
    doc["result"] =
        response.result_json.empty()
            ? json::object()
            : json::parse(response.result_json, nullptr, false);
    if (doc["result"].is_discarded()) {
      doc["result"] = json::object();
    }
  } else {
    json err;
    err["code"] = error_code_name(response.error.code);
    err["message"] = response.error.message;
    doc["error"] = std::move(err);
  }
  return doc.dump();
}

std::string IpcCodec::encode_error(const std::string& request_id,
                                   const IpcError& error) {
  Response response;
  response.request_id = request_id;
  response.ok = false;
  response.error = error;
  return encode_response(response);
}

std::string IpcCodec::encode_event(const ezcap::Event& event) {
  json doc;
  doc["schema_version"] = event.schema_version;
  doc["event_id"] = event.event_id;
  doc["event_type"] = event_type_name(event.type);
  doc["timestamp"] = time_util::to_rfc3339(event.timestamp);
  doc["source"] = event_source_name(event.source);
  doc["confidence"] = event.confidence;
  if (!event.correlation_id.empty()) {
    doc["correlation_id"] = event.correlation_id;
  }

  if (event.process) {
    json process;
    process["pid"] = static_cast<std::uint32_t>(event.process->pid);
    if (!event.process->name.empty()) {
      process["name"] = event.process->name;
    }
    if (event.process->uid) {
      process["uid"] = static_cast<std::uint32_t>(*event.process->uid);
    }
    doc["process"] = std::move(process);
  }

  if (event.network) {
    json network;
    network["transport"] = transport_name(event.network->transport);
    if (event.network->direction != Direction::Unknown) {
      network["direction"] = direction_name(event.network->direction);
    }
    if (!event.network->local_address.empty()) {
      network["local_address"] = event.network->local_address;
      network["local_port"] =
          static_cast<std::uint16_t>(event.network->local_port);
    }
    if (!event.network->remote_address.empty()) {
      network["remote_address"] = event.network->remote_address;
      network["remote_port"] =
          static_cast<std::uint16_t>(event.network->remote_port);
    }
    if (!event.network->dns_query_name.empty()) {
      network["dns_query_name"] = event.network->dns_query_name;
    }
    if (event.network->dns_response_code) {
      network["dns_response_code"] = *event.network->dns_response_code;
    }
    if (!event.network->interface.empty()) {
      network["interface"] = event.network->interface;
    }
    network["backend"] = event_source_name(event.network->backend);
    doc["network"] = std::move(network);
  }

  if (event.browser) {
    json browser;
    browser["tab_id"] = event.browser->tab_id;
    browser["window_id"] = event.browser->window_id;
    if (!event.browser->url.empty()) {
      browser["url"] = event.browser->url;
    }
    if (!event.browser->title.empty()) {
      browser["title"] = event.browser->title;
    }
    if (!event.browser->navigation_id.empty()) {
      json navigation;
      navigation["navigation_id"] = event.browser->navigation_id;
      navigation["frame_id"] = event.browser->frame_id;
      browser["navigation"] = std::move(navigation);
    }
    doc["browser"] = std::move(browser);
  }

  {
    json privacy;
    privacy["redacted"] = event.privacy.redacted;
    privacy["metadata_only"] = true;  // constant
    json::array_t redactions;
    if (event.privacy.redactions[static_cast<std::size_t>(RedactionKind::QueryString)])
      redactions.push_back("query-string");
    if (event.privacy.redactions[static_cast<std::size_t>(RedactionKind::Fragment)])
      redactions.push_back("fragment");
    if (event.privacy.redactions[static_cast<std::size_t>(RedactionKind::HostnameHash)])
      redactions.push_back("hostname-hash");
    if (event.privacy.redactions[static_cast<std::size_t>(RedactionKind::HostnameMask)])
      redactions.push_back("hostname-mask");
    if (event.privacy.redactions[static_cast<std::size_t>(RedactionKind::DomainExcluded)])
      redactions.push_back("domain-excluded");
    if (!redactions.empty()) {
      privacy["redactions"] = std::move(redactions);
    }
    doc["privacy"] = std::move(privacy);
  }

  if (event.type == EventType::Status && !event.backend_statuses.empty()) {
    json::array_t backends;
    for (const auto& b : event.backend_statuses) {
      json entry;
      entry["name"] = event_source_name(b.name);
      entry["state"] = b.active ? "active" : "unavailable";
      if (!b.detail.empty()) {
        entry["detail"] = b.detail;
      }
      backends.push_back(std::move(entry));
    }
    json status;
    status["state"] = "running";
    status["backends"] = std::move(backends);
    doc["status"] = std::move(status);
  }

  if (event.type == EventType::Error) {
    json err;
    err["code"] = event.error_code;
    err["message"] = event.error_message;
    doc["error"] = std::move(err);
  }

  return doc.dump();
}

bool IpcCodec::split_frames(std::string& buffer, std::size_t max_bytes,
                            std::vector<std::string>& frames, IpcError& error) {
  std::size_t search_from = 0;
  while (true) {
    const auto nl = buffer.find('\n', search_from);
    if (nl == std::string::npos) {
      break;
    }
    const std::size_t frame_len = nl - search_from;
    if (frame_len > max_bytes) {
      error = {ErrorCode::MessageTooLarge, "frame exceeds size limit"};
      return false;
    }
    frames.emplace_back(buffer, search_from, frame_len);
    search_from = nl + 1;
  }
  if (search_from > 0) {
    buffer.erase(0, search_from);
  }
  // Incomplete trailing data must still fit the limit once completed.
  if (buffer.size() >= max_bytes) {
    error = {ErrorCode::MessageTooLarge, "frame exceeds size limit"};
    return false;
  }
  return true;
}

}  // namespace ezcap::ipc
