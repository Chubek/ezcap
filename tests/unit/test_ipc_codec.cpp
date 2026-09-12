// Unit tests for the IPC codec: request validation (structure, version,
// forbidden fields, size caps), response/error encoding, event encoding,
// and newline frame splitting.

#include "ipc/ipc_codec.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <string>

using ezcap::ipc::IpcCodec;
using ezcap::ipc::Request;
using ezcap::ipc::Response;
using ezcap::ErrorCode;
using ezcap::EventType;
using ezcap::EventSource;
using ezcap::Transport;
using nlohmann::json;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

bool parse(const std::string& frame, Request& out, ezcap::IpcError& err) {
  return IpcCodec::parse_request(frame, ezcap::ipc::kMaxRequestBytes, out, err);
}

}  // namespace

int main() {
  // --- Valid request ----------------------------------------------------------
  {
    const std::string frame =
        R"({"protocol_version":1,"operation":"get_status","request_id":"req-1"})";
    Request req;
    ezcap::IpcError err;
    CHECK(parse(frame, req, err));
    CHECK(req.operation == ezcap::ipc::Operation::GetStatus);
    CHECK(req.request_id == "req-1");
  }

  // With params.
  {
    const std::string frame =
        R"({"protocol_version":1,"operation":"set_policy","request_id":"r2","params":{"metadata_only":true}})";
    Request req;
    ezcap::IpcError err;
    CHECK(parse(frame, req, err));
    CHECK(!req.params_json.empty());
  }

  // --- Structural rejections -----------------------------------------------------
  {
    Request req;
    ezcap::IpcError err;
    CHECK(!parse("not json", req, err));
    CHECK(err.code == ErrorCode::InvalidJson);

    CHECK(!parse("[]", req, err));
    CHECK(err.code == ErrorCode::SchemaViolation);

    CHECK(!parse("{}", req, err));
    CHECK(err.code == ErrorCode::MissingField);

    CHECK(!parse(R"({"protocol_version":2,"operation":"hello","request_id":"x"})",
                 req, err));
    CHECK(err.code == ErrorCode::UnsupportedVersion);

    CHECK(!parse(R"({"protocol_version":1,"operation":"teleport","request_id":"x"})",
                 req, err));
    CHECK(err.code == ErrorCode::UnknownOperation);

    CHECK(!parse(R"({"protocol_version":1,"operation":"hello","request_id":""})",
                 req, err));
    CHECK(err.code == ErrorCode::SchemaViolation);

    CHECK(!parse(R"({"protocol_version":1,"operation":"hello","request_id":"x","params":[]})",
                 req, err));
    CHECK(err.code == ErrorCode::SchemaViolation);
  }

  // --- Forbidden fields are rejected outright -------------------------------------
  {
    Request req;
    ezcap::IpcError err;
    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","payload":"abc"})",
        req, err));
    CHECK(err.code == ErrorCode::SchemaViolation);

    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","authorization":"Bearer y"})",
        req, err));
    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","cookies":"a=b"})",
        req, err));
    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","password":"hunter2"})",
        req, err));
    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","api_key":"k"})",
        req, err));
    CHECK(!parse(
        R"({"protocol_version":1,"operation":"hello","request_id":"x","body":"..."})",
        req, err));
  }

  // --- Size cap --------------------------------------------------------------------
  {
    Request req;
    ezcap::IpcError err;
    std::string big(1024 * 1024, 'a');  // way over 64 KiB
    CHECK(!parse(big, req, err));
    CHECK(err.code == ErrorCode::MessageTooLarge);
  }

  // --- Response / error encoding ------------------------------------------------------
  {
    Response ok;
    ok.request_id = "r3";
    ok.ok = true;
    ok.result_json = R"({"state":"running"})";
    const auto doc = json::parse(IpcCodec::encode_response(ok));
    CHECK(doc.at("ok").get<bool>());
    CHECK(doc.at("result").at("state") == "running");

    ezcap::IpcError err{ErrorCode::OperationNotAllowed, "no"};
    const auto errdoc = json::parse(IpcCodec::encode_error("r4", err));
    CHECK(!errdoc.at("ok").get<bool>());
    CHECK(errdoc.at("error").at("code") == "operation_not_allowed");
    CHECK(errdoc.at("error").at("message") == "no");
  }

  // --- Event encoding ------------------------------------------------------------------
  {
    ezcap::Event e;
    e.event_id = "00000000-0000-4000-8000-000000000003";
    e.type = EventType::Dns;
    e.source = EventSource::Pcap;
    e.timestamp = std::chrono::system_clock::now();
    e.confidence = 0.5;
    e.privacy.redacted = true;
    e.privacy.redactions[static_cast<std::size_t>(
        ezcap::RedactionKind::QueryString)] = true;

    ezcap::NetworkInfo net;
    net.transport = Transport::Udp;
    net.dns_query_name = "example.com";
    net.remote_address = "8.8.8.8";
    net.remote_port = static_cast<ezcap::Port>(53);
    e.network = net;

    const auto doc = json::parse(IpcCodec::encode_event(e));
    CHECK(doc.at("event_type") == "dns");
    CHECK(doc.at("source") == "pcap");
    CHECK(doc.at("network").at("dns_query_name") == "example.com");
    CHECK(doc.at("privacy").at("metadata_only").get<bool>() == true);
    CHECK(doc.at("privacy").at("redactions").size() == 1);
    // Forbidden fields never appear in an event encoding.
    CHECK(!doc.contains("payload"));
    CHECK(!doc.contains("body"));
    CHECK(!doc.contains("cookies"));
  }

  // --- Frame splitting --------------------------------------------------------------------
  {
    std::string buf = R"({"a":1})" "\n" R"({"b":2})" "\n" R"({"c":3})";
    std::vector<std::string> frames;
    ezcap::IpcError err;
    CHECK(IpcCodec::split_frames(buf, 1024, frames, err));
    CHECK(frames.size() == 2);  // third frame is incomplete, stays buffered
    CHECK(buf == R"({"c":3})");
    frames.clear();

    buf += "\n";
    CHECK(IpcCodec::split_frames(buf, 1024, frames, err));
    CHECK(frames.size() == 1);
    CHECK(frames[0] == R"({"c":3})");

    // Oversized frame rejected.
    std::string huge(2048, 'x');
    huge += '\n';
    CHECK(!IpcCodec::split_frames(huge, 1024, frames, err));
    CHECK(err.code == ErrorCode::MessageTooLarge);
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "ipc_codec: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("ipc_codec: all tests passed");
  return 0;
}
