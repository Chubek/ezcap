#pragma once

#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <vector>

namespace ezcap::specgen {

/// A validated endpoint descriptor (AGENTS_LUA_DRIVER.md E8.1). Descriptors
/// arrive as JSON (from Lua bindings or first-party code) and must pass
/// validate_endpoint_descriptor() before any emitter sees them.
struct EndpointDescriptor {
  std::string name;
  std::string ns;
  std::string version;
  std::string kind;          ///< "operation" | "stream" | "event"
  std::string summary;
  std::string description{};
  nlohmann::json request{};   ///< JSON Schema subset, may be empty.
  nlohmann::json response{};  ///< JSON Schema subset, may be empty.
  bool metadata_only{true};
  std::vector<std::string> attribution{};
  std::string confidence{};
  std::vector<std::string> privacy{};
};

/// Validation result. `error` is a stable, human-readable reason; it never
/// contains descriptor data beyond field names.
struct ValidationResult {
  bool ok{false};
  std::string error{};
};

/// Validate a descriptor against the constraints documented in
/// protocol/drivers/endpoint.schema.json. This mirrors the schema; the
/// schema is the source of truth and this function is the enforcement
/// point inside the daemon.
[[nodiscard]] ValidationResult validate_endpoint_descriptor(
    const nlohmann::json& doc);

/// Parse + validate in one step.
[[nodiscard]] ValidationResult parse_endpoint_descriptor(
    const nlohmann::json& doc, EndpointDescriptor& out);

/// Emitter registry (E8.2). Every emitter consumes the same validated
/// model; emitters never touch Lua, the daemon, the network, or the
/// filesystem. Output goes to a returned string — the caller owns any I/O.
enum class Format {
  OpenApi31,    ///< Default. Operations + events as webhooks.
  AsyncApi2,    ///< Stream/event endpoints.
  JsonSchema,   ///< JSON Schema bundle of all request/response shapes.
};

[[nodiscard]] const char* format_id(Format format) noexcept;
[[nodiscard]] bool format_from_id(const std::string& id, Format& out);

/// Allowed emitter ids (exposed to Lua as lezcap.spec.list_formats()).
[[nodiscard]] std::vector<std::string> list_formats();

/// Generation context recorded in every emitted document (E8.2): descriptor
/// source, generator version, schema version.
struct GenerationContext {
  std::string source;              ///< e.g. "driver:example" or "first-party".
  std::string generator_version;   ///< ezcap specgen version.
  std::uint32_t schema_version{1};
};

/// Generate a spec for `format` from validated descriptors. Deterministic:
/// identical inputs produce byte-identical output (stable key order, sorted
/// endpoints). Examples in output are synthetic and marked as such.
[[nodiscard]] bool generate(Format format,
                            const std::vector<EndpointDescriptor>& endpoints,
                            const GenerationContext& context, std::string& out,
                            std::string& error);

}  // namespace ezcap::specgen
