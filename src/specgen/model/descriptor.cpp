// Endpoint descriptor validation (AGENTS_LUA_DRIVER.md E8.1).
//
// protocol/drivers/endpoint.schema.json is the source of truth; this file
// is the enforcement point inside the daemon. Descriptors that fail here
// never reach an emitter.

#include "specgen/model/descriptor.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace ezcap::specgen {
namespace {

bool matches_pattern_length(const std::string& value, std::size_t max_len,
                            bool allow_upper) {
  if (value.empty() || value.size() > max_len) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [allow_upper](unsigned char c) {
    if (std::isalnum(c) != 0 || c == '_' || c == '-') {
      return true;
    }
    return false;
  }) && (allow_upper || std::none_of(value.begin(), value.end(), [](unsigned char c) {
           return std::isupper(c) != 0;
         }));
}

bool valid_version(const std::string& version) {
  std::int32_t components = 0;
  std::string current;
  for (const char c : version) {
    if (c == '.') {
      if (current.empty() || components >= 2) {
        return false;
      }
      current.clear();
      ++components;
    } else if (std::isdigit(static_cast<unsigned char>(c)) != 0) {
      current += c;
    } else {
      return false;
    }
  }
  return components >= 1 && !current.empty();
}

bool valid_string_list(const nlohmann::json& parent, const char* key,
                       std::size_t max_items, std::size_t max_item_len,
                       std::vector<std::string>& out, std::string& error) {
  if (!parent.contains(key)) {
    return true;
  }
  const auto& value = parent.at(key);
  if (!value.is_array()) {
    error = std::string(key) + " must be an array";
    return false;
  }
  if (value.size() > max_items) {
    error = std::string(key) + " exceeds the item limit";
    return false;
  }
  for (const auto& entry : value) {
    if (!entry.is_string()) {
      error = std::string(key) + " entries must be strings";
      return false;
    }
    const std::string item = entry.get<std::string>();
    if (item.size() > max_item_len) {
      error = std::string(key) + " entry exceeds maximum length";
      return false;
    }
    out.push_back(item);
  }
  return true;
}

// The JSON Schema subset accepted for request/response shapes. Intentionally
// narrow (schema $defs/schemaSubset): no $ref, no external URIs, bounded
// depth and size.
constexpr std::size_t kMaxSchemaDepth = 8;
constexpr std::size_t kMaxSchemaProperties = 64;
constexpr std::size_t kMaxSchemaEnumItems = 64;

bool valid_schema_subset(const nlohmann::json& doc, std::size_t depth,
                         std::string& error) {
  if (depth > kMaxSchemaDepth) {
    error = "request/response schema exceeds maximum depth";
    return false;
  }
  if (!doc.is_object()) {
    error = "request/response schema must be an object";
    return false;
  }
  for (const auto& [key, value] : doc.items()) {
    if (key != "type" && key != "description" && key != "properties" &&
        key != "items" && key != "required" && key != "enum") {
      error = "request/response schema contains unsupported key";
      return false;
    }
  }
  if (!doc.contains("type") || !doc.at("type").is_string()) {
    error = "request/response schema requires a type";
    return false;
  }
  const std::string type = doc.at("type").get<std::string>();
  static constexpr std::array<const char*, 7> kTypes = {
      "object", "array", "string", "number", "integer", "boolean", "null"};
  if (std::find(kTypes.begin(), kTypes.end(), type) == kTypes.end()) {
    error = "request/response schema has unknown type";
    return false;
  }
  if (doc.contains("description") &&
      (!doc.at("description").is_string() ||
       doc.at("description").get<std::string>().size() > 512)) {
    error = "schema description must be a bounded string";
    return false;
  }
  if (doc.contains("properties")) {
    const auto& props = doc.at("properties");
    if (!props.is_object() || props.size() > kMaxSchemaProperties) {
      error = "schema properties must be a bounded object";
      return false;
    }
    for (const auto& [name, sub] : props.items()) {
      if (name.empty() || name.size() > 64 ||
          !std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '_';
          })) {
        error = "schema property name is invalid";
        return false;
      }
      if (!valid_schema_subset(sub, depth + 1, error)) {
        return false;
      }
    }
  }
  if (doc.contains("items")) {
    if (!valid_schema_subset(doc.at("items"), depth + 1, error)) {
      return false;
    }
  }
  if (doc.contains("required")) {
    const auto& required = doc.at("required");
    if (!required.is_array() || required.size() > kMaxSchemaProperties) {
      error = "schema required must be a bounded array";
      return false;
    }
    for (const auto& entry : required) {
      if (!entry.is_string() || entry.get<std::string>().size() > 64) {
        error = "schema required entries must be bounded strings";
        return false;
      }
    }
  }
  if (doc.contains("enum")) {
    const auto& enumeration = doc.at("enum");
    if (!enumeration.is_array() || enumeration.size() > kMaxSchemaEnumItems) {
      error = "schema enum must be a bounded array";
      return false;
    }
    for (const auto& entry : enumeration) {
      if (!entry.is_string() && !entry.is_number() && !entry.is_boolean() &&
          !entry.is_null()) {
        error = "schema enum entries must be scalars";
        return false;
      }
    }
  }
  return true;
}

}  // namespace

ValidationResult validate_endpoint_descriptor(const nlohmann::json& doc) {
  ValidationResult result;
  if (!doc.is_object()) {
    result.error = "descriptor must be a JSON object";
    return result;
  }

  if (!doc.contains("name") || !doc.at("name").is_string()) {
    result.error = "descriptor.name is required";
    return result;
  }
  const std::string name = doc.at("name").get<std::string>();
  if (!matches_pattern_length(name, 64, /*allow_upper=*/true)) {
    result.error = "descriptor.name must match [a-zA-Z0-9_-]{1,64}";
    return result;
  }

  if (!doc.contains("namespace") || !doc.at("namespace").is_string()) {
    result.error = "descriptor.namespace is required";
    return result;
  }
  const std::string ns = doc.at("namespace").get<std::string>();
  if (!matches_pattern_length(ns, 64, /*allow_upper=*/false)) {
    result.error = "descriptor.namespace must match [a-z0-9-]{1,64}";
    return result;
  }

  if (!doc.contains("version") || !doc.at("version").is_string()) {
    result.error = "descriptor.version is required";
    return result;
  }
  const std::string version = doc.at("version").get<std::string>();
  if (!valid_version(version)) {
    result.error = "descriptor.version must be numeric x.y[.z]";
    return result;
  }

  if (!doc.contains("kind") || !doc.at("kind").is_string()) {
    result.error = "descriptor.kind is required";
    return result;
  }
  const std::string kind = doc.at("kind").get<std::string>();
  if (kind != "operation" && kind != "stream" && kind != "event") {
    result.error = "descriptor.kind must be operation, stream, or event";
    return result;
  }

  if (!doc.contains("summary") || !doc.at("summary").is_string()) {
    result.error = "descriptor.summary is required";
    return result;
  }
  const std::string summary = doc.at("summary").get<std::string>();
  if (summary.empty() || summary.size() > 256) {
    result.error = "descriptor.summary must be 1..256 characters";
    return result;
  }

  if (!doc.contains("metadata_only") || !doc.at("metadata_only").is_boolean()) {
    result.error = "descriptor.metadata_only is required";
    return result;
  }
  // The schema pins const true: any descriptor that could carry observed
  // data must declare metadata_only, and the daemon only ever produces
  // metadata-only endpoints from observations.
  if (!doc.at("metadata_only").get<bool>()) {
    result.error = "descriptor.metadata_only must be true";
    return result;
  }

  for (const auto& [key, value] : doc.items()) {
    (void)value;
    if (key != "name" && key != "namespace" && key != "version" &&
        key != "kind" && key != "summary" && key != "description" &&
        key != "request" && key != "response" && key != "metadata_only" &&
        key != "attribution" && key != "confidence" && key != "privacy") {
      result.error = "descriptor contains unknown field";
      return result;
    }
  }

  std::string error;
  if (doc.contains("description") && !doc.at("description").is_null()) {
    if (!doc.at("description").is_string() ||
        doc.at("description").get<std::string>().size() > 2048) {
      result.error = "descriptor.description must be a bounded string";
      return result;
    }
  }
  if (doc.contains("confidence") && !doc.at("confidence").is_null()) {
    if (!doc.at("confidence").is_string() ||
        doc.at("confidence").get<std::string>().size() > 256) {
      result.error = "descriptor.confidence must be a bounded string";
      return result;
    }
  }
  std::vector<std::string> attribution;
  if (!valid_string_list(doc, "attribution", 16, 512, attribution, error)) {
    result.error = error;
    return result;
  }
  std::vector<std::string> privacy;
  if (!valid_string_list(doc, "privacy", 16, 512, privacy, error)) {
    result.error = error;
    return result;
  }

  if (doc.contains("request") && !doc.at("request").is_null()) {
    if (!valid_schema_subset(doc.at("request"), 0, error)) {
      result.error = error;
      return result;
    }
  }
  if (doc.contains("response") && !doc.at("response").is_null()) {
    if (!valid_schema_subset(doc.at("response"), 0, error)) {
      result.error = error;
      return result;
    }
  }

  result.ok = true;
  return result;
}

ValidationResult parse_endpoint_descriptor(const nlohmann::json& doc,
                                           EndpointDescriptor& out) {
  ValidationResult result = validate_endpoint_descriptor(doc);
  if (!result.ok) {
    return result;
  }
  out = EndpointDescriptor{};
  out.name = doc.at("name").get<std::string>();
  out.ns = doc.at("namespace").get<std::string>();
  out.version = doc.at("version").get<std::string>();
  out.kind = doc.at("kind").get<std::string>();
  out.summary = doc.at("summary").get<std::string>();
  if (doc.contains("description") && doc.at("description").is_string()) {
    out.description = doc.at("description").get<std::string>();
  }
  if (doc.contains("request") && doc.at("request").is_object()) {
    out.request = doc.at("request");
  }
  if (doc.contains("response") && doc.at("response").is_object()) {
    out.response = doc.at("response");
  }
  out.metadata_only = true;  // validate() rejects anything else.
  if (doc.contains("attribution")) {
    for (const auto& entry : doc.at("attribution")) {
      out.attribution.push_back(entry.get<std::string>());
    }
  }
  if (doc.contains("confidence") && doc.at("confidence").is_string()) {
    out.confidence = doc.at("confidence").get<std::string>();
  }
  if (doc.contains("privacy")) {
    for (const auto& entry : doc.at("privacy")) {
      out.privacy.push_back(entry.get<std::string>());
    }
  }
  return result;
}

}  // namespace ezcap::specgen
