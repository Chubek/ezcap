// Spec generation entry point (AGENTS_LUA_DRIVER.md E8.2).
//
// The registry is the only surface: generate() dispatches to an emitter and
// nothing here performs I/O. lezcap.spec calls straight into this.

#include "specgen/emitters/emitters.hpp"

#include <algorithm>

namespace ezcap::specgen {

const char* format_id(Format format) noexcept {
  switch (format) {
    case Format::OpenApi31:
      return "openapi-3.1";
    case Format::AsyncApi2:
      return "asyncapi-2";
    case Format::JsonSchema:
      return "json-schema";
  }
  return "unknown";
}

bool format_from_id(const std::string& id, Format& out) {
  if (id == "openapi-3.1") {
    out = Format::OpenApi31;
  } else if (id == "asyncapi-2") {
    out = Format::AsyncApi2;
  } else if (id == "json-schema") {
    out = Format::JsonSchema;
  } else {
    return false;
  }
  return true;
}

std::vector<std::string> list_formats() {
  return {format_id(Format::OpenApi31), format_id(Format::AsyncApi2),
          format_id(Format::JsonSchema)};
}

bool generate(Format format, const std::vector<EndpointDescriptor>& endpoints,
              const GenerationContext& context, std::string& out,
              std::string& error) {
  // Enforce the model-level limits here as a second line of defense: the
  // bindings layer caps endpoints per driver, but first-party callers may
  // assemble larger bundles.
  if (endpoints.size() > 256) {
    error = "too many endpoints for one spec";
    return false;
  }
  // Namespace uniqueness across a bundle: two endpoints with the same
  // (namespace, name, version) would collide in every emitter.
  for (std::size_t i = 0; i < endpoints.size(); ++i) {
    for (std::size_t j = i + 1; j < endpoints.size(); ++j) {
      if (endpoints[i].ns == endpoints[j].ns &&
          endpoints[i].name == endpoints[j].name &&
          endpoints[i].version == endpoints[j].version) {
        error = "duplicate endpoint (namespace, name, version)";
        return false;
      }
    }
  }
  switch (format) {
    case Format::OpenApi31:
      out = emitters::emit_openapi31(endpoints, context);
      break;
    case Format::AsyncApi2:
      out = emitters::emit_asyncapi2(endpoints, context);
      break;
    case Format::JsonSchema:
      out = emitters::emit_json_schema(endpoints, context);
      break;
  }
  return true;
}

}  // namespace ezcap::specgen
