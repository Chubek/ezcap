// Spec emitters (AGENTS_LUA_DRIVER.md E8.2).
//
// Pure functions over validated descriptors. No I/O, no daemon access, no
// Lua: output is a string the caller owns. Determinism comes from sorting
// endpoints by (namespace, name, version) and serializing through
// nlohmann::json, whose object keys emit in sorted order. Examples in
// output are synthetic constants, clearly marked — never values derived
// from observations.

#include "specgen/emitters/emitters.hpp"

#include <algorithm>
#include <set>

namespace ezcap::specgen::emitters {
namespace {

using nlohmann::json;

void sort_endpoints(std::vector<const EndpointDescriptor*>& out,
                    const std::vector<EndpointDescriptor>& endpoints) {
  out.clear();
  for (const auto& endpoint : endpoints) {
    out.push_back(&endpoint);
  }
  std::sort(out.begin(), out.end(),
            [](const EndpointDescriptor* a, const EndpointDescriptor* b) {
              if (a->ns != b->ns) return a->ns < b->ns;
              if (a->name != b->name) return a->name < b->name;
              return a->version < b->version;
            });
}

void apply_privacy_annotations(json& target,
                               const EndpointDescriptor& endpoint) {
  if (!endpoint.attribution.empty()) {
    json attribution = json::array();
    for (const auto& note : endpoint.attribution) {
      attribution.push_back(note);
    }
    target["x-ezcap-attribution"] = std::move(attribution);
  }
  if (!endpoint.confidence.empty()) {
    target["x-ezcap-confidence"] = endpoint.confidence;
  }
  if (!endpoint.privacy.empty()) {
    json privacy = json::array();
    for (const auto& note : endpoint.privacy) {
      privacy.push_back(note);
    }
    target["x-ezcap-privacy"] = std::move(privacy);
  }
  // Metadata-only is constant for observed surfaces; record it explicitly so
  // consumers never have to infer it.
  target["x-ezcap-metadata-only"] = true;
}

}  // namespace

std::string emit_openapi31(const std::vector<EndpointDescriptor>& endpoints,
                           const GenerationContext& context) {
  json doc;
  doc["openapi"] = "3.1.0";
  doc["info"] = {{"title", "ezcap generated API"},
                 {"version", context.generator_version},
                 {"summary", "Generated from ezcap endpoint descriptors"},
                 {"x-ezcap-source", context.source},
                 {"x-ezcap-schema-version", context.schema_version},
                 {"x-ezcap-generated", "synthetic; contains no observed data"}};

  json paths = json::object();
  json components = json::object();
  json schemas = json::object();
  std::set<std::string> seen_ops;

  std::vector<const EndpointDescriptor*> sorted;
  sort_endpoints(sorted, endpoints);
  for (const auto* endpoint : sorted) {
    const std::string path =
        "/" + endpoint->ns + "/" + endpoint->name + "/v" + endpoint->version;

    json operation;
    operation["operationId"] = endpoint->ns + "." + endpoint->name;
    operation["summary"] = endpoint->summary;
    if (!endpoint->description.empty()) {
      operation["description"] = endpoint->description;
    }
    // Synthetic example, marked as such: generated specs must never carry
    // example values derived from real observations (E8.2).
    operation["x-ezcap-example"] = "synthetic placeholder; not observed data";
    apply_privacy_annotations(operation, *endpoint);

    if (endpoint->request.is_object()) {
      const std::string schema_name =
          endpoint->ns + "_" + endpoint->name + "_request";
      operation["requestBody"] = {{"required", true},
                                  {"content",
                                   {{"application/json",
                                     {{"schema",
                                       {{"$ref",
                                         "#/components/schemas/" + schema_name}}}}}}}};
      schemas[schema_name] = endpoint->request;
    }
    if (endpoint->response.is_object()) {
      const std::string schema_name =
          endpoint->ns + "_" + endpoint->name + "_response";
      operation["responses"] = {
          {"200",
           {{"description", "Success"},
            {"content",
             {{"application/json",
               {{"schema",
                 {{"$ref", "#/components/schemas/" + schema_name}}}}}}}}}};
      schemas[schema_name] = endpoint->response;
    } else {
      operation["responses"] = {{"204", {{"description", "No content"}}}};
    }

    if (endpoint->kind == "operation" || endpoint->kind == "event") {
      // Events surface as webhooks; operations as POST.
      if (seen_ops.insert(path).second) {
        paths[path] = json::object();
      }
      paths[path][endpoint->kind == "event" ? "post" : "post"] =
          std::move(operation);
      if (endpoint->kind == "event") {
        paths[path]["post"]["x-ezcap-kind"] = "event";
      }
    } else {
      // Streams are not request/response surfaces; they are described in
      // AsyncAPI output. Record a marker so the surface is discoverable.
      if (seen_ops.insert(path + "#stream").second) {
        json marker;
        marker["summary"] = endpoint->summary + " (stream; see AsyncAPI spec)";
        marker["x-ezcap-kind"] = "stream";
        apply_privacy_annotations(marker, *endpoint);
        paths[path] = {{"get", std::move(marker)}};
      }
    }
  }

  doc["paths"] = std::move(paths);
  if (!schemas.empty()) {
    components["schemas"] = std::move(schemas);
    doc["components"] = std::move(components);
  }
  return doc.dump(2) + "\n";
}

std::string emit_asyncapi2(const std::vector<EndpointDescriptor>& endpoints,
                           const GenerationContext& context) {
  json doc;
  doc["asyncapi"] = "2.6.0";
  doc["info"] = {{"title", "ezcap generated event API"},
                 {"version", context.generator_version},
                 {"x-ezcap-source", context.source},
                 {"x-ezcap-schema-version", context.schema_version},
                 {"x-ezcap-generated", "synthetic; contains no observed data"}};

  json channels = json::object();
  json components = json::object();
  json messages = json::object();

  std::vector<const EndpointDescriptor*> sorted;
  sort_endpoints(sorted, endpoints);
  for (const auto* endpoint : sorted) {
    if (endpoint->kind == "operation") {
      continue;  // Not an event surface.
    }
    const std::string channel =
        endpoint->ns + "/" + endpoint->name + "/v" + endpoint->version;

    json message;
    message["name"] = endpoint->ns + "." + endpoint->name;
    message["title"] = endpoint->summary;
    if (!endpoint->description.empty()) {
      message["description"] = endpoint->description;
    }
    message["x-ezcap-example"] = "synthetic placeholder; not observed data";
    if (endpoint->response.is_object()) {
      message["payload"] = endpoint->response;
    }
    apply_privacy_annotations(message, *endpoint);

    const std::string message_name = endpoint->ns + "_" + endpoint->name;
    messages[message_name] = message;

    json publish = {{"message",
                     {{"$ref", "#/components/messages/" + message_name}}}};
    // Confidence semantics are preserved in generated specs (E13): the
    // descriptor-level note rides along on the channel.
    json channel_doc = {{"publish", std::move(publish)}};
    if (!endpoint->confidence.empty()) {
      channel_doc["x-ezcap-confidence"] = endpoint->confidence;
    }
    channels[channel] = std::move(channel_doc);
  }

  doc["channels"] = std::move(channels);
  if (!messages.empty()) {
    components["messages"] = std::move(messages);
    doc["components"] = std::move(components);
  }
  return doc.dump(2) + "\n";
}

std::string emit_json_schema(const std::vector<EndpointDescriptor>& endpoints,
                             const GenerationContext& context) {
  json doc;
  doc["$schema"] = "https://json-schema.org/draft/2020-12/schema";
  doc["title"] = "ezcap endpoint schema bundle";
  doc["x-ezcap-source"] = context.source;
  doc["x-ezcap-generator-version"] = context.generator_version;
  doc["x-ezcap-schema-version"] = context.schema_version;
  doc["x-ezcap-generated"] = "synthetic; contains no observed data";
  doc["type"] = "object";

  json defs = json::object();
  std::vector<const EndpointDescriptor*> sorted;
  sort_endpoints(sorted, endpoints);
  for (const auto* endpoint : sorted) {
    json entry;
    entry["title"] = endpoint->summary;
    if (!endpoint->description.empty()) {
      entry["description"] = endpoint->description;
    }
    if (endpoint->request.is_object()) {
      entry["x-ezcap-request"] = endpoint->request;
    }
    if (endpoint->response.is_object()) {
      entry["x-ezcap-response"] = endpoint->response;
    }
    apply_privacy_annotations(entry, *endpoint);
    defs[endpoint->ns + "_" + endpoint->name] = std::move(entry);
  }
  if (!defs.empty()) {
    doc["$defs"] = std::move(defs);
  }
  return doc.dump(2) + "\n";
}

}  // namespace ezcap::specgen::emitters
