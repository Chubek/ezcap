#pragma once

#include "specgen/model/descriptor.hpp"

#include <string>
#include <vector>

namespace ezcap::specgen::emitters {

/// OpenAPI 3.1 document. Operations become POST paths; events become
/// webhook-style POST paths; streams get a marker path pointing at the
/// AsyncAPI output.
[[nodiscard]] std::string emit_openapi31(
    const std::vector<EndpointDescriptor>& endpoints,
    const GenerationContext& context);

/// AsyncAPI 2.6 document over stream/event endpoints.
[[nodiscard]] std::string emit_asyncapi2(
    const std::vector<EndpointDescriptor>& endpoints,
    const GenerationContext& context);

/// JSON Schema bundle of every endpoint's request/response shapes.
[[nodiscard]] std::string emit_json_schema(
    const std::vector<EndpointDescriptor>& endpoints,
    const GenerationContext& context);

}  // namespace ezcap::specgen::emitters
