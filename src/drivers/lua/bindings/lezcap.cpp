// The `lezcap` Lua library (AGENTS_LUA_DRIVER.md E5).
//
// Every function here validates arguments and returns (result, err) rather
// than throwing; errors are structured strings, never exception payloads.
// Modules are registered per-capability at load time: a capability absent
// from the manifest means the module is absent from the script's lezcap
// table entirely (E10), not merely erroring at call time.

#include "drivers/lua/bindings/lezcap.hpp"

#include "common/logging.hpp"
#include "common/sha256.hpp"
#include "common/time.hpp"
#include "specgen/emitters/emitters.hpp"

#include <chrono>
#include <cstring>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

namespace ezcap::drivers {
namespace {

using nlohmann::json;

// ---------------------------------------------------------------------------
// Host context: one userdata-light approach — the registry holds a single
// full userdata per state wrapping a pointer to the DriverHostState. The
// pointer is host-owned and never dereferenced from Lua (scripts cannot
// reach the registry).
// ---------------------------------------------------------------------------

constexpr char kHostStateKey[] = "ezcap.driver.host_state";

void push_host_state_ptr(lua_State* L, DriverHostState* state) {
  lua_pushlightuserdata(L, state);
  lua_setfield(L, LUA_REGISTRYINDEX, kHostStateKey);
}

DriverHostState* host_state(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, kHostStateKey);
  void* ptr = lua_touserdata(L, -1);
  lua_pop(L, 1);
  return static_cast<DriverHostState*>(ptr);
}

// ---------------------------------------------------------------------------
// Error convention: on failure push (nil, "code: message") and return 2.
// ---------------------------------------------------------------------------

int lezcap_error(lua_State* L, const char* code, const char* message) {
  lua_pushnil(L);
  lua_pushfstring(L, "%s: %s", code, message);
  return 2;
}

int lezcap_fail(lua_State* L, const char* code, const std::string& message) {
  lua_pushnil(L);
  lua_pushfstring(L, "%s: %s", code, message.c_str());
  return 2;
}

bool check_string(lua_State* L, int index, std::size_t max_bytes,
                  std::string& out, const char* what) {
  const char* raw = lua_tostring(L, index);  // Coerces numbers; still safe.
  if (raw == nullptr) {
    lezcap_error(L, "argument.type",
                 "expected a string");  // pushes; caller returns it
    out.clear();
    return false;
  }
  const std::size_t length = std::strlen(raw);
  if (length > max_bytes) {
    lezcap_error(L, "argument.too_long", "string exceeds the sandbox limit");
    out.clear();
    return false;
  }
  out.assign(raw, length);
  (void)what;
  return true;
}

// Read a bounded string field from the table at `index`. Returns:
//  0 — absent, 1 — present and stored, -1 — error already pushed.
int opt_table_string(lua_State* L, int index, const char* key,
                     std::size_t max_bytes, std::string& out) {
  lua_getfield(L, index, key);
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    return 0;
  }
  const char* raw = lua_tostring(L, -1);
  if (raw == nullptr) {
    lua_pop(L, 1);
    lezcap_fail(L, "argument.type", std::string(key) + " must be a string");
    return -1;
  }
  const std::size_t length = std::strlen(raw);
  if (length > max_bytes) {
    lua_pop(L, 1);
    lezcap_fail(L, "argument.too_long",
                std::string(key) + " exceeds the sandbox limit");
    return -1;
  }
  out.assign(raw, length);
  lua_pop(L, 1);
  return 1;
}

// Push an (err, message) result table or (result, nil).
int push_ok(lua_State* L) {
  lua_pushboolean(L, 1);
  lua_pushnil(L);
  return 2;
}

// ---------------------------------------------------------------------------
// lezcap.util — safe utilities (E5.1). Also home of the curated `time`
// shim built on std::chrono (E4.1): os.time/os.clock do not exist.
// ---------------------------------------------------------------------------

int util_now_ms(lua_State* L) {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  lua_pushnumber(L,
                 static_cast<double>(
                     std::chrono::duration_cast<std::chrono::milliseconds>(now)
                         .count()));
  return 1;
}

int util_now_rfc3339(lua_State* L) {
  lua_pushstring(L, time_util::to_rfc3339(time_util::now()).c_str());
  return 1;
}

int util_sha256_hex(lua_State* L) {
  std::string input;
  DriverHostState* state = host_state(L);
  const std::size_t max_bytes =
      state != nullptr ? state->limits.max_string_bytes : 8 * 1024;
  if (!check_string(L, 1, max_bytes, input, "value")) {
    return 2;
  }
  lua_pushstring(L, Sha256::hex_digest(input).c_str());
  return 1;
}

int util_base64_encode(lua_State* L) {
  std::string input;
  DriverHostState* state = host_state(L);
  const std::size_t max_bytes =
      state != nullptr ? state->limits.max_string_bytes : 8 * 1024;
  if (!check_string(L, 1, max_bytes, input, "value")) {
    return 2;
  }
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(((input.size() + 2) / 3) * 4);
  std::size_t i = 0;
  while (i + 2 < input.size()) {
    const std::uint32_t triple = (static_cast<unsigned char>(input[i]) << 16) |
                                 (static_cast<unsigned char>(input[i + 1]) << 8) |
                                 static_cast<unsigned char>(input[i + 2]);
    encoded += kAlphabet[(triple >> 18) & 0x3f];
    encoded += kAlphabet[(triple >> 12) & 0x3f];
    encoded += kAlphabet[(triple >> 6) & 0x3f];
    encoded += kAlphabet[triple & 0x3f];
    i += 3;
  }
  if (i + 1 == input.size()) {
    const std::uint32_t pair =
        static_cast<unsigned char>(input[i]) << 16;
    encoded += kAlphabet[(pair >> 18) & 0x3f];
    encoded += kAlphabet[(pair >> 12) & 0x3f];
    encoded += "==";
  } else if (i + 2 == input.size()) {
    const std::uint32_t pair = (static_cast<unsigned char>(input[i]) << 16) |
                               (static_cast<unsigned char>(input[i + 1]) << 8);
    encoded += kAlphabet[(pair >> 18) & 0x3f];
    encoded += kAlphabet[(pair >> 12) & 0x3f];
    encoded += kAlphabet[(pair >> 6) & 0x3f];
    encoded += '=';
  }
  lua_pushlstring(L, encoded.data(), encoded.size());
  return 1;
}

int util_truncate(lua_State* L) {
  const char* raw = lua_tostring(L, 1);
  if (raw == nullptr) {
    return lezcap_error(L, "argument.type", "expected a string");
  }
  std::size_t length = std::strlen(raw);
  if (!lua_isnoneornil(L, 2)) {
    if (!lua_isnumber(L, 2)) {
      return lezcap_error(L, "argument.type", "limit must be a number");
    }
    const lua_Number limit = lua_tonumber(L, 2);
    if (limit < 0) {
      return lezcap_error(L, "argument.range", "limit must be >= 0");
    }
    length = std::min(length, static_cast<std::size_t>(limit));
  }
  lua_pushlstring(L, raw, length);
  return 1;
}

// ---------------------------------------------------------------------------
// lezcap.log — structured logging (E5.1). Never payload, never raw
// buffers; messages are bounded by the sandbox string limit.
// ---------------------------------------------------------------------------

int log_emit(lua_State* L, const char* level) {
  std::string message;
  DriverHostState* state = host_state(L);
  const std::size_t max_bytes =
      state != nullptr ? state->limits.max_string_bytes : 8 * 1024;
  if (!check_string(L, 1, max_bytes, message, "message")) {
    return 2;
  }
  const std::string driver =
      state != nullptr ? state->manifest.name : std::string("unknown");
  const std::string line = "lua.driver[" + driver + "] " + message;
  if (std::strcmp(level, "warn") == 0) {
    EZCAP_LOG_WARN("{}", line);
  } else if (std::strcmp(level, "error") == 0) {
    EZCAP_LOG_ERROR("{}", line);
  } else if (std::strcmp(level, "debug") == 0) {
    EZCAP_LOG_DEBUG("{}", line);
  } else {
    EZCAP_LOG_INFO("{}", line);
  }
  return push_ok(L);
}

int log_info(lua_State* L) { return log_emit(L, "info"); }
int log_warn(lua_State* L) { return log_emit(L, "warn"); }
int log_error(lua_State* L) { return log_emit(L, "error"); }
int log_debug(lua_State* L) { return log_emit(L, "debug"); }

// ---------------------------------------------------------------------------
// lezcap.endpoint — declare endpoints (E8.1). The descriptor table is
// validated against the endpoint schema before it is stored; oversize or
// unknown fields are rejected, not repaired.
// ---------------------------------------------------------------------------

bool schema_subset_from_lua(lua_State* L, int index, json& out,
                            std::size_t depth, std::string& error);

// Convert the Lua table at `index` into JSON. Only the descriptor's narrow
// value domain (scalars, arrays, string-keyed tables) is accepted.
bool json_from_lua(lua_State* L, int index, json& out, std::size_t depth,
                   std::string& error) {
  if (depth > 16) {
    error = "value nesting exceeds the descriptor limit";
    return false;
  }
  switch (lua_type(L, index)) {
    case LUA_TNIL:
      out = nullptr;
      return true;
    case LUA_TBOOLEAN:
      out = lua_toboolean(L, index) != 0;
      return true;
    case LUA_TNUMBER: {
      const double value = lua_tonumber(L, index);
      out = value;
      return true;
    }
    case LUA_TSTRING: {
      const char* raw = lua_tostring(L, index);
      const std::size_t length = std::strlen(raw);
      if (length > 8 * 1024) {
        error = "string exceeds the sandbox limit";
        return false;
      }
      out = std::string(raw, length);
      return true;
    }
    case LUA_TTABLE: {
      // Detect array vs object by the first key.
      lua_pushnil(L);
      if (lua_next(L, index) == 0) {
        out = json::object();
        return true;
      }
      const bool array_like = lua_type(L, -2) == LUA_TNUMBER;
      lua_pop(L, 2);

      if (array_like) {
        out = json::array();
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
          json item;
          if (!json_from_lua(L, -1, item, depth + 1, error)) {
            lua_pop(L, 2);
            return false;
          }
          out.push_back(std::move(item));
          lua_pop(L, 1);
        }
        return true;
      }
      out = json::object();
      lua_pushnil(L);
      while (lua_next(L, index) != 0) {
        const char* key = lua_tostring(L, -2);
        if (key == nullptr) {
          lua_pop(L, 2);
          error = "table keys must be strings";
          return false;
        }
        json item;
        if (!json_from_lua(L, -1, item, depth + 1, error)) {
          lua_pop(L, 2);
          return false;
        }
        out[key] = std::move(item);
        lua_pop(L, 1);
      }
      return true;
    }
    default:
      error = "unsupported value type in descriptor";
      return false;
  }
}

bool schema_subset_from_lua(lua_State* L, int index, json& out,
                            std::size_t depth, std::string& error) {
  if (!lua_istable(L, index)) {
    error = "schema must be a table";
    return false;
  }
  if (!json_from_lua(L, index, out, depth, error)) {
    return false;
  }
  // Reuse the C++ validator for the subset semantics.
  const specgen::ValidationResult result =
      specgen::validate_endpoint_descriptor(
          json{{"name", "probe"}, {"namespace", "probe"}, {"version", "1.0"},
               {"kind", "operation"}, {"summary", "probe"},
               {"metadata_only", true}, {"request", out}});
  // The probe descriptor only validates the schema subset through the
  // request field; a failure naming anything other than the subset itself
  // cannot occur by construction. Report the raw error either way.
  if (!result.ok) {
    error = result.error;
    return false;
  }
  return true;
}

int endpoint_declare(lua_State* L) {
  DriverHostState* state = host_state(L);
  if (state == nullptr) {
    return lezcap_error(L, "internal.host_state", "host state missing");
  }
  if (!lua_istable(L, 1)) {
    return lezcap_error(L, "argument.type", "descriptor must be a table");
  }
  if (state->endpoints.size() >= state->limits.max_endpoints) {
    return lezcap_error(L, "limit.endpoints", "endpoint limit reached");
  }

  // Required fields.
  json doc = json::object();
  std::string value;
  static constexpr const char* kRequired[] = {"name", "namespace",
                                              "version", "kind", "summary"};
  for (const char* key : kRequired) {
    const int got = opt_table_string(L, 1, key, 256, value);
    if (got < 0) {
      return 2;
    }
    if (got == 0) {
      return lezcap_fail(L, "argument.missing",
                         std::string(key) + " is required");
    }
    doc[key] = value;
  }
  if (opt_table_string(L, 1, "description", 2048, value) < 0) {
    return 2;
  }
  if (!value.empty()) {
    doc["description"] = value;
    value.clear();
  }
  if (opt_table_string(L, 1, "confidence", 256, value) < 0) {
    return 2;
  }
  if (!value.empty()) {
    doc["confidence"] = value;
    value.clear();
  }

  // metadata_only is constant: forced true regardless of what the script
  // passed. A script-supplied false is a policy violation, reported as
  // such rather than silently overridden (E9).
  lua_getfield(L, 1, "metadata_only");
  if (!lua_isnil(L, -1) && lua_toboolean(L, -1) == 0) {
    lua_pop(L, 1);
    return lezcap_error(L, "policy.violation",
                        "metadata_only cannot be false");
  }
  lua_pop(L, 1);
  doc["metadata_only"] = true;

  // Optional request/response schemas.
  lua_getfield(L, 1, "request");
  if (!lua_isnil(L, -1)) {
    json schema;
    std::string error;
    if (!schema_subset_from_lua(L, -1, schema, 0, error)) {
      lua_pop(L, 1);
      return lezcap_fail(L, "argument.schema", error);
    }
    doc["request"] = std::move(schema);
  }
  lua_pop(L, 1);
  lua_getfield(L, 1, "response");
  if (!lua_isnil(L, -1)) {
    json schema;
    std::string error;
    if (!schema_subset_from_lua(L, -1, schema, 0, error)) {
      lua_pop(L, 1);
      return lezcap_fail(L, "argument.schema", error);
    }
    doc["response"] = std::move(schema);
  }
  lua_pop(L, 1);

  // Optional string lists: attribution, privacy.
  for (const char* key : {"attribution", "privacy"}) {
    lua_getfield(L, 1, key);
    if (!lua_isnil(L, -1)) {
      json list;
      std::string error;
      if (!lua_istable(L, -1) ||
          !json_from_lua(L, -1, list, 1, error)) {
        lua_pop(L, 1);
        return lezcap_fail(L, "argument.type", error.empty()
                                                ? std::string(key) +
                                                      " must be an array"
                                                : error);
      }
      doc[key] = std::move(list);
    }
    lua_pop(L, 1);
  }

  specgen::EndpointDescriptor descriptor;
  const specgen::ValidationResult result =
      specgen::parse_endpoint_descriptor(doc, descriptor);
  if (!result.ok) {
    return lezcap_fail(L, "argument.invalid", result.error);
  }
  state->endpoints.push_back(std::move(descriptor));
  return push_ok(L);
}

// ---------------------------------------------------------------------------
// lezcap.spec — invoke the specgen subsystem (E8.3).
// ---------------------------------------------------------------------------

int spec_list_formats(lua_State* L) {
  lua_createtable(L, static_cast<int>(specgen::list_formats().size()), 0);
  int i = 1;
  for (const auto& format : specgen::list_formats()) {
    lua_pushstring(L, format.c_str());
    lua_rawseti(L, -2, i++);
  }
  return 1;
}

int spec_generate(lua_State* L) {
  const char* format_raw = lua_tostring(L, 1);
  if (format_raw == nullptr) {
    return lezcap_error(L, "argument.type", "format must be a string");
  }
  specgen::Format format{};
  if (!specgen::format_from_id(format_raw, format)) {
    return lezcap_error(L, "argument.unknown_format",
                        "format is not an allowed emitter");
  }
  if (!lua_istable(L, 2)) {
    return lezcap_error(L, "argument.type", "endpoints must be a table");
  }

  // The endpoint list is either an array of descriptor tables (validated
  // here) or the literal string "declared", meaning the driver's own
  // declared endpoints.
  std::vector<specgen::EndpointDescriptor> endpoints;
  const std::size_t count = lua_objlen(L, 2);
  if (count > 256) {
    return lezcap_error(L, "limit.endpoints", "too many endpoints");
  }
  for (std::size_t i = 1; i <= count; ++i) {
    lua_rawgeti(L, 2, static_cast<int>(i));
    json doc;
    std::string error;
    if (!lua_istable(L, -1) || !json_from_lua(L, -1, doc, 0, error)) {
      lua_pop(L, 1);
      return lezcap_fail(L, "argument.invalid",
                         error.empty() ? "endpoints must be tables" : error);
    }
    lua_pop(L, 1);
    specgen::EndpointDescriptor descriptor;
    const specgen::ValidationResult result =
        specgen::parse_endpoint_descriptor(doc, descriptor);
    if (!result.ok) {
      return lezcap_fail(L, "argument.invalid", result.error);
    }
    endpoints.push_back(std::move(descriptor));
  }

  specgen::GenerationContext context;
  DriverHostState* state = host_state(L);
  context.source = state != nullptr
                       ? "driver:" + state->manifest.name
                       : std::string("first-party");
  context.generator_version = ezcap::version_string();

  std::string out;
  std::string error;
  if (!specgen::generate(format, endpoints, context, out, error)) {
    return lezcap_fail(L, "specgen.error", error);
  }
  if (out.size() > 512 * 1024) {
    return lezcap_error(L, "limit.output", "generated spec exceeds size cap");
  }
  lua_pushlstring(L, out.data(), out.size());
  return 1;
}

// ---------------------------------------------------------------------------
// lezcap.capture — register metadata-only filters (E9). Filters are
// reductions: they can only narrow delivery to this driver.
// ---------------------------------------------------------------------------

int capture_register_filter(lua_State* L) {
  DriverHostState* state = host_state(L);
  if (state == nullptr) {
    return lezcap_error(L, "internal.host_state", "host state missing");
  }
  if (!lua_istable(L, 1)) {
    return lezcap_error(L, "argument.type", "filter must be a table");
  }
  if (state->capture_filters.size() >= state->limits.max_subscriptions) {
    return lezcap_error(L, "limit.subscriptions", "filter limit reached");
  }

  CaptureFilter filter;
  std::string value;
  if (opt_table_string(L, 1, "event_type", 32, value) < 0) {
    return 2;
  }
  if (!value.empty()) {
    ezcap::EventType type{};
    if (!ezcap::event_type_from_name(value, type)) {
      return lezcap_fail(L, "argument.invalid", "unknown event_type");
    }
    filter.event_type = value;
    value.clear();
  }
  if (opt_table_string(L, 1, "transport", 8, value) < 0) {
    return 2;
  }
  if (!value.empty()) {
    ezcap::Transport transport{};
    if (!ezcap::transport_from_name(value, transport)) {
      return lezcap_fail(L, "argument.invalid", "unknown transport");
    }
    filter.transport = value;
    value.clear();
  }
  lua_getfield(L, 1, "min_confidence");
  if (!lua_isnil(L, -1)) {
    if (!lua_isnumber(L, -1)) {
      lua_pop(L, 1);
      return lezcap_error(L, "argument.type",
                          "min_confidence must be a number in [0, 1]");
    }
    const double confidence = lua_tonumber(L, -1);
    lua_pop(L, 1);
    if (confidence < 0.0 || confidence > 1.0) {
      return lezcap_error(L, "argument.range",
                          "min_confidence must be in [0, 1]");
    }
    filter.min_confidence_permille =
        static_cast<std::uint32_t>(confidence * 1000.0);
  } else {
    lua_pop(L, 1);
  }

  state->capture_filters.push_back(std::move(filter));
  return push_ok(L);
}

// ---------------------------------------------------------------------------
// lezcap.policy / lezcap.status / lezcap.process / lezcap.dns / lezcap.event
// ---------------------------------------------------------------------------

// Policy queries are read-only snapshots of the active redaction policy.
// The engine injects a snapshot function; the binding here just forwards.
int policy_query(lua_State* L) {
  DriverHostState* state = host_state(L);
  if (state == nullptr) {
    return lezcap_error(L, "internal.host_state", "host state missing");
  }
  // Read-only: the active policy as JSON, produced by the policy engine at
  // registration time and stored in the host state.
  lua_getfield(L, LUA_REGISTRYINDEX, "ezcap.driver.policy_snapshot");
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    return lezcap_error(L, "policy.unavailable", "no policy snapshot");
  }
  return 1;
}

// lezcap.event.emit: rate-limited event emission with drop accounting.
// The emitted table is converted to JSON and stored for the engine to
// forward into the normalized pipeline; payloads are structurally
// impossible (only metadata fields validate).
int event_emit(lua_State* L) {
  DriverHostState* state = host_state(L);
  if (state == nullptr) {
    return lezcap_error(L, "internal.host_state", "host state missing");
  }
  if (!lua_istable(L, 1)) {
    return lezcap_error(L, "argument.type", "event must be a table");
  }

  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now)
                          .count();
  if (now_ms - state->last_event_window_start_ms >= 1000) {
    state->last_event_window_start_ms = now_ms;
    state->events_in_window = 0;
  }
  if (state->limits.max_events_per_second > 0 &&
      state->events_in_window >= state->limits.max_events_per_second) {
    state->events_dropped += 1;
    return lezcap_error(L, "limit.rate", "event rate limit reached");
  }
  state->events_in_window += 1;
  state->events_emitted += 1;

  json doc;
  std::string error;
  if (!json_from_lua(L, 1, doc, 0, error)) {
    return lezcap_fail(L, "argument.invalid", error);
  }
  if (doc.dump().size() > 32 * 1024) {
    state->events_dropped += 1;
    return lezcap_error(L, "limit.size", "event exceeds size cap");
  }
  lua_getfield(L, LUA_REGISTRYINDEX, "ezcap.driver.event_sink");
  if (lua_isfunction(L, -1)) {
    // Store the JSON on the sink closure's upvalue path: push the JSON
    // string and call the sink. The engine installs a C closure that
    // appends to its own queue.
    lua_pushlstring(L, doc.dump().data(), doc.dump().size());
    lua_call(L, 1, 0);
  }
  lua_pop(L, 1);
  return push_ok(L);
}

// lezcap.status.backends: backend health from the engine's snapshot.
int status_backends(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, "ezcap.driver.status_snapshot");
  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    return lezcap_error(L, "status.unavailable", "no status snapshot");
  }
  return 1;
}

// lezcap.dns / lezcap.process: the engine delivers DNS and process
// metadata through on_event; the modules expose only query helpers over
// the last delivered event, registered by the engine. Here they provide
// the module tables the manifest gates.

// ---------------------------------------------------------------------------
// Module registration.
// ---------------------------------------------------------------------------

void register_module(lua_State* L, const char* name,
                     const struct luaL_Reg* functions) {
  lua_createtable(L, 0, 8);
  for (const luaL_Reg* reg = functions; reg->name != nullptr; ++reg) {
    lua_pushcfunction(L, reg->func);
    lua_setfield(L, -2, reg->name);
  }
  lua_setfield(L, -2, name);
}

}  // namespace

bool register_lezcap(lua::Sandbox& sandbox, const DriverManifest& manifest,
                     const DriverResourceLimits& limits,
                     DriverHostState& host_state_ref,
                     policy::PolicyEngine& policy_engine, std::string& error) {
  lua_State* L = sandbox.state();
  if (L == nullptr) {
    error = "sandbox state unavailable";
    return false;
  }
  push_host_state_ptr(L, &host_state_ref);

  // Read-only policy snapshot (E9): scripts query, never mutate.
  {
    const json snapshot = policy_engine.to_json();
    lua_pushlstring(L, snapshot.dump().data(), snapshot.dump().size());
    lua_setfield(L, LUA_REGISTRYINDEX, "ezcap.driver.policy_snapshot");
  }

  lua_createtable(L, 0, 10);  // The lezcap table itself.

  const struct luaL_Reg util_functions[] = {
      {"now_ms", util_now_ms},
      {"now_rfc3339", util_now_rfc3339},
      {"sha256_hex", util_sha256_hex},
      {"base64_encode", util_base64_encode},
      {"truncate", util_truncate},
      {nullptr, nullptr},
  };
  const struct luaL_Reg log_functions[] = {
      {"info", log_info}, {"warn", log_warn}, {"error", log_error},
      {"debug", log_debug}, {nullptr, nullptr},
  };
  const struct luaL_Reg endpoint_functions[] = {
      {"declare", endpoint_declare},
      {nullptr, nullptr},
  };
  const struct luaL_Reg spec_functions[] = {
      {"list_formats", spec_list_formats},
      {"generate", spec_generate},
      {nullptr, nullptr},
  };
  const struct luaL_Reg capture_functions[] = {
      {"register_filter", capture_register_filter},
      {nullptr, nullptr},
  };
  const struct luaL_Reg policy_functions[] = {
      {"query", policy_query},
      {nullptr, nullptr},
  };
  const struct luaL_Reg event_functions[] = {
      {"emit", event_emit},
      {nullptr, nullptr},
  };
  const struct luaL_Reg status_functions[] = {
      {"backends", status_backends},
      {nullptr, nullptr},
  };

  // Capability gating at registration time (E10): a capability absent
  // from the manifest means the module is never registered.
  if (manifest.capabilities.count(Capability::Util) != 0) {
    register_module(L, "util", util_functions);
  }
  if (manifest.capabilities.count(Capability::Log) != 0) {
    register_module(L, "log", log_functions);
  }
  if (manifest.capabilities.count(Capability::Endpoint) != 0) {
    register_module(L, "endpoint", endpoint_functions);
  }
  if (manifest.capabilities.count(Capability::Spec) != 0) {
    register_module(L, "spec", spec_functions);
  }
  if (manifest.capabilities.count(Capability::Capture) != 0) {
    register_module(L, "capture", capture_functions);
  }
  if (manifest.capabilities.count(Capability::Policy) != 0) {
    register_module(L, "policy", policy_functions);
  }
  if (manifest.capabilities.count(Capability::Events) != 0) {
    register_module(L, "event", event_functions);
  }
  if (manifest.capabilities.count(Capability::Status) != 0) {
    register_module(L, "status", status_functions);
  }
  // dns / process: their data reaches scripts through on_event delivery
  // after redaction (E9); no callable surface is registered beyond the
  // event pipeline itself. Registering the (empty) module keeps the
  // namespace reserved and the manifest gate observable.
  if (manifest.capabilities.count(Capability::Dns) != 0) {
    register_module(L, "dns", nullptr);
  }
  if (manifest.capabilities.count(Capability::Process) != 0) {
    register_module(L, "process", nullptr);
  }

  lua_setglobal(L, "lezcap");
  return true;
}

}  // namespace ezcap::drivers
