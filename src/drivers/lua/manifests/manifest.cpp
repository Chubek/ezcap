// Driver manifest parsing and validation (AGENTS_LUA_DRIVER.md E6 step 2).

#include "drivers/lua/manifests/manifest.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>

namespace ezcap::drivers {
namespace {

bool valid_name(const std::string& name) {
  if (name.empty() || name.size() > 64) {
    return false;
  }
  return std::all_of(name.begin(), name.end(), [](unsigned char c) {
    return std::isalnum(c) != 0 || c == '-';
  });
}

bool valid_version(const std::string& version) {
  // x[.y[.z]] with numeric components; rejects suffixes like "1.0-beta".
  std::int32_t components = 0;
  std::string current;
  for (const char c : version) {
    if (c == '.') {
      if (current.empty() || components >= 3) {
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

bool valid_sha256_hex(const std::string& hash) {
  if (hash.size() != 64) {
    return false;
  }
  return std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
    return std::isdigit(c) != 0 || (c >= 'a' && c <= 'f');
  });
}

bool bounded_string(const nlohmann::json& parent, const char* key,
                    std::string& out, std::string& error) {
  if (!parent.contains(key)) {
    return true;  // Optional field.
  }
  const auto& value = parent.at(key);
  if (!value.is_string()) {
    error = std::string(key) + " must be a string";
    return false;
  }
  out = value.get<std::string>();
  if (out.size() > kMaxManifestFieldLength) {
    error = std::string(key) + " exceeds maximum length";
    return false;
  }
  return true;
}

}  // namespace

bool capability_from_name(const std::string& name, Capability& out) {
  if (name == "events") {
    out = Capability::Events;
  } else if (name == "capture") {
    out = Capability::Capture;
  } else if (name == "dns") {
    out = Capability::Dns;
  } else if (name == "process") {
    out = Capability::Process;
  } else if (name == "policy") {
    out = Capability::Policy;
  } else if (name == "endpoint") {
    out = Capability::Endpoint;
  } else if (name == "spec") {
    out = Capability::Spec;
  } else if (name == "log") {
    out = Capability::Log;
  } else if (name == "util") {
    out = Capability::Util;
  } else if (name == "status") {
    out = Capability::Status;
  } else {
    return false;
  }
  return true;
}

const char* capability_name(Capability capability) noexcept {
  switch (capability) {
    case Capability::Events:
      return "events";
    case Capability::Capture:
      return "capture";
    case Capability::Dns:
      return "dns";
    case Capability::Process:
      return "process";
    case Capability::Policy:
      return "policy";
    case Capability::Endpoint:
      return "endpoint";
    case Capability::Spec:
      return "spec";
    case Capability::Log:
      return "log";
    case Capability::Util:
      return "util";
    case Capability::Status:
      return "status";
  }
  return "unknown";
}

bool DriverManifest::parse(const std::string& json_text, DriverManifest& out,
                           std::string& error) {
  nlohmann::json doc = nlohmann::json::parse(json_text, nullptr, false);
  if (doc.is_discarded()) {
    error = "manifest is not valid JSON";
    return false;
  }
  if (!doc.is_object()) {
    error = "manifest must be a JSON object";
    return false;
  }

  // Required scalar fields.
  if (!doc.contains("name") || !doc.at("name").is_string()) {
    error = "manifest.name is required";
    return false;
  }
  out.name = doc.at("name").get<std::string>();
  if (!valid_name(out.name)) {
    error = "manifest.name must match [a-zA-Z0-9-]{1,64}";
    return false;
  }

  if (!doc.contains("version") || !doc.at("version").is_string()) {
    error = "manifest.version is required";
    return false;
  }
  out.version = doc.at("version").get<std::string>();
  if (!valid_version(out.version)) {
    error = "manifest.version must be numeric x.y[.z]";
    return false;
  }

  if (!doc.contains("script") || !doc.at("script").is_string()) {
    error = "manifest.script is required";
    return false;
  }
  out.script_path = doc.at("script").get<std::string>();
  if (out.script_path.empty() || out.script_path.size() > 4096) {
    error = "manifest.script must be a non-empty path";
    return false;
  }

  if (!bounded_string(doc, "description", out.description, error)) {
    return false;
  }
  if (!bounded_string(doc, "script_sha256", out.script_sha256, error)) {
    return false;
  }
  if (!out.script_sha256.empty() && !valid_sha256_hex(out.script_sha256)) {
    error = "manifest.script_sha256 must be 64 lowercase hex characters";
    return false;
  }

  // Capabilities: every entry must be a known name.
  if (doc.contains("capabilities")) {
    const auto& caps = doc.at("capabilities");
    if (!caps.is_array()) {
      error = "manifest.capabilities must be an array";
      return false;
    }
    if (caps.size() > 16) {
      error = "manifest.capabilities has too many entries";
      return false;
    }
    for (const auto& entry : caps) {
      if (!entry.is_string()) {
        error = "manifest.capabilities entries must be strings";
        return false;
      }
      Capability capability{};
      if (!capability_from_name(entry.get<std::string>(), capability)) {
        error = "manifest.capabilities contains unknown capability '" +
                entry.get<std::string>() + "'";
        return false;
      }
      out.capabilities.insert(capability);
    }
  }

  // Event subscriptions.
  if (doc.contains("event_types")) {
    const auto& types = doc.at("event_types");
    if (!types.is_array()) {
      error = "manifest.event_types must be an array";
      return false;
    }
    if (types.size() > kMaxManifestEventTypes) {
      error = "manifest.event_types exceeds the subscription limit";
      return false;
    }
    for (const auto& entry : types) {
      if (!entry.is_string()) {
        error = "manifest.event_types entries must be strings";
        return false;
      }
      const std::string type_name = entry.get<std::string>();
      if (type_name.size() > 32) {
        error = "manifest.event_types entry exceeds maximum length";
        return false;
      }
      out.event_types.push_back(type_name);
    }
  }

  // Declared limits (may only lower the engine defaults, never raise them).
  if (doc.contains("max_endpoints")) {
    const auto& value = doc.at("max_endpoints");
    if (!value.is_number_unsigned() || value.get<std::uint64_t>() > 64) {
      error = "manifest.max_endpoints must be a number in [0, 64]";
      return false;
    }
    out.max_endpoints = static_cast<std::uint32_t>(value.get<std::uint64_t>());
  }
  if (doc.contains("max_subscriptions")) {
    const auto& value = doc.at("max_subscriptions");
    if (!value.is_number_unsigned() || value.get<std::uint64_t>() > 64) {
      error = "manifest.max_subscriptions must be a number in [0, 64]";
      return false;
    }
    out.max_subscriptions =
        static_cast<std::uint32_t>(value.get<std::uint64_t>());
  }

  return true;
}

bool path_within_allowlist(const std::string& canonical_path,
                           const std::vector<std::string>& dirs) {
  for (const auto& dir : dirs) {
    if (canonical_path.rfind(dir, 0) == 0) {
      const std::size_t dir_len = dir.size();
      // Boundary must be at a path separator to prevent /allowed-evil
      // matching /allowed.
      if (canonical_path.size() == dir_len ||
          (dir_len > 0 && dir.back() == '/') ||
          canonical_path[dir_len] == '/') {
        return true;
      }
    }
  }
  return false;
}

}  // namespace ezcap::drivers
