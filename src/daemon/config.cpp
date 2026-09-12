#include "daemon/config.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <set>
#include <sstream>
#include <string_view>

namespace ezcap::daemon {

namespace {

using nlohmann::json;

/// Validate a socket path: absolute, no "..", bounded length.
bool valid_path(std::string_view path, std::string& error) noexcept {
  if (path.empty() || path.front() != '/') {
    error = "path must be absolute";
    return false;
  }
  if (path.find("..") != std::string_view::npos) {
    error = "path must not contain '..'";
    return false;
  }
  if (path.size() > 104) {  // sockaddr_un::sun_path limit.
    error = "path too long for a unix socket";
    return false;
  }
  return true;
}

bool parse_policy(const json& doc, ezcap::Policy& policy, std::string& error) {
  static const std::set<std::string> kKeys{
      "redaction_mode", "strip_query_string", "strip_fragment",
      "sensitive_domains", "capture_interfaces", "pcap_filter"};

  const json redaction = doc.value("redaction", json::object());
  if (!redaction.is_object()) {
    error = "policy.redaction must be an object";
    return false;
  }
  for (const auto& [key, value] : redaction.items()) {
    if (kKeys.count(key) == 0) {
      error = "unknown policy key: " + key;
      return false;
    }
    if (key == "redaction_mode") {
      if (!value.is_string()) {
        error = "policy.redaction.redaction_mode must be a string";
        return false;
      }
      if (!ezcap::Policy::redaction_mode_from_name(value.get<std::string>(),
                                                   policy.redaction_mode)) {
        error = "unknown redaction_mode";
        return false;
      }
    } else if (key == "strip_query_string" || key == "strip_fragment") {
      if (!value.is_boolean()) {
        error = "policy.redaction." + key + " must be a boolean";
        return false;
      }
      (key == "strip_query_string" ? policy.strip_query_string
                                   : policy.strip_fragment) =
          value.get<bool>();
    } else if (key == "sensitive_domains") {
      if (!value.is_array()) {
        error = "policy.redaction.sensitive_domains must be an array";
        return false;
      }
      policy.sensitive_domains.clear();
      for (const auto& domain : value) {
        if (!domain.is_string() || domain.get<std::string>().empty() ||
            domain.get<std::string>().size() > 253) {
          error = "policy.redaction.sensitive_domains entries must be "
                  "non-empty strings (max 253 chars)";
          return false;
        }
        policy.sensitive_domains.push_back(domain.get<std::string>());
      }
    } else if (key == "capture_interfaces") {
      if (!value.is_array()) {
        error = "policy.redaction.capture_interfaces must be an array";
        return false;
      }
      policy.capture_interfaces.clear();
      for (const auto& iface : value) {
        if (!iface.is_string() || iface.get<std::string>().empty() ||
            iface.get<std::string>().size() > 16) {
          error = "policy.redaction.capture_interfaces entries must be "
                  "non-empty interface names (max 16 chars)";
          return false;
        }
        policy.capture_interfaces.push_back(iface.get<std::string>());
      }
    } else {  // pcap_filter
      if (!value.is_string() || value.get<std::string>().size() > 256) {
        error = "policy.redaction.pcap_filter must be a string (max 256 chars)";
        return false;
      }
      policy.pcap_filter = value.get<std::string>();
    }
  }
  return true;
}

bool parse_document(const json& doc, Config& config, std::string& error) {
  static const std::set<std::string> kTopKeys{
      "socket_path",    "log_level",     "log_file",
      "prefer_ebpf",    "pcap_fallback", "interfaces",
      "pcap_filter",    "policy",        "storage",
      "status_interval_ms", "max_events_per_second"};

  if (!doc.is_object()) {
    error = "configuration must be a JSON object";
    return false;
  }
  for (const auto& [key, value] : doc.items()) {
    if (kTopKeys.count(key) == 0) {
      error = "unknown configuration key: " + key;
      return false;
    }
  }

  if (doc.contains("socket_path")) {
    const auto& v = doc["socket_path"];
    if (!v.is_string() || !valid_path(v.get<std::string>(), error)) {
      if (error.empty()) error = "invalid socket_path";
      return false;
    }
    config.socket_path = v.get<std::string>();
  }

  if (doc.contains("log_level")) {
    const auto& v = doc["log_level"];
    if (!v.is_string()) {
      error = "log_level must be a string";
      return false;
    }
    const std::string level = v.get<std::string>();
    if (level != "trace" && level != "debug" && level != "info" &&
        level != "warn" && level != "error" && level != "off") {
      error = "log_level must be one of trace|debug|info|warn|error|off";
      return false;
    }
    config.log_level = level;
  }

  if (doc.contains("log_file")) {
    const auto& v = doc["log_file"];
    if (!v.is_string()) {
      error = "log_file must be a string";
      return false;
    }
    config.log_file = v.get<std::string>();
  }

  if (doc.contains("prefer_ebpf")) {
    if (!doc["prefer_ebpf"].is_boolean()) {
      error = "prefer_ebpf must be a boolean";
      return false;
    }
    config.prefer_ebpf = doc["prefer_ebpf"].get<bool>();
  }

  if (doc.contains("pcap_fallback")) {
    if (!doc["pcap_fallback"].is_boolean()) {
      error = "pcap_fallback must be a boolean";
      return false;
    }
    config.pcap_fallback = doc["pcap_fallback"].get<bool>();
  }

  if (doc.contains("interfaces")) {
    const auto& v = doc["interfaces"];
    if (!v.is_array()) {
      error = "interfaces must be an array";
      return false;
    }
    config.interfaces.clear();
    for (const auto& iface : v) {
      if (!iface.is_string() || iface.get<std::string>().empty() ||
          iface.get<std::string>().size() > 16) {
        error = "interfaces entries must be non-empty names (max 16 chars)";
        return false;
      }
      config.interfaces.push_back(iface.get<std::string>());
    }
  }

  if (doc.contains("pcap_filter")) {
    const auto& v = doc["pcap_filter"];
    if (!v.is_string() || v.get<std::string>().size() > 256) {
      error = "pcap_filter must be a string (max 256 chars)";
      return false;
    }
    config.pcap_filter = v.get<std::string>();
  }

  if (doc.contains("policy")) {
    if (!parse_policy(doc["policy"], config.policy, error)) {
      return false;
    }
  }

  if (doc.contains("storage")) {
    const auto& v = doc["storage"];
    if (!v.is_object()) {
      error = "storage must be an object";
      return false;
    }
    static const std::set<std::string> kStorageKeys{"enabled", "path",
                                                    "retention_seconds"};
    for (const auto& [key, value] : v.items()) {
      if (kStorageKeys.count(key) == 0) {
        error = "unknown storage key: " + key;
        return false;
      }
    }
    if (v.contains("enabled")) {
      if (!v["enabled"].is_boolean()) {
        error = "storage.enabled must be a boolean";
        return false;
      }
      config.storage_enabled = v["enabled"].get<bool>();
    }
    if (v.contains("path")) {
      const auto& p = v["path"];
      if (!p.is_string() || p.get<std::string>().empty()) {
        error = "storage.path must be a non-empty string";
        return false;
      }
      config.storage_path = p.get<std::string>();
    }
    if (v.contains("retention_seconds")) {
      const auto& r = v["retention_seconds"];
      if (!r.is_number_unsigned() || r.get<std::uint64_t>() < 60 ||
          r.get<std::uint64_t>() > 31536000) {
        error = "storage.retention_seconds must be between 60 and 31536000";
        return false;
      }
      config.storage_retention =
          std::chrono::seconds{r.get<std::uint64_t>()};
    }
  }

  if (doc.contains("status_interval_ms")) {
    const auto& v = doc["status_interval_ms"];
    if (!v.is_number_unsigned() || v.get<std::uint64_t>() < 100 ||
        v.get<std::uint64_t>() > 3600000) {
      error = "status_interval_ms must be between 100 and 3600000";
      return false;
    }
    config.status_interval =
        std::chrono::milliseconds{v.get<std::uint64_t>()};
  }

  if (doc.contains("max_events_per_second")) {
    const auto& v = doc["max_events_per_second"];
    if (!v.is_number_unsigned()) {
      error = "max_events_per_second must be a non-negative integer";
      return false;
    }
    config.max_events_per_second = v.get<std::uint64_t>();
  }

  // Cross-field rule: storage enabled requires a usable path.
  if (config.storage_enabled && config.storage_path.empty()) {
    error = "storage.enabled requires storage.path";
    return false;
  }

  return true;
}

}  // namespace

bool Config::load(const std::string& path, Config& out, std::string& error) {
  std::ifstream file{path, std::ios::binary};
  if (!file) {
    error = "cannot open configuration file: " + path;
    return false;
  }

  std::ostringstream buffer;
  buffer << file.rdbuf();
  const std::string text = buffer.str();
  if (text.size() > 256 * 1024) {
    error = "configuration file too large";
    return false;
  }
  return parse(text, out, error);
}

bool Config::parse(const std::string& json_text, Config& out,
                   std::string& error) {
  json doc = json::parse(json_text, nullptr, false);
  if (doc.is_discarded()) {
    error = "configuration is not valid JSON";
    return false;
  }
  return parse_document(doc, out, error);
}

std::string to_json_text(const Config& config) {
  json doc = json::object();
  doc["socket_path"] = config.socket_path;
  doc["log_level"] = config.log_level;
  doc["log_file"] = config.log_file;
  doc["prefer_ebpf"] = config.prefer_ebpf;
  doc["pcap_fallback"] = config.pcap_fallback;
  doc["interfaces"] = config.interfaces;
  doc["pcap_filter"] = config.pcap_filter;
  doc["policy"] = json::object({
      {"redaction_mode",
       ezcap::Policy::redaction_mode_name(config.policy.redaction_mode)},
      {"strip_query_string", config.policy.strip_query_string},
      {"strip_fragment", config.policy.strip_fragment},
      {"sensitive_domains", config.policy.sensitive_domains},
      {"capture_interfaces", config.policy.capture_interfaces},
  });
  doc["storage"] = json::object({
      {"enabled", config.storage_enabled},
      {"path", config.storage_path},
      {"retention_seconds",
       static_cast<std::uint64_t>(config.storage_retention.count())},
  });
  return doc.dump();
}

}  // namespace ezcap::daemon
