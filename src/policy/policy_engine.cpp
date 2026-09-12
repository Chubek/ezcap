#include "policy_engine.hpp"

#include <algorithm>
#include <string>

namespace ezcap::policy {

using nlohmann::json;

PolicyEngine::PolicyEngine() : policy_{} {
  // Defaults per AGENTS.md 5.1: metadata-only, redaction on, no storage.
  policy_.redaction_mode = RedactionMode::QueryStringRemoval;
  policy_.strip_query_string = true;
  policy_.strip_fragment = true;
  policy_.persistence_enabled = false;
}

ezcap::Policy PolicyEngine::policy() const {
  std::lock_guard<std::mutex> lock{mutex_};
  return policy_;
}

PolicyDecision PolicyEngine::apply(ezcap::Event& event) {
  // The metadata-only invariant is structural, but verify defensively.
  if (!event.privacy.metadata_only) {
    return PolicyDecision::Drop;
  }

  std::lock_guard<std::mutex> lock{mutex_};
  Redactor redactor{policy_};

  bool redacted = false;

  if (event.network) {
    if (!event.network->dns_query_name.empty()) {
      auto name = redactor.redact_dns_name(event.network->dns_query_name);
      if (name.empty()) {
        // Sensitive domain: drop the DNS name entirely.
        event.network->dns_query_name.clear();
        redacted = true;
      } else if (name != event.network->dns_query_name) {
        event.network->dns_query_name = std::move(name);
        redacted = true;
      }
    }
  }

  if (event.browser && !event.browser->url.empty()) {
    auto url = redactor.redact_url(event.browser->url);
    if (url.empty()) {
      // Sensitive domain: the whole browser association is dropped so the
      // event does not leak that a sensitive site was visited via tab info.
      event.browser.reset();
      redacted = true;
    } else if (url != event.browser->url) {
      event.browser->url = std::move(url);
      redacted = true;
    }
  }

  event.privacy.redacted = redacted;
  const auto kinds = redactor.last_redactions();
  for (std::size_t i = 0; i < kinds.size(); ++i) {
    event.privacy.redactions[i] = event.privacy.redactions[i] || kinds[i];
  }

  return redacted ? PolicyDecision::Redact : PolicyDecision::Allow;
}

bool PolicyEngine::update_from_json(const json& doc, std::string& error) {
  if (!doc.is_object()) {
    error = "policy document must be an object";
    return false;
  }

  ezcap::Policy next;
  {
    std::lock_guard<std::mutex> lock{mutex_};
    next = policy_;
  }

  if (doc.contains("metadata_only")) {
    const auto& flag = doc.at("metadata_only");
    if (!flag.is_boolean() || !flag.get<bool>()) {
      error = "metadata-only mode cannot be disabled";
      return false;
    }
  }

  if (doc.contains("redaction")) {
    const auto& red = doc.at("redaction");
    if (!red.is_object()) {
      error = "redaction must be an object";
      return false;
    }
    if (red.contains("mode")) {
      const auto& mode = red.at("mode");
      if (!mode.is_string()) {
        error = "redaction.mode must be a string";
        return false;
      }
      if (!ezcap::Policy::redaction_mode_from_name(mode.get<std::string>(),
                                                   next.redaction_mode)) {
        error = "unknown redaction mode";
        return false;
      }
    }
    if (red.contains("sensitive_domains")) {
      const auto& domains = red.at("sensitive_domains");
      if (!domains.is_array() || domains.size() > 256) {
        error = "sensitive_domains must be an array of at most 256 entries";
        return false;
      }
      next.sensitive_domains.clear();
      for (const auto& d : domains) {
        if (!d.is_string() || d.get<std::string>().size() > 253) {
          error = "invalid sensitive domain entry";
          return false;
        }
        next.sensitive_domains.push_back(d.get<std::string>());
      }
    }
  }

  if (doc.contains("persistence")) {
    const auto& persist = doc.at("persistence");
    if (!persist.is_object()) {
      error = "persistence must be an object";
      return false;
    }
    if (persist.contains("enabled")) {
      const auto& flag = persist.at("enabled");
      if (!flag.is_boolean()) {
        error = "persistence.enabled must be a boolean";
        return false;
      }
      next.persistence_enabled = flag.get<bool>();
    }
    if (persist.contains("retention_seconds")) {
      const auto& seconds = persist.at("retention_seconds");
      if (!seconds.is_number_integer()) {
        error = "retention_seconds must be an integer";
        return false;
      }
      const auto value = seconds.get<std::int64_t>();
      if (value < 60 || value > 31536000) {
        error = "retention_seconds out of range";
        return false;
      }
      next.retention = std::chrono::seconds{value};
    }
  }

  std::lock_guard<std::mutex> lock{mutex_};
  policy_ = next;
  return true;
}

nlohmann::json PolicyEngine::to_json() const {
  std::lock_guard<std::mutex> lock{mutex_};

  json redaction;
  redaction["mode"] =
      ezcap::Policy::redaction_mode_name(policy_.redaction_mode);
  redaction["sensitive_domains"] = policy_.sensitive_domains;

  json persistence;
  persistence["enabled"] = policy_.persistence_enabled;
  persistence["retention_seconds"] =
      policy_.retention.count();

  json doc;
  doc["metadata_only"] = true;  // constant: cannot be disabled
  doc["redaction"] = std::move(redaction);
  doc["persistence"] = std::move(persistence);
  return doc;
}

}  // namespace ezcap::policy
