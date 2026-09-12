#pragma once

#include <ezcap/event.hpp>
#include <ezcap/policy.hpp>

#include "policy/redactor.hpp"

#include <mutex>
#include <nlohmann/json.hpp>

namespace ezcap::policy {

/// Applies the active policy to events before they reach IPC, storage, or
/// logs. Redaction happens here and nowhere else.
class PolicyEngine {
 public:
  PolicyEngine();

  /// Apply policy to an event in place. Sensitive fields are redacted or
  /// dropped; events violating the metadata-only invariant are dropped
  /// entirely (they cannot occur by construction, but the engine verifies
  /// anyway).
  PolicyDecision apply(ezcap::Event& event);

  /// Current policy snapshot.
  [[nodiscard]] ezcap::Policy policy() const;

  /// Replace the policy from a JSON document (set_policy operation).
  /// Returns false with `error` when the document is malformed or attempts
  /// to disable metadata-only mode. Redaction defaults may only become
  /// stricter without a schema version bump; loosening beyond
  /// query-string-removal defaults is rejected.
  bool update_from_json(const nlohmann::json& doc, std::string& error);

  /// Serialize the current policy to JSON.
  [[nodiscard]] nlohmann::json to_json() const;

 private:
  mutable std::mutex mutex_;
  ezcap::Policy policy_;
};

}  // namespace ezcap::policy
