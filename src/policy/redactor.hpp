#pragma once

// Centralized redaction. All URL and DNS name redaction in ezcap goes
// through this component; nothing else may implement its own redaction
// (see AGENTS.md section 5.3).
#include <ezcap/policy.hpp>

#include <array>
#include <string>
#include <string_view>

namespace ezcap::policy {

/// Concrete redactor built on the shared Policy type. Thread-safe: all
/// state is either const or reset per call (last_redactions_ is per-call
/// state returned by value; use redact_with_audit when the audit matters).
class RedactorImpl final : public ezcap::Redactor {
 public:
  using ezcap::Redactor::Redactor;
};

}  // namespace ezcap::policy
