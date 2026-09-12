#include "pcap_filter.hpp"

#include <cctype>
#include <set>

namespace ezcap::capture {

namespace {

/// Allowed tokens of the restricted filter grammar. Anything else —
/// function calls, arithmetic, length operators on payloads — is rejected.
const std::set<std::string>& allowed_tokens() {
  static const std::set<std::string> tokens = {
      "ip",       "ip6",     "tcp",     "udp",     "icmp",    "host",
      "net",      "port",    "ports",   "src",     "dst",     "and",
      "or",       "not",     "ether",   "arp",     "rarp",    "ipproto",
      "broadcast", "less",   "greater", "len"};
  return tokens;
}

bool is_word_char(char c) noexcept {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' ||
         c == ':' || c == '/';
}

bool is_number(const std::string& s) noexcept {
  if (s.empty()) return false;
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

/// A literal (IPv4/IPv6 address or number) token.
bool looks_like_literal(const std::string& s) noexcept {
  if (is_number(s)) return true;
  int colons = 0, dots = 0;
  for (char c : s) {
    if (c == ':') ++colons;
    else if (c == '.') ++dots;
    else if (!std::isxdigit(static_cast<unsigned char>(c)) &&
             c != '/') return false;
  }
  return dots > 0 || colons > 0;
}

}  // namespace

bool PcapFilterValidator::validate(const std::string& filter,
                                   std::string& error) {
  if (filter.empty()) {
    error = "empty filter";
    return false;
  }
  if (filter.size() > 256) {
    error = "filter too long";
    return false;
  }

  // Tokenize on whitespace and parentheses; reject any other punctuation
  // so no BPF extension syntax can sneak in.
  std::string token;
  auto flush = [&](bool paren, char which) -> bool {
    if (!token.empty()) {
      const bool known = allowed_tokens().count(token) > 0 ||
                         looks_like_literal(token);
      if (!known) {
        error = "disallowed token in filter";
        return false;
      }
      token.clear();
    }
    if (paren) {
      error = std::string("unexpected character in filter: ") + which;
      return false;
    }
    return true;
  };

  for (char c : filter) {
    if (is_word_char(c)) {
      token.push_back(c);
    } else if (c == ' ' || c == '\t' || c == '\n') {
      if (!flush(false, ' ')) return false;
    } else if (c == '(' || c == ')') {
      if (!flush(false, c)) return false;
    } else {
      if (!flush(true, c)) return false;
    }
  }
  return flush(false, ' ');
}

}  // namespace ezcap::capture
