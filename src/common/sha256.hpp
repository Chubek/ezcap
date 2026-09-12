#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ezcap {

/// Minimal SHA-256 (FIPS 180-4). Used for script integrity pins and the
/// lezcap.util hashing surface. No external dependency: the implementation
/// is small, fixed, and easy to audit, and it never handles secret data —
/// only public script text and bounded strings supplied by driver scripts.
class Sha256 {
 public:
  Sha256() { reset(); }

  /// Process a byte range. May be called repeatedly to hash a stream.
  void update(const void* data, std::size_t size);

  /// Convenience overload for string data.
  void update(std::string_view text) { update(text.data(), text.size()); }

  /// Finish and write the 32-byte digest. The object is reset afterwards
  /// and may be reused.
  void final(std::uint8_t out[32]);

  /// One-shot digest.
  static void digest(std::string_view text, std::uint8_t out[32]);

  /// One-shot lowercase hex digest (64 characters).
  [[nodiscard]] static std::string hex_digest(std::string_view text);

 private:
  void reset();
  void process_block(const std::uint8_t* block);

  std::uint32_t state_[8];
  std::uint64_t total_bits_{0};
  std::uint8_t buffer_[64]{};
  std::size_t buffer_used_{0};
};

}  // namespace ezcap
