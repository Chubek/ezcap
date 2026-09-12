// SHA-256 (FIPS 180-4), self-contained implementation.
//
// Kept small and readable on purpose: it backs script integrity pins and
// the lezcap.util hashing surface, both of which operate on public, bounded
// data. Verified against the FIPS test vectors in tests/unit/test_specgen
// and the sandbox tests.

#include "common/sha256.hpp"

#include <algorithm>
#include <cstring>

namespace ezcap {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t rotate_right(std::uint32_t value, unsigned bits) {
  return (value >> bits) | (value << (32u - bits));
}

}  // namespace

void Sha256::reset() {
  state_[0] = 0x6a09e667u;
  state_[1] = 0xbb67ae85u;
  state_[2] = 0x3c6ef372u;
  state_[3] = 0xa54ff53au;
  state_[4] = 0x510e527fu;
  state_[5] = 0x9b05688cu;
  state_[6] = 0x1f83d9abu;
  state_[7] = 0x5be0cd19u;
  total_bits_ = 0;
  buffer_used_ = 0;
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::process_block(const std::uint8_t* block) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotate_right(w[i - 15], 7) ^
                             rotate_right(w[i - 15], 18) ^
                             (w[i - 15] >> 3);
    const std::uint32_t s1 = rotate_right(w[i - 2], 17) ^
                             rotate_right(w[i - 2], 19) ^
                             (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 =
        rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t temp1 = h + s1 + ch + kRoundConstants[i] + w[i];
    const std::uint32_t s0 =
        rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_bits_ += static_cast<std::uint64_t>(size) * 8u;

  // Fill partial buffer first.
  if (buffer_used_ > 0) {
    const std::size_t need = 64 - buffer_used_;
    const std::size_t take = std::min(need, size);
    std::memcpy(buffer_ + buffer_used_, bytes, take);
    buffer_used_ += take;
    bytes += take;
    size -= take;
    if (buffer_used_ == 64) {
      process_block(buffer_);
      buffer_used_ = 0;
    }
  }

  // Whole blocks straight from the input.
  while (size >= 64) {
    process_block(bytes);
    bytes += 64;
    size -= 64;
  }

  // Tail into the buffer.
  if (size > 0) {
    std::memcpy(buffer_, bytes, size);
    buffer_used_ = size;
  }
}

void Sha256::final(std::uint8_t out[32]) {
  const std::uint64_t bits = total_bits_;

  // Padding: 0x80, zeros, then the bit count as a 64-bit big-endian value.
  std::uint8_t pad = 0x80;
  update(&pad, 1);
  const std::uint8_t zero = 0;
  while (buffer_used_ != 56) {
    update(&zero, 1);
  }
  // update() advanced total_bits_, but the length field must reflect the
  // original message; append the count manually.
  std::uint8_t length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>(bits >> (56 - i * 8));
  }
  total_bits_ = bits;  // Not used again before reset().
  update(length_bytes, 8);

  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24);
    out[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
    out[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
    out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
  }
  reset();
}

void Sha256::digest(std::string_view text, std::uint8_t out[32]) {
  Sha256 hash;
  hash.update(text);
  hash.final(out);
}

std::string Sha256::hex_digest(std::string_view text) {
  std::uint8_t raw[32];
  digest(text, raw);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(64);
  for (const std::uint8_t byte : raw) {
    hex += kHex[byte >> 4];
    hex += kHex[byte & 0x0f];
  }
  return hex;
}

}  // namespace ezcap
