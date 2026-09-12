// Integration test for the native host's message framing: Native
// Messaging length-prefixed round-trips through a pipepair, plus the
// framing edge cases (zero length, oversize, truncated prefix, invalid
// UTF-8). Framing is the browser-facing attack surface; these tests pin
// it down without launching the host process itself.

#include "message_reader.hpp"
#include "message_writer.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using ezcap::native_host::MessageReader;
using ezcap::native_host::MessageWriter;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                     \
  do {                                                                  \
    if (!(cond)) {                                                      \
      std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++g_failures;                                                     \
    }                                                                   \
  } while (0)

void put_le32(std::string& s, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    s.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  }
}

}  // namespace

int main() {
  // --- Round-trip through a real pipe ------------------------------------------
  {
    int fds[2];
    CHECK(pipe(fds) == 0);

    const std::string payload = R"({"kind":"request","payload":{"operation":"hello"}})";
    CHECK(MessageWriter::write(fds[1], payload));

    std::string out;
    std::string err;
    CHECK(MessageReader::read(fds[0], out, err));
    CHECK(out == payload);

    ::close(fds[0]);
    ::close(fds[1]);
  }

  // --- Reader rejects malformed framing (in-process, on a pipe) ----------------
  {
    // Zero length.
    {
      int fds[2];
      CHECK(pipe(fds) == 0);
      std::string zero;
      put_le32(zero, 0);
      CHECK(::write(fds[1], zero.data(), zero.size()) >= 0);
      std::string out, err;
      CHECK(!MessageReader::read(fds[0], out, err));
      ::close(fds[0]);
      ::close(fds[1]);
    }
    // Oversize.
    {
      int fds[2];
      CHECK(pipe(fds) == 0);
      std::string big;
      put_le32(big, MessageReader::kMaxMessageBytes + 1);
      CHECK(::write(fds[1], big.data(), big.size()) >= 0);
      std::string out, err;
      CHECK(!MessageReader::read(fds[0], out, err));
      ::close(fds[0]);
      ::close(fds[1]);
    }
    // Truncated body.
    {
      int fds[2];
      CHECK(pipe(fds) == 0);
      std::string partial;
      put_le32(partial, 100);
      partial.append("{\"a\":");  // fewer than 100 bytes, then EOF
      CHECK(::write(fds[1], partial.data(), partial.size()) >= 0);
      ::close(fds[1]);
      std::string out, err;
      CHECK(!MessageReader::read(fds[0], out, err));
      ::close(fds[0]);
    }
    // Invalid UTF-8 in the body.
    {
      int fds[2];
      CHECK(pipe(fds) == 0);
      std::string bad = "{\"\xFF\xFE\":1}";
      std::string framed;
      put_le32(framed, static_cast<std::uint32_t>(bad.size()));
      framed += bad;
      CHECK(::write(fds[1], framed.data(), framed.size()) >= 0);
      ::close(fds[1]);
      std::string out, err;
      CHECK(!MessageReader::read(fds[0], out, err));
      ::close(fds[0]);
    }
  }

  // --- Writer rejects oversize payloads ------------------------------------------
  {
    int fds[2];
    CHECK(pipe(fds) == 0);
    const std::string big(1024 * 1024 + 1, 'x');  // over the 1 MiB ceiling
    CHECK(!MessageWriter::write(fds[1], big));
    CHECK(!MessageWriter::write(fds[1], ""));  // empty payload rejected
    ::close(fds[0]);
    ::close(fds[1]);
  }

  // --- EOF is reported as an error string, not a crash ----------------------------
  {
    int fds[2];
    CHECK(pipe(fds) == 0);
    ::close(fds[1]);
    std::string out, err;
    CHECK(!MessageReader::read(fds[0], out, err));
    CHECK(err == "eof");
    ::close(fds[0]);
  }

  // --- Many sequential frames over one pipe ----------------------------------------
  {
    int fds[2];
    CHECK(pipe(fds) == 0);
    constexpr int kCount = 200;
    for (int i = 0; i < kCount; ++i) {
      CHECK(MessageWriter::write(fds[1], std::string(R"({"seq":)") +
                                             std::to_string(i) + "}"));
    }
    std::string out, err;
    for (int i = 0; i < kCount; ++i) {
      CHECK(MessageReader::read(fds[0], out, err));
      CHECK(out == std::string(R"({"seq":)") + std::to_string(i) + "}");
    }
    ::close(fds[0]);
    ::close(fds[1]);
  }

  if (g_failures > 0) {
    std::fprintf(stderr, "native_host: %d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("native_host: all tests passed");
  return 0;
}
