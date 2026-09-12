#include "time.hpp"

#include <sys/time.h>

#include <cstdio>
#include <cstring>

namespace ezcap::time_util {

std::chrono::system_clock::time_point now() noexcept {
  return std::chrono::system_clock::now();
}

std::string to_rfc3339(std::chrono::system_clock::time_point tp) noexcept {
  using namespace std::chrono;
  const auto secs = time_point_cast<seconds>(tp);
  const auto ms = duration_cast<milliseconds>(tp - secs).count();

  std::time_t tt = system_clock::to_time_t(tp);
  std::tm tm_utc{};
  gmtime_r(&tt, &tm_utc);

  char buf[40];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec,
                static_cast<int>(ms));
  return buf;
}

namespace {

bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

int parse2(const char* p) noexcept {
  return (p[0] - '0') * 10 + (p[1] - '0');
}

}  // namespace

std::chrono::system_clock::time_point from_rfc3339(
    const std::string& text) noexcept {
  // Strict "YYYY-MM-DDTHH:MM:SS(.mmm)?Z" parsing; anything else fails.
  if (text.size() < 20 || !text.empty() && text.back() != 'Z') {
    if (text.size() < 20) return {};
  }
  const char* p = text.c_str();
  if (!(is_digit(p[0]) && is_digit(p[1]) && is_digit(p[2]) && is_digit(p[3]) &&
        p[4] == '-' && is_digit(p[5]) && is_digit(p[6]) && p[7] == '-' &&
        is_digit(p[8]) && is_digit(p[9]) && (p[10] == 'T' || p[10] == 't') &&
        is_digit(p[11]) && is_digit(p[12]) && p[13] == ':' && is_digit(p[14]) &&
        is_digit(p[15]) && p[16] == ':' && is_digit(p[17]) && is_digit(p[18]))) {
    return {};
  }

  std::tm tm_utc{};
  tm_utc.tm_year = (p[0] - '0') * 1000 + (p[1] - '0') * 100 +
                   (p[2] - '0') * 10 + (p[3] - '0') - 1900;
  tm_utc.tm_mon = parse2(p + 5) - 1;
  tm_utc.tm_mday = parse2(p + 8);
  tm_utc.tm_hour = parse2(p + 11);
  tm_utc.tm_min = parse2(p + 14);
  tm_utc.tm_sec = parse2(p + 17);
  tm_utc.tm_isdst = 0;

  std::time_t tt = timegm(&tm_utc);
  if (tt == static_cast<std::time_t>(-1)) return {};

  int ms = 0;
  if (p[19] == '.' && text.size() >= 24) {
    ms = (p[20] - '0') * 100 + (p[21] - '0') * 10 + (p[22] - '0');
  }

  using namespace std::chrono;
  return system_clock::time_point{seconds{tt} + milliseconds{ms}};
}

std::chrono::system_clock::time_point from_ktime_ns(
    std::uint64_t ktime_ns, std::chrono::system_clock::time_point boot_walltime) noexcept {
  using namespace std::chrono;
  return boot_walltime + nanoseconds{ktime_ns};
}

}  // namespace ezcap::time_util
