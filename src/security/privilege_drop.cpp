#include "privilege_drop.hpp"

#include "common/logging.hpp"

#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <linux/securebits.h>

#include <cerrno>
#include <cstring>

namespace ezcap::security {

namespace {

/// Apply a capability set as both permitted and effective, then drop the
/// ambient set entirely.
bool apply_caps(cap_t caps, std::string& error) noexcept {
  // Lock securebits BEFORE dropping capabilities: PR_SET_SECUREBITS requires
  // CAP_SETPCAP, which cap_set_proc() below removes. EPERM means the caller
  // never had CAP_SETPCAP (e.g. a restricted systemd bounding set); the
  // unit's NoNewPrivileges= provides the same no-setuid-regain guarantee,
  // so continue instead of failing. EINVAL is for kernels without securebits.
  if (::prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) != 0 &&
      errno != EINVAL && errno != EPERM) {
    error = "prctl securebits failed";
    return false;
  }
  if (::cap_set_proc(caps) != 0) {
    error = "cap_set_proc failed";
    return false;
  }
  // Clear the securebits-adjacent ambient set so exec'd children (none in
  // practice) cannot inherit capabilities.
  if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
      errno != EINVAL) {
    // EINVAL on kernels without ambient caps: acceptable.
    error = "prctl ambient clear failed";
    return false;
  }
  return true;
}

}  // namespace

bool PrivilegeDropper::drop_to(const std::vector<std::string>& keep,
                               std::string& error) noexcept {
  cap_t caps = ::cap_get_proc();
  if (caps == nullptr) {
    error = "cap_get_proc failed";
    return false;
  }

  cap_t target = ::cap_init();
  if (target == nullptr) {
    ::cap_free(caps);
    error = "cap_init failed";
    return false;
  }

  bool ok = true;
  for (const auto& name : keep) {
    cap_value_t value{};
    if (::cap_from_name(name.c_str(), &value) != 0) {
      error = "unknown capability name";
      ok = false;
      break;
    }
    if (::cap_set_flag(target, CAP_PERMITTED, 1, &value, CAP_SET) != 0 ||
        ::cap_set_flag(target, CAP_EFFECTIVE, 1, &value, CAP_SET) != 0) {
      error = "cap_set_flag failed";
      ok = false;
      break;
    }
  }

  if (ok) {
    ok = apply_caps(target, error);
  }

  ::cap_free(target);
  ::cap_free(caps);

  if (ok) {
    EZCAP_LOG_INFO("privileges dropped");
  } else {
    EZCAP_LOG_ERROR("privilege drop failed");
  }
  return ok;
}

bool PrivilegeDropper::drop_all(std::string& error) noexcept {
  return drop_to({}, error);
}

bool PrivilegeDropper::has_capabilities() noexcept {
  cap_t caps = ::cap_get_proc();
  if (caps == nullptr) {
    return false;
  }
  ssize_t effective = -1;
  const char* text = ::cap_to_text(caps, &effective);
  const bool none = text != nullptr && std::strcmp(text, "=") == 0;
  ::cap_free(caps);
  ::cap_free(const_cast<char*>(text));
  return !none;
}

}  // namespace ezcap::security
