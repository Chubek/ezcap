// Script integrity pin verification (AGENTS_LUA_DRIVER.md E6 step 2).

#include "drivers/lua/manifests/manifest.hpp"

#include "common/sha256.hpp"

namespace ezcap::drivers {

bool verify_script_hash(const DriverManifest& manifest,
                        const std::string& script_source, std::string& error) {
  if (manifest.script_sha256.empty()) {
    return true;  // No pin configured; discovery allowlist still applies.
  }
  const std::string actual = Sha256::hex_digest(script_source);
  if (actual != manifest.script_sha256) {
    error = "script hash does not match the manifest pin";
    return false;
  }
  return true;
}

}  // namespace ezcap::drivers
