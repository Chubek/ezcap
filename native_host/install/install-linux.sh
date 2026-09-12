#!/usr/bin/env bash
# Install the ezcap Native Messaging host manifests for the current user.
#
# Registers the host binary with Chromium-family and Firefox browsers by
# copying manifests into the per-browser native messaging directories.
# The host binary itself is expected to already be installed (system
# package or cmake --install); this script only registers it.
#
# Usage:
#   install-linux.sh [--manifest-dir DIR]
#
#   --manifest-dir DIR  directory containing the configured manifests
#                       (default: <script dir>/../manifests)

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
manifest_dir="${script_dir}/../manifests"

if [[ "${1:-}" == "--manifest-dir" ]]; then
  manifest_dir="$2"
fi

host_name="com.ezcap.host"
manifests=(
  "chromium:${manifest_dir}/${host_name}.chrome.json"
  "firefox:${manifest_dir}/${host_name}.firefox.json"
)

fail() {
  echo "install-linux.sh: $*" >&2
  exit 1
}

[[ -f "${manifests[0]#*:}" ]] || fail "manifest not found: ${manifests[0]#*:} (configure the project first)"

# Per-user native messaging directories (Linux).
chromium_dir="${HOME}/.config/chromium/NativeMessagingHosts"
chrome_dir="${HOME}/.config/google-chrome/NativeMessagingHosts"
edge_dir="${HOME}/.config/microsoft-edge/NativeMessagingHosts"
brave_dir="${HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
firefox_dir="${HOME}/.mozilla/native-messaging-hosts"

install_manifest() {
  local src="$1" dest_dir="$2"
  mkdir -p "${dest_dir}"
  install -m 0644 "${src}" "${dest_dir}/${host_name}.json"
  echo "installed ${dest_dir}/${host_name}.json"
}

# Chromium family.
for dir in "${chromium_dir}" "${chrome_dir}" "${edge_dir}" "${brave_dir}"; do
  if [[ -d "$(dirname "${dir}")" ]]; then
    install_manifest "${manifests[0]#*:}" "${dir}"
  fi
done

# Firefox (registers when the profile directory exists).
if [[ -d "${HOME}/.mozilla" ]]; then
  install_manifest "${manifests[1]#*:}" "${firefox_dir}"
else
  echo "note: no Firefox profile found; skipping Firefox registration"
fi

echo
echo "ezcap native host registered."
echo "Make sure the ezcap daemon is running and the extension is loaded."
