#!/usr/bin/env bash
# Remove the ezcap Native Messaging host manifests for the current user.

set -euo pipefail

host_name="com.ezcap.host"

dirs=(
  "${HOME}/.config/chromium/NativeMessagingHosts"
  "${HOME}/.config/google-chrome/NativeMessagingHosts"
  "${HOME}/.config/microsoft-edge/NativeMessagingHosts"
  "${HOME}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "${HOME}/.mozilla/native-messaging-hosts"
)

removed=0
for dir in "${dirs[@]}"; do
  if [[ -f "${dir}/${host_name}.json" ]]; then
    rm -f "${dir}/${host_name}.json"
    echo "removed ${dir}/${host_name}.json"
    removed=1
  fi
done

if [[ "${removed}" -eq 0 ]]; then
  echo "nothing to remove"
fi
