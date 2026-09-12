# Native Messaging host installation

The Native Messaging host (`ezcap-native-host`) is a small, unprivileged
bridge between the browser extension and the ezcap daemon's Unix-domain
socket. It:

- reads length-prefixed JSON messages from the browser (stdin),
- validates them against `protocol/schema/native_message.schema.json`
  (allowlisted operations only; `shutdown` and any `execute`/`eval`-style
  operation are rejected before forwarding),
- relays them to the daemon at `/run/ezcap/ezcap.sock`,
- relays responses and subscription events back to the browser (stdout).

The host performs no privileged actions and must not be installed
setuid. The daemon authenticates the host over the socket using
`SO_PEERCRED` (same effective UID only).

## Installing

1. Build and install the daemon and host (see `docs/development.md`).
   The manifests are configured during the build with the actual install
   paths and extension IDs.

2. Register the host with your browsers:

   ```sh
   native_host/install/install-linux.sh
   ```

   The script only touches per-user directories under `$HOME` and skips
   browsers that are not installed.

3. Load the extension (Chromium: `chrome://extensions` → Developer mode →
   Load unpacked; Firefox: `about:debugging` → This Firefox → Load
   Temporary Add-on). The extension ID shown after loading must match the
   one configured in the manifests (`EZCAP_EXTENSION_ID_CHROMIUM` /
   `EZCAP_EXTENSION_ID_FIREFOX` CMake options). For development, use an
   unpacked extension and note the generated ID.

## Removing

```sh
native_host/install/uninstall-linux.sh
```

## Manifest fields

| Field | Meaning |
|---|---|
| `name` | Fixed: `com.ezcap.host`. The extension refers to this name. |
| `path` | Absolute path to the installed `ezcap-native-host` binary. |
| `type` | Always `stdio`. |
| `allowed_origins` / `allowed_extensions` | The exact extension IDs permitted to connect. Anything else is rejected by the browser before the host starts. |

For a system-wide install (all users), copy the same manifests to
`/etc/chromium/native-messaging-hosts/`, `/etc/opt/chrome/native-messaging-hosts/`,
or `/usr/lib/mozilla/native-messaging-hosts/` respectively; the manifest
contents are identical.
