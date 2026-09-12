# ezcap — local browser network observability (metadata-only)

ezcap observes network activity that originates in a web browser and
correlates it with what the browser was doing at the time — **without ever
capturing sensitive payload data**. It is a local, Linux-first system made
of four components:

```
┌────────────┐  native msg  ┌──────────────┐  unix socket  ┌────────────┐
│  browser   │◄────────────►│ native host  │◄─────────────►│   daemon   │
│ extension  │  (stdio)     │ (per-browser)│  (same euid)  │  (capture) │
└────────────┘              └──────────────┘               └─────┬──────┘
                                                                  │ eBPF / pcap
                                                                  ▼
                                                          kernel packet metadata
```

- **daemon** (`ezcap-daemon`) — captures connection metadata via eBPF (with
  a libpcap fallback), correlates it with browser navigation, applies the
  privacy policy, and serves events over a Unix-domain socket.
- **native host** (`ezcap-native-host`) — bridges the browser's native
  messaging protocol (length-prefixed stdio) to the daemon socket. It
  forwards only an allowlist of operations; `shutdown` is never forwardable.
- **browser extension** (chromium + firefox) — reports navigation context,
  validates every incoming event against the shared model, and keeps a
  bounded local ring of recent events.
- **protocol/** — JSON Schemas + examples that define the event, request,
  and native-message wire formats shared by all components.
- **Lua drivers** -- We embed Lua and offer a Lua runtime module that are
  used to "drive" the capture.

## Hard privacy guarantees

- Metadata only: no packet payloads, no HTTP bodies, no cookies, no
  authorization headers, no form data.
- Redaction is centralized (`src/policy/redactor.*`) and applied before
  anything is sent over IPC, stored, logged, or shown in the UI.
- URL query strings are stripped by default; sensitive domains can be
  excluded entirely.
- Attribution is always labelled with an explicit confidence band
  (weak / probable / strong / direct). pcap-only correlation can never
  exceed "probable" — the daemon enforces this.
- Storage (SQLite) is **disabled by default**; when enabled it keeps only
  redacted events with bounded retention.
- No TLS decryption, no keystroke recording, no code injection, no traffic
  modification — ever.

## Building

First, you'll need to clone submodules:
```sh
git submodule update --init --recursive
```

Requirements: CMake ≥ 3.24, a C++20 compiler, and the system libraries
`libpcap`, `libbpf`, `libcap`, `libseccomp`, `spdlog`, `sqlite3`
(nlohmann/json is bundled as a submodule). The eBPF programs additionally
need `clang` with the BPF target, `bpftool`, and kernel BTF
(`/sys/kernel/btf/vmlinux`); when those are missing the build simply skips
the eBPF backend and the daemon uses pcap.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

See `docs/development.md` for the full guide, `docs/architecture.md` for
component design, `docs/privacy.md` and `docs/security-model.md` for the
guarantees, and `docs/capture-backends.md` for how eBPF and pcap capture
differ.

## Running

1. Install: `cmake --install build --prefix /usr/local`
2. Register the native host with your browser(s):
   `/usr/local/share/ezcap/install-linux.sh`
3. Load the extension from `extension/dist/chromium` (or `firefox`) via
   your browser's "load unpacked" developer option.
4. Start the daemon: `systemctl --user start ezcap` (unit provided in
   `packaging/systemd/ezcap.service`), or run `ezcap-daemon` directly with
   `--config`.

### Docker

Build:

```sh
docker build -t ezcap:local .
```

Run the daemon in a container (pcap-only default build):

```sh
docker run --rm --user 1001:1001 --cap-add CAP_NET_RAW \
  --mount type=tmpfs,destination=/run/ezcap \
  --mount type=volume,src=ezcap-data,target=/var/lib/ezcap \
  ezcap:local
```

To force a pcap-only container image, disable eBPF explicitly:

```sh
docker build --build-arg BUILD_WITH_EBPF=ON -t ezcap:local-ebpf .
```

> eBPF still requires kernel + container capability support; if unavailable,
> the daemon falls back to `pcap`.

## Status

Work in progress. The eBPF backend requires `bpftool`, `clang` with the
BPF target, and kernel BTF; on hosts without them the build skips it and
the daemon runs on the pcap backend. See `docs/capture-backends.md`.
