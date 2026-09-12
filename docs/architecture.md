# Architecture

ezcap is a pipeline: capture → normalize → attribute → enforce policy →
deliver. Every stage is local, every stage is bounded, and the privacy
policy sits between the raw world and everything a user (or a log file)
can see.

```
                    kernel
      ┌───────────┬──────────────┐
      │  eBPF     │  libpcap     │     capture layer
      └─────┬─────┴──────┬───────┘
            │ ring buf   │ headers only
            ▼            ▼
      ┌──────────────────────────┐
      │ event normalizer         │     one internal event type
      └────────────┬─────────────┘
                   ▼
      ┌──────────────────────────┐    navigation observations
      │ correlator / attribution │◄───────────────────────────┐
      └────────────┬─────────────┘                            │
                   ▼                                          │
      ┌──────────────────────────┐     ┌──────────────────────┴─────┐
      │ policy engine + redactor │     │ extension (reports context)│
      └────────────┬─────────────┘     └────────────────────────────┘
                   │ redacted events only
        ┌──────────┴──────────┐
        ▼                     ▼
┌──────────────┐      ┌──────────────┐
│ IPC server   │      │ SQLite store │    (optional, off by default)
│ (unix socket)│      └──────────────┘
└──────┬───────┘
       ▼
 native host ── stdio native messaging ──► extension popup
```

## Components

### Capture layer (`src/capture/`)

Two backends behind one interface:

- `ebpf/` — loads the compiled `ezcap.bpf.o`, polls the ring buffer, and
  translates versioned compact structs into internal events. Structs are
  defined in `ebpf/include/ezcap_events.h`; the version field lets the
  user-space side reject (not misread) objects built for a different
  layout.
- `pcap/` — live capture with a validated filter. `pcap_filter.cpp`
  parses the configured filter string and rejects anything outside the
  permitted TCP/UDP/ICMP/DNS header vocabulary before libpcap ever sees
  it.
- `packet_parser.cpp` — decodes the link/IP/transport header chain into a
  `PacketMetadata` (addresses, ports, protocol, sizes, timestamps). It
  stops at the header boundary; there is no code path that returns
  payload bytes.
- `event_normalizer.cpp` — merges backend output into the single
  normalized event shape (`include/ezcap/event.hpp`).

### Attribution (`src/attribution/`)

The correlator joins network events against browser navigation
observations reported by the extension. Every association carries a
confidence score; `confidence.cpp` defines the bands (weak / probable /
strong / direct) and the hard cap for pcap-derived attribution (0.69).
Nothing downstream can display an association without its band.

### Policy (`src/policy/`)

`policy_engine.cpp` holds the runtime policy (redaction mode, query
string stripping, sensitive domains, per-interface capture). The engine
is the only component allowed to modify policy, and only through
validated `set_policy` requests. `redactor.cpp` is the single place URLs
and strings are sanitized before they leave the process — IPC, storage,
and logging all call it; none of them re-implements it.

### IPC (`src/ipc/`)

`unix_socket_server.cpp` listens on a Unix-domain socket (default
`/run/ezcap/ezcap.sock`, same effective-uid peer check via
`SO_PEERCRED`). Requests are newline-delimited JSON, capped at 64 KiB;
event frames capped at 256 KiB. Outgoing queues are bounded per client
with drop accounting — a slow subscriber can never stall capture.
`ipc_codec.cpp` encodes/decodes and produces structured errors; invalid
frames are answered with an error frame, never a crash.

### Storage (`src/storage/`)

SQLite, disabled by default. Forward-only migrations with
`PRAGMA user_version` (`migrations.cpp`); all writes are parameterized
and pass through a bounded queue drained by a writer thread, so storage
can never back-pressure capture. The schema has no column that could
hold a payload — that is enforced structurally, not by convention.
Retention is bounded and pruned periodically.

### Daemon (`src/daemon/`)

`daemon.cpp` composes the above: builds the pipeline, selects the
backend, owns the run loop, and answers the six IPC operations (`hello`,
`get_status`, `subscribe`, `unsubscribe`, `set_policy`, `get_policy`).
`shutdown` is rejected over IPC — only the service manager or a signal
stops the daemon. `config.cpp` parses and strictly validates the JSON
config (unknown keys rejected, paths absolute, all lengths bounded).
`main.cpp` wires signals, drops privileges, and installs the seccomp
sandbox — both fail closed.

### Native host (`native_host/`)

A thin, deliberately dumb bridge. It speaks native messaging on stdio
(length-prefixed frames, ≤ 1 MiB, full UTF-8 validation), checks every
field against an allowlist, refuses any message that carries or requests
sensitive data (`payload`, `body`, `cookies`, `authorization`,
`password`, `api_key`) or forbidden operations (`execute`, `run`, `eval`,
`command`, `shell` — and `shutdown`), and forwards the rest to the
daemon socket. It holds no policy of its own: the daemon remains the
single enforcement point.

### Extension (`extension/`)

Cross-browser TypeScript (shared core, per-browser manifests for
chromium and firefox MV3). The background script owns the native-messaging
connection (with reconnect + backoff), validates every incoming event
against `shared/src/event-model.ts` (forbidden-field check included),
stores a bounded ring in `storage.local`, and reports navigation context
on `tabs.onUpdated`. Content scripts are intentionally inert — the
extension never reads page content.

### Protocol (`protocol/`)

The source of truth for wire formats: JSON Schemas (draft-07) for the
event, daemon request/response, and native message envelopes, plus
examples for each. C++ and TypeScript implementations are expected to
match these schemas; the examples double as fixtures.

## Data flow invariants

1. No payload bytes exist anywhere past `packet_parser` — by type, not
   by discipline.
2. Nothing crosses the IPC boundary without passing the redactor.
3. Every attribution carries its confidence band out to the wire.
4. Every queue is bounded with drop accounting.
5. Every input — config file, IPC frame, native message — is validated
   before use; malformed input produces a structured error, never a
   crash.
