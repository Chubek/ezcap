# Privacy model

ezcap's defining constraint: **metadata only, ever**. This document lists
the guarantees, where each is enforced in code, and what a user can
expect in each default.

## Never collected

There is no code path — in any backend, in any mode, under any
configuration — that captures, stores, or transmits:

- packet payloads (application data of any kind)
- HTTP/HTTPS request or response bodies
- cookies, authorization headers, API keys, passwords, form contents
- keystrokes or other user input
- page content

The capture layer's `PacketMetadata` type (`src/capture/packet_parser.*`)
has no field that could carry payload bytes; the eBPF ring-buffer structs
(`ebpf/include/ezcap_events.h`) likewise carry only bounded address,
port, pid, and name fields. These are structural facts, not policies a
misconfiguration could relax.

## Redaction

All sanitization happens in one place: `src/policy/redactor.*`. Every
consumer — IPC serialization, SQLite storage, logging, extension UI —
calls the redactor; none of them re-implements sanitization.

Default redaction:

- URL query strings stripped (`?...` removed) — reversible per-domain
  only via explicit policy
- URL fragments stripped
- hostnames lowercased and normalized
- sensitive domains (configurable list) excluded from capture entirely —
  not merely redacted after the fact

## Attribution honesty

Correlations between network events and browser activity are estimates.
Every event carries `confidence` in [0, 1] and the UI always renders its
band:

| Band | Range | Meaning |
|---|---|---|
| weak | 0.00–0.39 | time/proximity only |
| probable | 0.40–0.69 | time + destination match |
| strong | 0.70–0.89 | process + timing + destination |
| direct | 0.90–1.00 | reported by the browser itself |

pcap-derived attribution is hard-capped at **0.69** by
`src/attribution/confidence.cpp`; the cap is not configurable. An
uncertain association can never be presented as a fact.

## Storage

- SQLite storage is **disabled by default**.
- When enabled, only already-redacted events are written, with bounded
  retention (pruned periodically by the daemon).
- The schema cannot hold payload data (no such column exists).
- All statements are parameterized; no string-built SQL anywhere.

## Transport

- Everything is local: a Unix-domain socket (same effective-uid peers
  only) between native host and daemon, and stdio between browser and
  native host. Nothing leaves the machine.
- Outgoing queues are bounded with drop accounting — if a subscriber is
  slow, events are dropped and counted, never buffered unboundedly.

## Forbidden by design

The following are not "disabled by default" — they are impossible:

- TLS decryption / MITM of browser traffic
- traffic modification or interception
- code injection into pages or the browser
- bypassing browser security features
- the native host executing anything (`execute`, `run`, `eval` message
  kinds are rejected outright in `native_host/src/main.cpp`)
- the daemon acting as a general-purpose sniffer (the pcap filter
  vocabulary is validated and intentionally tiny)

## Verification

- `tests/unit/test_redactor.cpp` — stripping, sensitive-domain
  exclusion, malformed URL handling.
- `tests/unit/test_policy.cpp` — policy validation, rejection of
  attempts to weaken guarantees.
- `tests/unit/test_correlator.cpp` — confidence band assignment and the
  pcap cap.
- The extension re-validates every event it receives
  (`extension/shared/src/event-model.ts`), including a forbidden-field
  check — defense in depth against a compromised host.
