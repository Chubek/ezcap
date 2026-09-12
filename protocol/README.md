# ezcap protocol

This directory defines the shared protocol used by every ezcap component:

- `schema/event.schema.json` — normalized event model, used by all events
  crossing a component boundary (capture backend → daemon, daemon → native
  host, native host → extension).
- `schema/daemon_request.schema.json` — request model for the daemon's
  Unix-domain socket IPC.
- `schema/native_message.schema.json` — envelope for messages exchanged
  between the browser extension and the Native Messaging host.
- `examples/` — sample documents.

## Transport summary

```text
Browser extension ⟷ Native Messaging host   Native Messaging framing
                                               (4-byte LE length prefix, ≤ 1 MiB)
Native Messaging host ⟷ daemon               Unix-domain socket, newline-delimited
                                               JSON frames (≤ 64 KiB each)
Capture backend ⟶ daemon                     in-process normalized events
```

## Event model

Every event carries:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | Currently `1`. Breaking changes require an increment. |
| `event_id` | string | UUID or equivalent, ≤ 64 chars. |
| `event_type` | enum | `connection`, `dns`, `navigation`, `process`, `status`, `error`. |
| `timestamp` | string | RFC 3339, UTC. |
| `source` | enum | `ebpf`, `pcap`, or `browser`. |
| `confidence` | number | Attribution confidence, 0.0–1.0. |
| `correlation_id` | string? | Links related events. |
| `process` | object? | PID, process name, optional UID. |
| `network` | object? | Addresses, ports, transport, direction, DNS name, interface, backend. |
| `browser` | object? | Tab/window correlation, redacted URL. |
| `privacy` | object? | Redaction annotations. |
| `error` | object? | Structured error for `error` events. |
| `status` | object? | Backend state for `status` events. |

### Attribution confidence

The `confidence` score must be interpreted as:

| Range | Meaning |
|---|---|
| 0.00–0.39 | weak |
| 0.40–0.69 | probable |
| 0.70–0.89 | strong |
| 0.90–1.00 | direct or highly reliable |

Consumers (including the extension UI) must not describe weak or probable
associations as definite. Events with `source: "pcap"` never receive tab
attribution with confidence above the *probable* band, because `libpcap`
cannot identify browser tabs.

### Forbidden fields

The event schema explicitly rejects any event containing `payload`, `body`,
`cookies`, `authorization`, `password`, or `api_key` fields. There is no
schema version in which these are legal; payload capture is a non-goal of
the project.

## Daemon IPC

Requests are newline-delimited JSON frames on a Unix-domain socket, each
limited to 64 KiB. Supported operations:

```text
hello        handshake; returns daemon status and protocol version
get_status   current daemon and backend status
subscribe    subscribe to event types; returns a subscription id
unsubscribe  remove a subscription
set_policy   update redaction/persistence policy (metadata_only cannot be disabled)
get_policy   read the current policy
shutdown     stop the daemon; requires additional authorization (peer must
             be the service owner — the native host never forwards this)
```

There is deliberately no generic `execute`, `run`, or `eval` operation.

Responses use the shape:

```json
{"request_id": "...", "ok": true, "result": {}}
{"request_id": "...", "ok": false, "error": {"code": "...", "message": "..."}}
```

Error codes are stable strings such as `message_too_large`,
`invalid_json`, `unsupported_version`, `unknown_operation`,
`operation_not_allowed`, and `daemon_busy`.

## Native Messaging

The native host validates the 4-byte little-endian length prefix, rejects
messages over 1 MiB, parses and validates JSON against
`native_message.schema.json`, and forwards only allowlisted `request`
messages to the daemon. Errors are returned as structured
`error` messages with stable codes; the host never crashes on malformed
input and never executes commands.

## Versioning rules

- `schema_version`/`protocol_version` `1` is the only supported version today.
- Adding an optional field is a minor change: consumers must ignore unknown
  fields (the extension does this via its runtime validators).
- Removing or reinterpreting a field, or adding a required field, requires a
  version increment. Unknown-field behavior is therefore "ignore" on the
  consumer side and "reject with `schema_violation`" on the producer side
  when emitting.
- Bump the version in all three schemas together; they are versioned as a set.
