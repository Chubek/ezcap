# Security model

ezcap runs with elevated privileges only where the kernel requires them
(eBPF / packet sockets) and sheds everything else immediately. Every
trust boundary validates strictly and fails closed.

## Trust boundaries

```
browser ──(stdio, native msg)── native host ──(unix socket)── daemon ── kernel
```

1. **Browser → native host.** Untrusted. Frames are length-prefixed,
   ≤ 1 MiB, fully UTF-8 validated. Only the six forwardable operations
   are accepted; messages carrying sensitive keys (`payload`, `body`,
   `cookies`, `authorization`, `password`, `api_key`) or forbidden verbs
   (`execute`, `run`, `eval`, `command`, `shell`) are dropped. The host
   never interprets message content beyond the allowlist.
2. **Native host → daemon.** Same user. Unix-domain socket only;
   `SO_PEERCRED` requires the peer's effective uid to match. Requests
   are newline-delimited JSON ≤ 64 KiB, validated field-by-field;
   responses to malformed input are structured error frames, never
   crashes.
3. **Daemon → kernel.** The only privileged surface: eBPF load and/or a
   packet socket, opened during startup, then dropped (below).

## Privilege dropping

`src/security/privilege_drop.cpp`: after capture setup, the daemon drops
all capabilities (libcap) and supplementary groups. If dropping fails,
the daemon exits — it never continues with residual privilege
(fail closed).

## Seccomp sandbox

`src/security/sandbox.cpp`: a default-deny syscall filter is installed
after setup, allowing only the syscalls the steady-state loop needs
(socket I/O, file I/O for the optional store, logging, timing). Policy
violations kill the process rather than degrade it.

## IPC operation allowlist

| Operation | Allowed over IPC? |
|---|---|
| `hello`, `get_status`, `get_policy` | yes |
| `subscribe`, `unsubscribe` | yes |
| `set_policy` | yes (validated; attempts to weaken privacy guarantees are rejected) |
| `shutdown` | **no** — rejected with `operation_not_allowed`; only a signal or the service manager stops the daemon |

There is no operation that executes code, reads files, or returns raw
packet data — by allowlist, not by blacklist.

## Backpressure and resource limits

- Per-client outgoing queues are bounded; overflow drops and *counts*
  events (`dropped_events` is reported in status).
- Request frames ≤ 64 KiB, event frames ≤ 256 KiB, native messages
  ≤ 1 MiB — all hard-capped in the codecs.
- The storage writer queue is bounded (capture can never stall on disk).
- Config parsing caps file size, path lengths, list sizes, and rejects
  unknown keys outright.

## eBPF safety

- Programs are minimal and purpose-specific; they read only the fields
  the event structs carry and never inspect packet payload bytes.
- Events cross via a BPF ring buffer as versioned compact structs; a
  version mismatch is rejected by user space, never misparsed.
- The object is loaded from a fixed, compiled-in path by default and then
  verified against known adjacent install/build locations (`lib`, `lib64`,
  `ebpf`) to tolerate layout differences. User input cannot override the
  lookup path.

## Build-time honesty

The build detects the eBPF toolchain (clang BPF target, bpftool, kernel
BTF). If any piece is missing, the eBPF backend is simply not built and
the daemon reports pcap fallback — it never claims support it does not
have, and never stubs out the checks.
