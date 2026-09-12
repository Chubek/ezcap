# eBPF and libpcap capture backends

The daemon supports two capture backends. They differ in what metadata
they can see and therefore in how confidently a network event can be
attributed to a browser tab — the eBPF backend is preferred whenever the
toolchain is available, with pcap as the universal fallback.

## Backend selection

At startup the daemon tries backends in order:

1. **eBPF** — only when the build produced `ezcap.bpf.o` (see below).
   The daemon checks `EZCAP_EBPF_OBJECT_PATH` first, then a few known
   install/build locations (`../lib`, `../lib64`, `../ebpf`) before giving
   up. This keeps users safe from arbitrary-path loading while staying
   resilient to package/install layout differences. Privileges permitting, this
   is the richest source.
2. **libpcap** — a live capture on the preferred interface, using a compiled
   BPF filter that admits only TCP/UDP/ICMP/DNS packet
   headers. Never a payload source.

If eBPF is unavailable the daemon starts in *degraded mode* on pcap. The pcap
interface selection order is:

1. `EZCAP_INTERFACE` environment variable (if set and valid).
2. The first configured interface in `interfaces` (if present).
3. Auto-detected default interface.
4. `"any"` fallback.

If no interface can be opened, the daemon fails closed and reports startup
failure.

`EZCAP_INTERFACE` can be set in the service environment (for example via a
systemd drop-in with `Environment=EZCAP_INTERFACE=<iface>`) or in the shell
before launching `ezcap-daemon`.

## eBPF backend

The eBPF backend attaches small, purpose-specific programs:

| Program | Hook | Purpose |
|---|---|---|
| `connect` | kprobe on `tcp_v4_connect` / `tcp_v6_connect` | outgoing connection attempts (address, port, pid, comm) |
| `dns` | socket filter on AF_PACKET | DNS query/response *headers* only — domain names, never the full message body |
| `socket_state` | `tcp`/`tcp_destroy_sock` tracepoints or equivalent | connection close/failure events |

Events cross the kernel boundary through a **BPF ring buffer** as
compact, versioned C structs (`ebpf/include/ezcap_events.h`) — never JSON,
never payload bytes, and always with bounded string fields.

**Build requirements** (all three, or the build honestly disables the
backend):

- `clang` with the BPF target
- `bpftool` (to generate `vmlinux.h` from the kernel's BTF)
- kernel BTF at `/sys/kernel/btf/vmlinux`

The generated `vmlinux.h` makes the programs CO-RE (compile once, run on
patched kernels) rather than tied to one kernel build.

## libpcap backend

The pcap backend opens a live handle with an explicit filter string that
is **validated** before being handed to libpcap (only TCP/UDP/ICMP/DNS
header clauses are permitted — arbitrary filter expressions are rejected,
so a misconfiguration can never turn ezcap into a general sniffer).

Attribution from pcap alone is inherently weaker: pcap sees packets, not
processes, so events captured this way are correlated by time and
destination only, and their confidence is capped at **probable** (0.69)
by the confidence module. The daemon enforces this cap; it can never be
raised by configuration.

## What neither backend can do

- Read TLS-encrypted content (we do not decrypt, ever).
- See the URL or path of an HTTPS request (that lives inside TLS).
- Attribute a connection to a specific tab without the browser
  extension's navigation context (pcap alone cannot; eBPF can identify
  the process, the extension refines it).
