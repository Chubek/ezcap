# Debian packaging notes

ezcap does not ship a full `debian/` directory; these notes are for
anyone building a `.deb` by hand or in a downstream distribution.

## Files installed by `cmake --install`

| Install path | Source |
|---|---|
| `/usr/bin/ezcap-daemon` | daemon executable |
| `/usr/bin/ezcap-native-host` | native messaging bridge |
| `/usr/lib/ezcap/ezcap.bpf.o` | combined eBPF object (when built) |
| `/usr/lib/systemd/system/ezcap.service` | systemd unit |
| `/usr/share/ezcap/manifests/*.json` | configured native-messaging manifests |
| `/usr/share/ezcap/install-linux.sh` | per-user manifest registration |
| `/etc/ezcap/ezcap.conf.json` | sample config (rename/install carefully) |

## Suggested package dependencies

- Depends: `libpcap0.8 (>= 1.9)`, `libbpf1`, `libcap2`, `libseccomp2`,
  `libspdlog1.x`, `libsqlite3-0`, `libc6`
- Recommends: `bpftool` (only needed at *build* time, not runtime)
- The eBPF object is compiled at package build time against the kernel
  BTF of the *build* machine; thanks to CO-RE it runs on other kernels
  with BTF, so `Depends: linux-image-*` is not required.

## Post-install

1. Register the runtime directory:
   `systemd-tmpfiles --create` picks up `ezcap.tmpfiles.conf`.
2. Enable the service if desired: `systemctl enable --now ezcap`.
3. Each user who wants the extension integration runs
   `/usr/share/ezcap/install-linux.sh` (per-user manifest registration;
   no root needed).

## Permissions

- The daemon needs `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_RAW` only
  during capture setup; it drops them itself afterwards (fail closed if
  it cannot).
- The native host needs no special permissions — it runs as the browsing
  user and only talks to the daemon socket via same-uid Unix socket.
- See `packaging/permissions/udev-rules.example` for setups where the
  daemon runs unprivileged and raw capture is granted via udev.
