/* Compatibility shims for compiling ezcap eBPF programs with a vmlinux.h
 * world (where libc headers are unavailable). Included via -include so
 * each program gets it before any system header could leak in. */
#ifndef EZCAP_EBPF_COMPAT_H
#define EZCAP_EBPF_COMPAT_H

/* vmlinux.h defines these; when it does not (older generation), keep the
 * programs compilable with explicit sizes. */
#ifndef NULL
#define NULL ((void *)0)
#endif

#endif /* EZCAP_EBPF_COMPAT_H */
