/* Compatibility shims for compiling ezcap eBPF programs with a vmlinux.h
 * world (where libc headers are unavailable). Included via -include so
 * each program gets it before any system header could leak in. */
#ifndef EZCAP_EBPF_COMPAT_H
#define EZCAP_EBPF_COMPAT_H

#endif /* EZCAP_EBPF_COMPAT_H */
