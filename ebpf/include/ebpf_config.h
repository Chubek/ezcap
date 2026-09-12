/* Common configuration for ezcap eBPF programs.
 *
 * This header is shared between the kernel-side programs and the userspace
 * loader. It must stay C-compatible (no C++ constructs) and ABI-stable.
 * Generated headers such as vmlinux.h are produced by scripts and must not
 * be hand-edited.
 */
#ifndef EZCAP_EBPF_CONFIG_H
#define EZCAP_EBPF_CONFIG_H

/* Event schema version shared with userspace (include/ezcap/version.hpp). */
#define EZCAP_EVENT_VERSION 1

/* Versioned event type tags. */
#define EZCAP_EVENT_TAG_CONNECT 1
#define EZCAP_EVENT_TAG_DNS 2
#define EZCAP_EVENT_TAG_SOCKET_STATE 3

/* Bounded sizes. The verifier requires fixed bounds; never enlarge these
 * without bumping EZCAP_EVENT_VERSION. */
#define EZCAP_IFNAME_MAX 16
#define EZCAP_DNS_NAME_MAX 253

/* Ring buffer size in pages (power of two). */
#define EZCAP_RINGBUF_PAGES 256

/* DNS name capture: only the first question name of the first DNS message
 * per packet is captured, capped at EZCAP_DNS_NAME_MAX bytes. Payload bytes
 * beyond the question name are never read. */

#endif /* EZCAP_EBPF_CONFIG_H */
