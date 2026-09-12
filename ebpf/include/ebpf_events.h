/* Compact, versioned event structures shared between ezcap eBPF programs
 * and the userspace loader.
 *
 * Rules enforced by review:
 *  - explicitly sized fields only (no `int`, no pointers),
 *  - fixed-size arrays with explicit length fields,
 *  - no packet payload bytes, only metadata,
 *  - changing a struct requires bumping EZCAP_EVENT_VERSION.
 */
#ifndef EZCAP_EBPF_EVENTS_H
#define EZCAP_EBPF_EVENTS_H

#include "ebpf_config.h"

#include <linux/types.h>

/* Common event header. `tag` selects the payload union interpretation. */
struct ezcap_event_header {
    __u8 version;   /* EZCAP_EVENT_VERSION */
    __u8 tag;       /* EZCAP_EVENT_TAG_* */
    __u16 pad0;     /* reserved, zero */
    __u32 pid;      /* originating process id (init pid ns) */
    __u32 uid;      /* owning user id */
    __u64 timestamp_ns; /* ktime_get_ns() */
};

/* Outbound/inbound connection attempt observed at the socket layer. */
struct ezcap_connect_event {
    struct ezcap_event_header hdr;
    __u32 local_addr4;   /* network byte order; 0 when v6 */
    __u32 remote_addr4;  /* network byte order; 0 when v6 */
    __u8 local_addr6[16];
    __u8 remote_addr6[16];
    __u16 local_port;    /* host byte order */
    __u16 remote_port;   /* host byte order */
    __u8 transport;      /* IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP */
    __u8 direction;      /* 0 unknown, 1 outbound, 2 inbound */
    __u8 is_ipv6;
    __u8 pad0;
    char ifname[EZCAP_IFNAME_MAX]; /* NUL-terminated */
};

/* DNS query metadata. Only the question name is captured; response bytes
 * and any payload content are never read. */
struct ezcap_dns_event {
    struct ezcap_event_header hdr;
    __u32 local_addr4;
    __u8 local_addr6[16];
    __u16 local_port;
    __u16 pad0;
    __u8 is_ipv6;
    __u8 transport;
    __u16 query_len;             /* bytes used in query_name */
    char query_name[EZCAP_DNS_NAME_MAX]; /* NUL-terminated, bounded */
    char ifname[EZCAP_IFNAME_MAX];
};

/* Socket close / state-change metadata. */
struct ezcap_socket_state_event {
    struct ezcap_event_header hdr;
    __u32 local_addr4;
    __u32 remote_addr4;
    __u8 local_addr6[16];
    __u8 remote_addr6[16];
    __u16 local_port;
    __u16 remote_port;
    __u8 transport;
    __u8 direction;
    __u8 is_ipv6;
    __u8 new_state;   /* TCP state enum value, e.g. 7 = CLOSE */
    __u64 duration_ns;
    __u64 bytes_tx;   /* counters only, no contents */
    __u64 bytes_rx;
    char ifname[EZCAP_IFNAME_MAX];
};

#endif /* EZCAP_EBPF_EVENTS_H */
