/* ezcap connect tracer: emits connection metadata (no payloads) for
 * outbound TCP/UDP connect attempts.
 *
 * Only socket-layer metadata is read: addresses, ports, transport, and the
 * owning task's pid/uid. Packet contents are never accessed.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ebpf_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EZCAP_RINGBUF_PAGES * 4096);
} events SEC(".maps");

static __always_inline void fill_header(struct ezcap_event_header *hdr, __u8 tag)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->version = EZCAP_EVENT_VERSION;
    hdr->tag = tag;
    hdr->pad0 = 0;
    hdr->pid = pid_tgid >> 32;
    hdr->uid = (__u32)uid_gid;
    hdr->timestamp_ns = bpf_ktime_get_ns();
}

static __always_inline void copy_ifname(struct ezcap_connect_event *ev,
                                        const char (*ifname)[16])
{
    /* Interface name is short (<= IFNAMSIZ-1 = 15 chars); a bounded loop
     * the verifier can reason about. */
    for (int i = 0; i < EZCAP_IFNAME_MAX; i++) {
        ev->ifname[i] = (*ifname)[i];
        if (ev->ifname[i] == '\0')
            break;
    }
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(ezcap_tcp_v4_connect, struct sock *sk)
{
    struct ezcap_connect_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_header(&ev->hdr, EZCAP_EVENT_TAG_CONNECT);

    /* Read the socket tuple before the connect mutates it. */
    BPF_CORE_READ_INTO(&ev->remote_addr4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&ev->local_addr4, sk, __sk_common.skc_daddr);
    /* Note: for connect these are swapped in sk; userspace normalizes. */

    __u16 dport = 0, sport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    ev->local_port = sport;
    ev->remote_port = __builtin_bswap16(dport);

    ev->transport = 6 /* IPPROTO_TCP */;
    ev->direction = 1 /* outbound */;
    ev->is_ipv6 = 0;
    ev->pad0 = 0;

    /* Interface name is not yet bound at connect time on some kernels;
     * leave empty and let userspace fill it from socket diagnostics. */
    ev->ifname[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(ezcap_tcp_v6_connect, struct sock *sk)
{
    struct ezcap_connect_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_header(&ev->hdr, EZCAP_EVENT_TAG_CONNECT);

    const struct in6_addr *daddr = NULL, *saddr = NULL;
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    if (daddr)
        __builtin_memcpy(ev->remote_addr6, daddr, 16);
    if (saddr)
        __builtin_memcpy(ev->local_addr6, saddr, 16);

    __u16 dport = 0, sport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    ev->local_port = sport;
    ev->remote_port = __builtin_bswap16(dport);

    ev->transport = 6;
    ev->direction = 1;
    ev->is_ipv6 = 1;
    ev->pad0 = 0;
    ev->ifname[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
