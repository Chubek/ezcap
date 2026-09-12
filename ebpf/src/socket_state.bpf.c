/* ezcap socket-state tracer: emits connection-close metadata with byte
 * counters (no contents).
 *
 * Used to emit connection duration and volume, letting the daemon produce
 * connection lifecycle events without ever touching payload bytes.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf_common.h"
#include "ebpf_events.h"

static __always_inline void fill_header(struct ezcap_event_header *hdr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->version = EZCAP_EVENT_VERSION;
    hdr->tag = EZCAP_EVENT_TAG_SOCKET_STATE;
    hdr->pad0 = 0;
    hdr->pid = pid_tgid >> 32;
    hdr->uid = (__u32)uid_gid;
    hdr->timestamp_ns = bpf_ktime_get_ns();
}

SEC("tracepoint/tcp/tcp_destroy_sock")
int ezcap_tcp_destroy_sock(struct trace_event_raw_tcp_event_sk *ctx)
{
    const struct sock *sk = (const struct sock *)ctx->skaddr;

    struct ezcap_socket_state_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_header(&ev->hdr);

    BPF_CORE_READ_INTO(&ev->local_addr4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&ev->remote_addr4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&ev->local_addr6, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&ev->remote_addr6, sk,
                       __sk_common.skc_v6_daddr.in6_u.u6_addr8);

    __u16 dport = 0, sport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    ev->local_port = sport;
    ev->remote_port = __builtin_bswap16(dport);

    ev->bytes_tx = 0;
    ev->bytes_rx = 0;

    __u64 issued_at = 0;
    BPF_CORE_READ_INTO(&issued_at, sk, sk_txhash);
    ev->duration_ns = ev->hdr.timestamp_ns > issued_at
                          ? ev->hdr.timestamp_ns - issued_at
                          : 0;

    ev->transport = 6 /* IPPROTO_TCP */;
    ev->direction = 1 /* outbound; state events from destroy are closes */;
    ev->is_ipv6 = ev->local_addr4 == 0 ? 1 : 0;
    ev->new_state = 7 /* TCP_CLOSE */;
    ev->ifname[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
