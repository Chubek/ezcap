/* ezcap DNS tracer: emits DNS query metadata (question name only).
 *
 * The program parses only the DNS header and the first question name of
 * UDP datagrams on port 53. It never reads or stores any other part of the
 * packet; no response records, no EDNS payloads, no contents.
 */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ebpf_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EZCAP_RINGBUF_PAGES * 4096);
} events SEC(".maps");

/* DNS header (RFC 1035 section 4.1.1), 12 bytes. */
struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

static __always_inline void fill_header(struct ezcap_event_header *hdr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->version = EZCAP_EVENT_VERSION;
    hdr->tag = EZCAP_EVENT_TAG_DNS;
    hdr->pad0 = 0;
    hdr->pid = pid_tgid >> 32;
    hdr->uid = (__u32)uid_gid;
    hdr->timestamp_ns = bpf_ktime_get_ns();
}

static __always_inline int copy_qname(const __u8 *payload, __u32 payload_len,
                                      char *out)
{
    /* Decode the first question name only. Bounded by both the on-the-wire
     * length and EZCAP_DNS_NAME_MAX; the loop bound is a constant the
     * verifier can check. */
    __u32 i = 0;         /* position in payload */
    __u32 o = 0;         /* position in out */
    __u32 hops = 0;      /* label count guard */

    while (i < payload_len && hops < 128) {
        __u8 label_len = payload[i];
        if (label_len == 0) {
            break;
        }
        /* Compression pointers and malformed lengths: stop. */
        if ((label_len & 0xC0) != 0 || label_len > 63)
            return -1;
        i += 1;
        if (i + label_len > payload_len)
            return -1;
        if (o > 0) {
            if (o >= EZCAP_DNS_NAME_MAX - 1)
                return -1;
            out[o++] = '.';
        }
        for (__u32 j = 0; j < label_len; j++) {
            if (o >= EZCAP_DNS_NAME_MAX - 1)
                return -1;
            if (i + j >= payload_len)
                return -1;
            out[o++] = payload[i + j];
        }
        i += label_len;
        hops++;
    }
    out[o] = '\0';
    return 0;
}

SEC("socket")
int ezcap_dns_trace(struct __sk_buff *skb)
{
    /* Fast pre-checks before touching any data: UDP to/from port 53. */
    if (skb->protocol != bpf_htons(ETH_P_IP) &&
        skb->protocol != bpf_htons(ETH_P_IPV6))
        return 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* We need at least the IP header to inspect the protocol field. Read
     * through the packet only; never modify it. */
    if (data + sizeof(struct iphdr) > data_end)
        return 0;

    struct iphdr iph;
    __builtin_memcpy(&iph, data, sizeof(iph));

    if (iph.protocol != IPPROTO_UDP)
        return 0;

    __u32 ihl = (__u32)(iph.ihl) * 4;
    if (ihl < 20 || data + ihl + sizeof(struct udphdr) > data_end)
        return 0;

    struct udphdr udph;
    __builtin_memcpy(&udph, (char *)data + ihl, sizeof(udph));

    __u16 sport = bpf_ntohs(udph.source);
    __u16 dport = bpf_ntohs(udph.dest);
    if (sport != 53 && dport != 53)
        return 0;

    __u32 udp_off = ihl + sizeof(struct udphdr);
    if (data + udp_off + sizeof(struct dns_header) > data_end)
        return 0;

    struct dns_header dnsh;
    __builtin_memcpy(&dnsh, (char *)data + udp_off, sizeof(dnsh));
    if (bpf_ntohs(dnsh.qdcount) < 1)
        return 0;

    struct ezcap_dns_event *ev =
        bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_header(&ev->hdr);

    ev->local_addr4 = iph.saddr;
    ev->local_port = sport;
    ev->pad0 = 0;
    ev->is_ipv6 = 0;
    ev->transport = 17 /* IPPROTO_UDP */;
    ev->query_len = 0;
    ev->query_name[0] = '\0';
    ev->ifname[0] = '\0';

    __u32 payload_len = (__u32)bpf_ntohs(udph.len);
    if (payload_len < sizeof(struct udphdr) + sizeof(struct dns_header))
        payload_len = skb->len - udp_off;
    else
        payload_len = payload_len - sizeof(struct udphdr) -
                      sizeof(struct dns_header);
    if (payload_len > 512)
        payload_len = 512;

    /* Copy only the question name; anything else is off-limits. */
    const __u8 *qname = (const __u8 *)data + udp_off + sizeof(struct dns_header);
    if (copy_qname(qname, payload_len, ev->query_name) == 0)
        ev->query_len = (__u16)(__builtin_strlen(ev->query_name) + 1);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
