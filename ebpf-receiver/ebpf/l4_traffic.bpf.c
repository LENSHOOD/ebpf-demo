#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define MAX_PACK_SIZE 512

struct l4_event_t {
    __u64 timestamp_ns;
    __u32 protocol;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 data_len;
    char data[MAX_PACK_SIZE];
} __attribute__((packed));

struct {
    	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} l4_events_rb SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int net_filter(struct __sk_buff *skb) {
    struct l4_event_t *event;

    // only monitor IP packet
    __u16 l3_proto;
    bpf_skb_load_bytes(skb, 12, &l3_proto, 2);
	if (__bpf_ntohs(l3_proto) != ETH_P_IP)
	{
	    return 0;
	}

    // ignore IP fragment
    __u8 ethhdr_len = ETH_HLEN;
	if (ip_is_fragment(skb, ethhdr_len))
	{
		return 0;
	}

    // decode IP packet
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, ethhdr_len, &ip, sizeof(ip)) < 0)
    {
        return 0;
    }

//    event.src_ip = ip.saddr;
//    event.dst_ip = ip.daddr;
//    event.protocol = ip.protocol;
    __u8 iphdr_len = ip.ihl * 4;
    __u16 ip_pkt_tlen = __bpf_ntohs(ip.tot_len);

    // decode L4 packet
    __u16 l4_offset = ethhdr_len + iphdr_len;
    __u16 src_port, dst_port, l4_payload_len, payload_offset;
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0) {
                return 0;
            }

            src_port = tcp.source;
            dst_port = tcp.dest;

            __u8 tcphdr_len = tcp.doff * 4;
            l4_payload_len = ip_pkt_tlen - iphdr_len - tcphdr_len;
            payload_offset = l4_offset + tcphdr_len;
//            if (bpf_skb_load_bytes(skb, l4_offset + tcphdr_len, &event.data, MAX_PACK_SIZE) < 0) {
//                return 0;
//            }
            break;
        }

        case IPPROTO_UDP: {
            struct udphdr udp;
            if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0) {
                return 0;
            }

            src_port = udp.source;
            dst_port = udp.dest;

            __u8 udphdr_len = sizeof(udp);
            __u16 l4_payload_len = ip_pkt_tlen - iphdr_len - udphdr_len;
            payload_offset = l4_offset + udphdr_len;
//            bpf_skb_load_bytes(skb, l4_offset + udphdr_len, &event.data, MAX_PACK_SIZE);
            break;
        }

        default:
            return 0;
    }

    // ignore empty payload traffic
    if (l4_payload_len <= 0)
    {
        return 0;
    }

    event = bpf_ringbuf_reserve(&l4_events_rb, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}

    event->timestamp_ns = bpf_ktime_get_ns();
    event->protocol = ip.protocol;
    event->src_ip = ip.saddr;
    event->dst_ip = ip.daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->data_len = l4_payload_len;
    bpf_skb_load_bytes(skb, payload_offset, event->data, MAX_PACK_SIZE);

    bpf_ringbuf_submit(event, 0);
//    __builtin_memcpy(event.data, packet_body, sizeof(packet_body));
//    bpf_perf_event_output(skb, &l4_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
