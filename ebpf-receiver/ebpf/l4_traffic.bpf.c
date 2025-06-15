#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define MAX_PACK_SIZE 1024
#define DATA_LOAD_OFFSET_512 512
#define DATA_LOAD_OFFSET_256 256
#define DATA_LOAD_OFFSET_128 128
#define DATA_LOAD_OFFSET_64 64
#define DATA_LOAD_OFFSET_32 32
#define DATA_LOAD_OFFSET_16 16
#define DATA_LOAD_OFFSET_8 8
#define DATA_LOAD_OFFSET_4 4
#define DATA_LOAD_OFFSET_2 2
#define DATA_LOAD_OFFSET_1 1

struct l4_event_t {
    __u64 mono_timestamp_ns;
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

int copy_event_data(struct __sk_buff *skb, struct l4_event_t *event, __u16 payload_offset, __u16 l4_payload_len) {
    if (skb == 0 || event == 0) {
        return -1;
    }

    __u16 copy_remain_bytes = l4_payload_len > MAX_PACK_SIZE ? MAX_PACK_SIZE : l4_payload_len;
    __u16 copy_offset = 0;
    if (copy_remain_bytes >= MAX_PACK_SIZE) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, MAX_PACK_SIZE);
        copy_offset += MAX_PACK_SIZE;
        copy_remain_bytes -= MAX_PACK_SIZE;
    }

    if (copy_remain_bytes >= DATA_LOAD_OFFSET_512) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_512);
        copy_offset += DATA_LOAD_OFFSET_512;
        copy_remain_bytes -= DATA_LOAD_OFFSET_512;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_256) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_256);
        copy_offset += DATA_LOAD_OFFSET_256;
        copy_remain_bytes -= DATA_LOAD_OFFSET_256;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_128) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_128);
        copy_offset += DATA_LOAD_OFFSET_128;
        copy_remain_bytes -= DATA_LOAD_OFFSET_128;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_64) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_64);
        copy_offset += DATA_LOAD_OFFSET_64;
        copy_remain_bytes -= DATA_LOAD_OFFSET_64;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_32) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_32);
        copy_offset += DATA_LOAD_OFFSET_32;
        copy_remain_bytes -= DATA_LOAD_OFFSET_32;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_16) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_16);
        copy_offset += DATA_LOAD_OFFSET_16;
        copy_remain_bytes -= DATA_LOAD_OFFSET_16;
    }

    if (copy_remain_bytes >= DATA_LOAD_OFFSET_8) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_8);
        copy_offset += DATA_LOAD_OFFSET_8;
        copy_remain_bytes -= DATA_LOAD_OFFSET_8;
    }
    
    if (copy_remain_bytes >= DATA_LOAD_OFFSET_4) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_4);
        copy_offset += DATA_LOAD_OFFSET_4;
        copy_remain_bytes -= DATA_LOAD_OFFSET_4;
    }

    if (copy_remain_bytes >= DATA_LOAD_OFFSET_2) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_2);
        copy_offset += DATA_LOAD_OFFSET_2;
        copy_remain_bytes -= DATA_LOAD_OFFSET_2;
    }

    if (copy_remain_bytes >= DATA_LOAD_OFFSET_1) {
        bpf_skb_load_bytes(skb, payload_offset + copy_offset, event->data + copy_offset, DATA_LOAD_OFFSET_1);
        copy_offset += DATA_LOAD_OFFSET_1;
        copy_remain_bytes -= DATA_LOAD_OFFSET_1;
    }

    return copy_remain_bytes;
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
            break;
        }

        default:
            return 0;
    }

    // ignore empty payload traffic
    if (l4_payload_len == 0)
    {
        return 0;
    }

    event = bpf_ringbuf_reserve(&l4_events_rb, sizeof(*event), 0);
	if (!event)
	{
		return 0;
	}

    event->mono_timestamp_ns = bpf_ktime_get_ns();
    event->protocol = ip.protocol;
    event->src_ip = ip.saddr;
    event->dst_ip = ip.daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->data_len = l4_payload_len;

    copy_event_data(skb, event, payload_offset, l4_payload_len);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
