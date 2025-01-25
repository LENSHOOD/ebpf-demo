#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/filter.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

#define MAX_PACK_SIZE 64

struct tcp_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    char data[MAX_PACK_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_events SEC(".maps");

SEC("socket")
int net_filter(struct __sk_buff *skb) {
    char packet_body[MAX_PACK_SIZE];
    struct tcp_event_t event = {};

    int offset = ETH_HLEN;
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0) {
        return 0;
    }

    if (ip.protocol != IPPROTO_TCP) {
        return 0;
    }

    event.src_ip = ip.saddr;
    event.dst_ip = ip.daddr;

    offset += ip.ihl * 4;
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0) {
        return 0;
    }

    event.dst_port = tcp.dest;
    offset += tcp.doff * 4;

    if (bpf_skb_load_bytes(skb, offset, http_header, sizeof(http_header)) < 0) {
        return 0;
    }

//    if (http_header[0] == 'G' || http_header[0] == 'P' || http_header[0] == 'H') {
        __builtin_memcpy(event.data, http_header, sizeof(http_header));
        bpf_perf_event_output(skb, &http_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//    }

    return 0;
}

char _license[] SEC("license") = "GPL";
