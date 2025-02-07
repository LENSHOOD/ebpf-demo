#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14
#define MAX_PACK_SIZE 20

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

    if (bpf_skb_load_bytes(skb, offset, packet_body, sizeof(packet_body)) < 0) {
        return 0;
    }

    __builtin_memcpy(event.data, packet_body, sizeof(packet_body));
    bpf_perf_event_output(skb, &tcp_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char _license[] SEC("license") = "GPL";
