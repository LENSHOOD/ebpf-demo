/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct qtp_event_t {
    __u32 pid;
    __u8 protocol; // 6 = TCP, 17 = UDP
    __u8 family;   // AF_INET or AF_INET6
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} qtp_events_rb SEC(".maps");

static __always_inline void submit_ipv4_event(struct sock *sk, __u8 proto) {
    struct qtp_event_t *event;
    event = bpf_ringbuf_reserve(&qtp_events_rb, sizeof(*event), 0);
    if (!event)
        return;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    event->pid = pid;
    event->protocol = proto;
    event->family = AF_INET;

    bpf_core_read(&event->sport, sizeof(event->sport), &sk->__sk_common.skc_num);
    bpf_core_read(&event->dport, sizeof(event->dport), &sk->__sk_common.skc_dport);

    bpf_core_read(&event->saddr, sizeof(event->saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&event->daddr, sizeof(event->daddr), &sk->__sk_common.skc_daddr);

    bpf_ringbuf_submit(event, 0);
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    submit_ipv4_event(sk, IPPROTO_TCP);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(handle_udp_sendmsg, struct sock *sk) {
    submit_ipv4_event(sk, IPPROTO_UDP);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";