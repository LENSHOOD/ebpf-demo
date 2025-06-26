/* SPDX-License-Identifier: GPL-2.0 */
#ifdef __TARGET_ARCH_arm64
#include "vmlinux_arm64.h"
#endif

#ifdef __TARGET_ARCH_x86
#include "vmlinux_x86.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct file_rw_event_t {
    __u32 pid;
    char comm[16];
    __u32 fd;
    __u32 op; // 0 = read, 1 = write
    __u32 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} frw_events_rb SEC(".maps");

static __always_inline void fill_event(__u32 fd, __u32 op) {
    struct file_rw_event_t *event = bpf_ringbuf_reserve(&frw_events_rb, sizeof(*event), 0);
    if (!event)
        return;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->op = op;
    event->fd = fd;    

    bpf_printk("pid = %d, fd = %d, op = %d\n", event->pid, event->fd, event->op);
    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u32 fd = ctx->args[0];
    fill_event(fd, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
     __u32 fd = ctx->args[0];
    fill_event(fd, 1);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
