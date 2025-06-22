/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct file_rw_event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
    __u32 bytes;
    __u32 op; // 0 = read, 1 = write
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} frw_events_rb SEC(".maps");

static __always_inline int read_filename(struct file *file, char *buf, int size) {
    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    bpf_core_read_str(buf, size, &de->d_name.name);
    return 0;
}

static __always_inline int fill_event(struct file_rw_event_t *event, ssize_t bytes, struct file *file, __u32 op) {
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->bytes = bytes;
    event->op = op;

    return read_filename(file, event->filename, sizeof(event->filename));
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(handle_vfs_read_ret) {
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    struct file_rw_event_t *event = bpf_ringbuf_reserve(&frw_events_rb, sizeof(*event), 0);
    if (!event)
        return 0;

    if (fill_event(event, ret, file, 0) < 0) {
        bpf_ringbuf_discard(event, 0);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(handle_vfs_write_ret) {
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;

    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    struct file_rw_event_t *event = bpf_ringbuf_reserve(&frw_events_rb, sizeof(*event), 0);
    if (!event)
        return 0;

    if (fill_event(event, ret, file, 0) < 0) {
        bpf_ringbuf_discard(event, 0);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
