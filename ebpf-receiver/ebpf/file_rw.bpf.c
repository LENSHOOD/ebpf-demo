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
    __u32 op; // 0 = read, 1 = write
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} frw_events_rb SEC(".maps");

static __always_inline void fill_event(struct file *file, __u32 op) {
    struct file_rw_event_t *event = bpf_ringbuf_reserve(&frw_events_rb, sizeof(*event), 0);
    if (!event)
        return;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->op = op;

    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    bpf_core_read_str(event->filename, sizeof(event->filename), &de->d_name.name);

    bpf_printk("file = %s\n", event->filename);
    bpf_ringbuf_submit(event, 0);
}

SEC("kprobe/vfs_read")
int BPF_KRETPROBE(handle_vfs_read_ret, struct file *file) {
    if (!file) {
        return 0;
    }

    fill_event(file, 0);

    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KRETPROBE(handle_vfs_write_ret, struct file *file) {
     if (!file) {
        return 0;
    }

    fill_event(file, 1);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
