// SPDX-License-Identifier: GPL-2.0
// Traces execve/execveat system calls.
#include "common.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cid = bpf_get_current_cgroup_id();
    if (!should_trace(cid)) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type         = EVENT_PROCESS_EXEC;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = cid;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->result       = 0;
    e->flags        = 0;
    e->remote_port  = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read the first argument (filename)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
