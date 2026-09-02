// SPDX-License-Identifier: GPL-2.0
// Traces connect() syscalls to capture outbound network connections.
#include "common.h"
#include <bpf/bpf_endian.h>

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8  pad[8];
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u64 cid = bpf_get_current_cgroup_id();
    if (!should_trace(cid)) return 0;

    // Read sockaddr from user space
    struct sockaddr_in sa;
    const void *uaddr = (const void *)ctx->args[1];
    if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0) return 0;
    if (sa.sin_family != 2 /* AF_INET */) return 0; // IPv4 only for now

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type         = EVENT_NETWORK_CONNECT;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = cid;
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->uid          = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->remote_port  = bpf_ntohs(sa.sin_port);
    e->flags        = 0;
    e->result       = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Format IP as a.b.c.d
    __u32 ip = sa.sin_addr;
    __u8 a = ip & 0xFF, b = (ip >> 8) & 0xFF,
         c = (ip >> 16) & 0xFF, d = (ip >> 24) & 0xFF;
    bpf_snprintf(e->remote_addr, sizeof(e->remote_addr),
                 "%d.%d.%d.%d", a, b, c, d);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
