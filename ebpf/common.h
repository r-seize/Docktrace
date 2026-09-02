#pragma once
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define PATH_LEN      256

enum event_type {
    EVENT_PROCESS_EXEC    = 1,
    EVENT_PROCESS_EXIT    = 2,
    EVENT_FILE_OPEN       = 3,
    EVENT_FILE_WRITE      = 4,
    EVENT_NETWORK_CONNECT = 7,
};

struct event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 uid;
    __u32 type;
    __s32 result;
    __s32 flags;
    __u16 remote_port;
    __u8  pad[2];
    char  comm[TASK_COMM_LEN];
    char  path[PATH_LEN];
    char  remote_addr[48];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Optional: filter by cgroup_id (0 = accept all)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} target_cgroup SEC(".maps");

static __always_inline int should_trace(__u64 cid) {
    __u32 key = 0;
    __u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target || *target == 0) return 1; // no filter: trace all
    return (*target == cid);
}
