// SPDX-License-Identifier: Dual MIT/GPL
// Tracepoint probes compiled with system clang -target bpf; loaded by Aya.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 128
#define KIND_EXECVE 1
#define KIND_OPENAT 2

struct probe_event {
    __u8 kind;
    __u8 _pad[3];
    __u32 pid;
    __u32 uid;
    char path[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} EVENTS SEC(".maps");

static __always_inline int emit_path(void *ctx, __u8 kind, const char *filename)
{
    struct probe_event e = {};
    e.kind = kind;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = (__u32)bpf_get_current_uid_gid();
    if (filename)
        bpf_probe_read_user_str(e.path, sizeof(e.path), filename);
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

/* x86_64 raw layout: common(8) + __syscall_nr(+pad) → filename @ 16 */
SEC("tracepoint/syscalls/sys_enter_execve")
int sysspectogram_execve(void *ctx)
{
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), (char *)ctx + 16);
    return emit_path(ctx, KIND_EXECVE, filename);
}

/* openat: common(8) + nr + dfd → filename @ 24 */
SEC("tracepoint/syscalls/sys_enter_openat")
int sysspectogram_openat(void *ctx)
{
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), (char *)ctx + 24);
    return emit_path(ctx, KIND_OPENAT, filename);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
