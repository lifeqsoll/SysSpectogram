// SPDX-License-Identifier: Dual MIT/GPL
// Tracepoint probes compiled with system clang -target bpf; loaded by Aya.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 128
#define KIND_EXECVE 1
#define KIND_OPENAT 2
#define KIND_MODULE 3

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

static __always_inline void fill_meta(struct probe_event *e, __u8 kind)
{
    e->kind = kind;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
}

/* User pointer → path (execve/openat/delete_module name). */
static __always_inline int emit_user_path(void *ctx, __u8 kind, const char *filename)
{
    struct probe_event e = {};
    fill_meta(&e, kind);
    if (filename)
        bpf_probe_read_user_str(e.path, sizeof(e.path), filename);
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

/* Fixed label in BPF rodata (do NOT use probe_read_user_str). */
static __always_inline int emit_label(void *ctx, __u8 kind, const char *label)
{
    struct probe_event e = {};
    fill_meta(&e, kind);
    if (label)
        bpf_probe_read_kernel_str(e.path, sizeof(e.path), label);
    bpf_perf_event_output(ctx, &EVENTS, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

/* x86_64 raw layout: common(8) + __syscall_nr(+pad) → filename @ 16 */
SEC("tracepoint/syscalls/sys_enter_execve")
int sysspectogram_execve(void *ctx)
{
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), (char *)ctx + 16);
    return emit_user_path(ctx, KIND_EXECVE, filename);
}

/* openat: common(8) + nr + dfd → filename @ 24 */
SEC("tracepoint/syscalls/sys_enter_openat")
int sysspectogram_openat(void *ctx)
{
    const char *filename = NULL;
    bpf_probe_read_kernel(&filename, sizeof(filename), (char *)ctx + 24);
    return emit_user_path(ctx, KIND_OPENAT, filename);
}

/* Module load/unload — high-signal rootkit-relevant */
SEC("tracepoint/syscalls/sys_enter_finit_module")
int sysspectogram_finit_module(void *ctx)
{
    return emit_label(ctx, KIND_MODULE, "finit_module");
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int sysspectogram_init_module(void *ctx)
{
    return emit_label(ctx, KIND_MODULE, "init_module");
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int sysspectogram_delete_module(void *ctx)
{
    const char *name = NULL;
    bpf_probe_read_kernel(&name, sizeof(name), (char *)ctx + 16);
    if (!name)
        return emit_label(ctx, KIND_MODULE, "delete_module");
    return emit_user_path(ctx, KIND_MODULE, name);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
