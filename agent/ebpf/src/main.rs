#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use sysspectogram_common::{ProbeEvent, KIND_EXECVE, KIND_OPENAT, PATH_LEN};

#[map]
static EVENTS: PerfEventArray<ProbeEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn sysspectogram_execve(ctx: TracePointContext) -> u32 {
    match try_path_event(&ctx, KIND_EXECVE, 16) {
        Ok(()) => 0,
        Err(c) => c,
    }
}

#[tracepoint]
pub fn sysspectogram_openat(ctx: TracePointContext) -> u32 {
    // sys_enter_openat: filename pointer after common hdr + syscall_nr + dfd
    // typical offset 24 on x86_64 raw syscall tracepoints
    match try_path_event(&ctx, KIND_OPENAT, 24) {
        Ok(()) => 0,
        Err(c) => c,
    }
}

fn try_path_event(ctx: &TracePointContext, kind: u8, filename_off: usize) -> Result<(), u32> {
    let mut ev = ProbeEvent::zeroed();
    ev.kind = kind;
    let pid_tgid = bpf_get_current_pid_tgid();
    ev.pid = (pid_tgid >> 32) as u32;
    ev.uid = bpf_get_current_uid_gid() as u32;

    let filename_ptr: u64 = unsafe { ctx.read_at(filename_off) }.map_err(|_| 1u32)?;
    if filename_ptr == 0 {
        return Ok(());
    }
    let mut buf = [0u8; PATH_LEN];
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut buf) };
    ev.path = buf;

    EVENTS.output(ctx, &ev, 0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
