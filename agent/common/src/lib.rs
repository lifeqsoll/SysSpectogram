//! Shared eBPF ↔ userspace event layout (POD).

#![cfg_attr(not(feature = "user"), no_std)]

pub const PATH_LEN: usize = 128;

pub const KIND_EXECVE: u8 = 1;
pub const KIND_OPENAT: u8 = 2;
pub const KIND_MODULE: u8 = 3;

/// Fixed-size event pushed through RingBuf / PerfEventArray.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProbeEvent {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub path: [u8; PATH_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProbeEvent {}

impl ProbeEvent {
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            _pad: [0; 3],
            pid: 0,
            uid: 0,
            path: [0; PATH_LEN],
        }
    }
}
