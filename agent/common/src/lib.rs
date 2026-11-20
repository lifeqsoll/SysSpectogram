//! Shared eBPF ↔ userspace event layout (POD).

#![cfg_attr(not(feature = "user"), no_std)]

pub const PATH_LEN: usize = 128;
pub const COMM_LEN: usize = 16;

pub const KIND_EXECVE: u8 = 1;
pub const KIND_OPENAT: u8 = 2;
pub const KIND_MODULE: u8 = 3;
pub const KIND_KILL: u8 = 4;
pub const KIND_SETUID: u8 = 5;

/// Fixed-size event pushed through RingBuf / PerfEventArray.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProbeEvent {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub comm: [u8; COMM_LEN],
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
            ppid: 0,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn probe_event_layout_matches_c() {
        assert_eq!(size_of::<ProbeEvent>(), 4 + 4 + 4 + 4 + COMM_LEN + PATH_LEN);
        assert_eq!(align_of::<ProbeEvent>(), 4);
        assert_eq!(offset_of!(ProbeEvent, kind), 0);
        assert_eq!(offset_of!(ProbeEvent, pid), 4);
        assert_eq!(offset_of!(ProbeEvent, uid), 8);
        assert_eq!(offset_of!(ProbeEvent, ppid), 12);
        assert_eq!(offset_of!(ProbeEvent, comm), 16);
        assert_eq!(offset_of!(ProbeEvent, path), 16 + COMM_LEN);
    }
}
