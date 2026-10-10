# ADR 0004: privilege model (helper split)

Status: accepted for v1.0.

## Decision

- The Control Center runs as the user. It has no shell access and does not store passwords.
- `sysspectogram-helper` is a systemd unit under root. It accepts only allowlisted operations: install, apply-config, rollback, service start and stop, update.
- Every privileged operation goes through polkit. The user confirms in the system dialog.
- The agent runs as root only in eBPF mode, via its own systemd unit. Userspace mode runs without root.
- eBPF and kmod are off by default in the UI.

## Consequences

- A compromised GUI cannot run arbitrary root commands.
- Installing the helper and polkit policy requires one `sudo` step, listed in the system-steps block.

## Rejected

- Running the whole application under `sudo`: simplest, but the whole UI runs as root.
- Running everything without root: eBPF and kmod features would be unavailable.
