# VMI cross-view (read-only)

Status in v1.0: **read-only task cross-view** for a Linux guest on a KVM host you control. Shipped behind `kirk.vmi: false` (off by default).

## What it does

1. The guard reads the guest's process list from the in-guest agent (`sysspectogram.pids.v1` snapshots over the agent socket).
2. It reads the task list of the same guest from the hypervisor side (`GuestTaskSource`).
3. A task that the hypervisor sees and the guest does not is a candidate for hiding. It alerts as `vmi_task_hidden` (severity `high`) after `kirk.vmi_confirm` consecutive passes.
4. Each hidden pid alerts once. It alerts again only if it disappears and comes back.
5. Kernel pids 0 and 1 are never reported.

The check never pauses, writes to or kills anything. It only raises alerts.

## Backends

| `kirk.vmi_backend` | Use | Needs |
| --- | --- | --- |
| `mock` (default) | tests, demos, Control Center lab run | nothing |
| `libvmi` | real guest on a KVM host | libvmi Python binding, libvirt domain, ISF profile for the guest kernel |

The `libvmi` backend walks `init_task.tasks`. It binds the ISF profile to the guest kernel release recorded in `<profile>.meta.json` and refuses to run on a mismatch. The binding names were written against the libvmi Python API and have **not yet been verified on a live KVM guest**. Verify them with the lab procedure before relying on the backend.

## Configuration

```yaml
kirk:
  vmi: false            # master switch
  vmi_backend: mock     # mock | libvmi
  vmi_domain: null      # libvirt domain name of the guest (libvmi only)
  vmi_profile: null     # path to the ISF profile (libvmi only)
  vmi_trust: lab        # lab | out-of-band, see ADR 0003
  vmi_confirm: 2        # consecutive passes before an alert
  vmi_interval_sec: 30  # cross-view period
  vmi_pids_sec: 5       # how often the agent sends pid snapshots
```

The same keys are in the Control Center settings (group Integrity and VMI). `kirk.vmi` and `kirk.vmi_backend` need a guard restart.

## Trust label

`vmi_trust: lab` means the hypervisor and the guard run on the same machine, so one compromised host can affect both. Use `out-of-band` only when the hypervisor is a separate trust domain. See [adr/0003-trust-labels.md](adr/0003-trust-labels.md). Alerts carry the label in `extras.trust`.

## Limits

- Linux guests only. Windows guests are out of scope.
- Task list only. There is no module scan, no memory scan and no syscall table check.
- A rootkit can still lie to the in-guest view and to libvmi reads that go through the same kernel data. The cross-view finds inconsistencies. It does not prove absence.
- The `libvmi` backend is unverified on hardware until the lab run in the release notes passes.

## Lab procedure

1. Run `kvm-ok` (or check `/dev/kvm`) on the host. Install libvirt and libvmi as described in the release notes.
2. Create a Linux guest and install the SysSpectogram agent in it.
3. Build the ISF profile for the guest kernel and record its release in `<profile>.meta.json`.
4. Set `kirk.vmi: true`, `kirk.vmi_backend: libvmi`, `kirk.vmi_domain` and `kirk.vmi_profile`. Set `kirk.vmi_trust: lab`.
5. Check the alert path first with the `mock` backend (Control Center lab-demo scenario). Then, only on a throwaway guest, hide a process with a lab-only test module. Expect `vmi_task_hidden`. Never do step 5 on a production host.

Until the lab run passes, use in-guest Kirk plus the IMA/TPM label. See [KIRK.md](KIRK.md).
