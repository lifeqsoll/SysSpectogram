# Optional kernel watchdog helper (v0.9)

Default **off**. Userspace Phoenix + systemd remain the primary anti-silence path.

## What it does

`sysspectogram_wd` exposes sysfs:

```text
/sys/kernel/sysspectogram_wd/protected_pids
```

Write:

```bash
echo 'add 1234' | sudo tee /sys/kernel/sysspectogram_wd/protected_pids
echo 'del 1234' | sudo tee /sys/kernel/sysspectogram_wd/protected_pids
echo 'clear YOUR_TOKEN' | sudo tee /sys/kernel/sysspectogram_wd/protected_pids
```

This release ships a **PID registry** scaffold. Full LSM deny-kill is an opt-in
kernel build path and is **not** enabled by default (many distro kernels reject
unsigned out-of-tree modules).

## Build (self-hosted / custom kernel)

```bash
cd packaging/kmod/sysspectogram_wd
make
sudo insmod ./sysspectogram_wd.ko admin_token=secret
# or DKMS:
sudo dkms add .
sudo dkms install sysspectogram_wd/0.9.0
```

## Config

```yaml
watchdog:
  phoenix: true
  kernel_protect: false   # set true only after module loads cleanly
```

## Honest limits

- Cloud VPS images often block unsigned modules / lack headers.
- Root can still `rmmod` unless the platform locks modules.
- Does **not** replace VMI (v1.0) or claim unkillable EDR.
