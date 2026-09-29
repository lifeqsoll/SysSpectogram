# SysSpectogram v0.8.0 — signed supply chain

v0.8 hardens the path from a release or model builder to a running VPS:
signed artifacts, deterministic manifests, SPDX SBOM, distro package recipes,
and a safe model-loading policy.

## Included

- Minisign signatures for release binaries, Python distributions, checksums,
  SBOM, and profile packs.
- Deterministic `artifacts.manifest.json` with SHA-256 and size for every model
  file.
- Optional `supply_chain.enforce` policy propagated through guard, monitor,
  offline analysis, web, and Telegram scoring.
- `cnn.pt` loading with `weights_only=True` only; no unsafe arbitrary-object
  fallback.
- SPDX 2.3 SBOM generator for installed Python and Cargo dependencies.
- CI dependency vulnerability auditing.
- Buildable AUR and Debian packaging recipes with hardened systemd units.
- Release verification helper that never executes downloaded assets.

## Compatibility and rollout

Existing v0.7.x configs continue to work with enforcement disabled:

```yaml
supply_chain:
  enforce: false
```

After installing the release public key and signing the model directory:

```yaml
supply_chain:
  enforce: true
  public_key: /etc/sysspectogram/sysspectogram.minisign.pub
  manifest_name: artifacts.manifest.json
  signature_name: artifacts.manifest.json.minisig
```

Use `python -m sysspectogram configure` to set this interactively. It refuses
to enable enforcement without a public key.

## Verify release assets

```bash
minisign -Vm sysspectogram-agent-x86_64-linux-musl \
  -p SysSpectogram.minisign.pub \
  -x sysspectogram-agent-x86_64-linux-musl.minisig

scripts/verify-release.sh SysSpectogram.minisign.pub \
  sysspectogram-agent-x86_64-linux-musl \
  sysspectogram-agent-x86_64-linux-musl.sha256
```

## Verify model artifacts

```bash
python -m sysspectogram supply-chain verify artifacts/real_v3 \
  --enforce --public-key /etc/sysspectogram/sysspectogram.minisign.pub
```

`--insecure` remains available for explicit local profile installation only;
it is not a production trust mode.

## Build and package

Builder:

```bash
python -m build
python scripts/generate-sbom.py --out dist/sbom.spdx.json
cd agent && cargo build --release --locked --no-default-features
```

Arch:

```bash
cd packaging/aur
makepkg -si
```

Debian/Ubuntu:

```bash
dpkg-buildpackage -us -uc -b -d
```

The packaged agent defaults to userspace mode. eBPF requires a compatible
kernel and the documented capabilities; it is not silently assumed.

## Upgrade

```bash
git fetch --tags
git checkout v0.8.0
python -m venv .venv
source .venv/bin/activate
pip install -e '.[onnx]'
cd agent && cargo build --release --locked
cd ..
python -m sysspectogram configure
```

Keep `response.mode: observe` and `kirk.auto_isolate: false` during the first
upgrade, verify the public key and model signature, then restart the services.

## Security notes

`iforest.joblib` and `scaler.joblib` remain legacy pickle-compatible files.
They are accepted only after manifest verification when enforcement is enabled.
Prefer ONNX inference on small VPS hosts and generate model artifacts on a
trusted builder. See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) and [SECURITY.md](../SECURITY.md).

## Known ceiling

`kirk.trust: best-effort` remains honest on hosts without IMA plus measured
boot evidence. Live VMI is still conditional v1.0 functionality for self-hosted
KVM and is not part of this release.
