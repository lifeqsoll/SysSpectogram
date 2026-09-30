# v0.8 Supply-chain hardening

SysSpectogram v0.8 separates two trust layers:

1. SHA-256 manifests detect accidental or local tampering.
2. `minisign` signatures authenticate who published a release or model pack.

The existing HMAC pack sidecar remains supported for local compatibility. It is
not a replacement for a release signing key.

## Generate and verify a model manifest

Training and ONNX export write `artifacts.manifest.json` automatically:

```bash
python -m sysspectogram supply-chain manifest artifacts/real_v3
python -m sysspectogram supply-chain verify artifacts/real_v3
```

The manifest covers regular files below the model directory, including
`cnn.onnx`, `cnn.pt`, `iforest.ssf.npz`, `scaler.json`, `meta.json`, and the
existing checksum file. It excludes only the manifest and its signature.

## Create a minisign key

Keep the secret key off the VPS and out of Git:

```bash
# CI-friendly: empty password (still keep the file mode 600 / in GitHub Secrets)
minisign -G -W -p sysspectogram.minisign.pub -s sysspectogram.minisign.key
chmod 600 sysspectogram.minisign.key
```

For GitHub Actions `release-assets`:

```bash
# put the exact key file into the repo secret (preserves newlines)
gh secret set MINISIGN_SECRET_KEY < sysspectogram.minisign.key
# public key as a repository variable (Settings → Variables), or:
gh variable set MINISIGN_PUBLIC_KEY < sysspectogram.minisign.pub
```

If the secret key is password-protected, also set `MINISIGN_PASSWORD` as a
repository secret. Encrypted keys with a wrong/missing password fail CI with
`Wrong password for that key`.

Sign a manifest:

```bash
python -m sysspectogram supply-chain sign \
  artifacts/real_v3/artifacts.manifest.json \
  --secret-key /secure/sysspectogram.minisign.key \
  --signature artifacts/real_v3/artifacts.manifest.json.minisig
```

Verify it before installing or starting the guard:

```bash
python -m sysspectogram supply-chain verify artifacts/real_v3 \
  --enforce \
  --public-key /etc/sysspectogram/sysspectogram.minisign.pub
```

## Enforce on a VPS

Add this to `configs/default.yaml`:

```yaml
supply_chain:
  enforce: true
  public_key: /etc/sysspectogram/sysspectogram.minisign.pub
  manifest_name: artifacts.manifest.json
  signature_name: artifacts.manifest.json.minisig
```

With enforcement enabled, guard, monitor, web scoring, Telegram `/score`, and
offline analysis reject missing, altered, unsigned, or invalidly signed model
artifacts before deserializing them. Existing v0.7.x configurations keep
`enforce: false` until an operator opts in.

`--insecure` on `profiles pull/install` is an explicit compatibility escape
hatch. Do not use it for production models.

## Model format policy

- Prefer `cnn.onnx` on a VPS: it avoids installing PyTorch.
- `cnn.pt` is loaded only with PyTorch `weights_only=True`; v0.8 no longer
  falls back to unsafe arbitrary-object deserialization.
- v0.9 defaults: `scaler.json` and `iforest.ssf.npz` (+ `iforest.ssf.meta.json`).
- Legacy `.joblib` is **not** loaded at runtime. Migrate once:
  `python -m sysspectogram artifacts migrate --model DIR --delete-legacy`.
- `open_verified_artifact()` re-checks the digest of the open file against the
  manifest before deserialization when enforcement is enabled.
- The optional agent IF (`agent.iforest`) is also verified with its adjacent
  `.minisig` before load when enforcement is enabled.

An IF refit changes the manifest. Under enforcement, pass the signing key so
the operation remains trusted:

```bash
python -m sysspectogram feedback retrain-if \
  --model artifacts/real_v3 \
  --minisign-secret-key /secure/sysspectogram.minisign.key
```

Without a signing key an enforced refit fails before changing the model. A
non-enforced refit removes an old stale signature, so the next enforced start
cannot mistake it for a trusted model.

## Release assets

Release CI signs the musl agent, Python distributions, checksums, SBOM, and
profile packs with the repository's `MINISIGN_SECRET_KEY` secret. The public
key is published as `SysSpectogram.minisign.pub` from the non-secret
`MINISIGN_PUBLIC_KEY` repository variable.

Verify downloaded assets without executing them:

```bash
scripts/verify-release.sh SysSpectogram.minisign.pub \
  sysspectogram-agent-x86_64-linux-musl \
  sysspectogram-agent-x86_64-linux-musl.sha256
```

Rotate keys by publishing the new public key in a new release, updating the
VPS key file atomically, verifying a test artifact, and then changing
`supply_chain.public_key`. Never commit a secret key.

## SBOM

Generate a deterministic SPDX 2.3 document:

```bash
python scripts/generate-sbom.py --out dist/sbom.spdx.json
python -m sysspectogram supply-chain sbom --output dist/sbom.spdx.json
```

The document includes installed Python distributions, Cargo workspace
packages, and optional release-file hashes. `SOURCE_DATE_EPOCH` controls the
SPDX creation timestamp for reproducible builds.

## Package builds

Arch:

```bash
cd packaging/aur
makepkg -si
```

Debian/Ubuntu:

```bash
dpkg-buildpackage -us -uc -b -d
```

Both packages install the agent, hardened systemd units, and the default
configuration. The packaged agent defaults to userspace mode, while the guard
and monitor run as the dedicated `sysspectogram` account. Enable eBPF only
after confirming kernel support and applying a reviewed systemd drop-in that
grants the documented `CAP_BPF`, `CAP_PERFMON`, and related capabilities.
