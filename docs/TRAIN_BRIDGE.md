# Train bridge — VPS data → PC train → weights back

## Flow

```bash
# On VPS (no Torch)
python -m sysspectogram data bundle \
  --csv data/normal.csv data/anomaly.csv \
  --out /tmp/ss-data.tgz

# On PC
python -m sysspectogram data pull-cmd --bundle /tmp/ss-data.tgz --ssh user@vps
# → rsync -avz user@vps:/tmp/ss-data.tgz ./ss-bundles/
python -m sysspectogram data unpack ./ss-bundles/ss-data.tgz --dest ~/ss-work
python -m sysspectogram build-dataset --normal … --anomaly … --out ~/ss-work/ds
python -m sysspectogram train --dataset ~/ss-work/ds --out ~/ss-work/artifacts
python -m sysspectogram export-onnx --model ~/ss-work/artifacts
python -m sysspectogram artifacts push \
  --model ~/ss-work/artifacts --ssh user@vps \
  --remote /opt/sysspectogram/artifacts/live \
  --restart-systemd sysspectogram-guard
```

Secrets (`.env`, keys) are refused in bundles.
