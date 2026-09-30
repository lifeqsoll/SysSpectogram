# Golden path (smoke)

End-to-end lab check: quiet baseline → synthetic load → alert line.

## Prerequisites

```bash
source .venv/bin/activate
pip install -e ".[dev]"
# optional model:
#   artifacts/live with cnn.onnx + scaler.json + iforest.ssf.npz
```

## Script

```bash
chmod +x scripts/demo_golden_path.sh
./scripts/demo_golden_path.sh
# with model:
./scripts/demo_golden_path.sh --model artifacts/live
```

Expect: non-zero exit if no alert-looking line appears in the jsonl / log within the window.

No nmap/recon in this path.
