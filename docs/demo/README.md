# Interactive demo (GitHub Pages)

Synthetic browser demo of SysSpectogram scenarios (CPU / mem / net / SSH brute / egress / fake train). **No real host metrics, models, or Telegram.**

## Local preview

```bash
# from repo root
python -m http.server 8765 --directory docs
# open http://127.0.0.1:8765/demo/
```

## Enable GitHub Pages

1. Repo **Settings → Pages**
2. Source: **Deploy from a branch**
3. Branch: `main`, folder: `/docs`
4. Save → wait a minute

Live URL:

`https://lifeqsoll.github.io/SysSpectogram/demo/`

Root `docs/index.html` redirects to `/demo/`.
