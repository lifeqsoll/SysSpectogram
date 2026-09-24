# Interactive demo (GitHub Pages)

Synthetic browser demo of SysSpectogram scenarios (CPU / mem / net / SSH brute / egress / fake train). **No real host metrics, models, or Telegram.**

## Local preview

```bash
cd docs && python -m http.server 8765
# open http://127.0.0.1:8765/demo/
```

## Enable GitHub Pages (one-time)

Repo files live under `docs/`. If Pages is set to **branch root `/`**, you only see the README and `/demo/` returns **404**.

### Recommended: GitHub Actions

1. Push includes `.github/workflows/pages.yml` (deploys the `docs/` folder).
2. **Settings → Pages → Build and deployment → Source:** **GitHub Actions**.
3. Wait for the **Deploy Pages demo** workflow (Actions tab) → green.
4. Open:
   - https://lifeqsoll.github.io/SysSpectogram/  
   - https://lifeqsoll.github.io/SysSpectogram/demo/

### Alternative: branch `/docs` folder

1. **Settings → Pages → Source:** Deploy from a branch  
2. Branch: `main` · Folder: **`/docs`** (not `/`)  
3. Save and wait ~1 minute.

`docs/.nojekyll` disables Jekyll so `index.html` is served as-is.

Root `docs/index.html` redirects to `/demo/`.
