# Contributing

Thanks for helping improve SysSpectogram.

## Dev install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd agent && cargo build && cd ..
# optional desktop
cd control-center && npm install && cd ..
```

## Tests

```bash
pytest -q
```

Integration tests that touch real nftables (optional):

```bash
sudo unshare -n pytest -m nft_real -q
```

## Control Center / Fleet (Tauri)

```bash
cd control-center && npm run check && npm test
cd fleet-center && npm run check && npm test
```

## Docs (EN / RU)

User-facing install paths exist in **both** [docs/INSTALL.md](docs/INSTALL.md) and [docs/INSTALL_RU.md](docs/INSTALL_RU.md). If you change commands, flags, or release asset names, update both (and [docs/INSTALL_WITH_AI.md](docs/INSTALL_WITH_AI.md) when the agent prompt references them).

## Pull requests

- One logical change per PR when possible.
- Run `pytest` before opening.
- Security issues: [SECURITY.md](SECURITY.md) (private advisory preferred).

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
