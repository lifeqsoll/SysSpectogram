# ADR 0005: signed release bundle instead of git pull

Status: accepted for v1.0.

## Decision

- The GUI version equals the release version of the Python package and the agent.
- On first run the GUI downloads the signed release of its own version: Python package, lock file, agent binary, scenario presets.
- Verification: minisign signature and sha256. The public key is embedded in the GUI build. Unsigned bundles are refused.
- Installation is performed by the helper through polkit.
- No `git pull` at runtime. Updates happen only on an explicit user action.

## Consequences

- Works offline after the first install.
- Code that runs as root always comes from a verified release, never from a live branch.
