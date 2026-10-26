# SysSpectogram v1.3.2

Follow-up to the v1.3.1 verify pass.

- Web: `/api/unlock` no longer mints `ss_session` for unauthenticated loopback (Bearer or correct code)
- Control Center: minisign via absolute path; `SYSSPECTOGRAM_GITHUB_REPO` needs `SYSSPECTOGRAM_DEV=1`
- Docs: `INSTALL.md` / `INSTALL_RU.md` / `INSTALL_WITH_AI.md` + README entry points
- Auth: SSH cert IDs with spaces; polkit `service` → `auth_admin`
