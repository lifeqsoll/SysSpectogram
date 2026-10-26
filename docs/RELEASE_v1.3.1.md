# SysSpectogram v1.3.1

Security follow-up to the v1.3.0 audit.

- Helper install: mandatory minisign for helper + packaging.tgz; signed install scripts in CI
- Control Center: no user-writable path in pkexec (bash -s + verified stdin)
- Web: mutations need session/Bearer; Host check on /api/health; connection/SSE caps
- Secrets: 0600 write helper, bot token via stdin, migrate needs --i-trust-this-pickle
- Auth: SSH certificate Accepted lines; pkcheck pid,start,uid; nmap/recon input hardening
