# Install with an AI agent

Technical steps live in **[INSTALL.md](INSTALL.md)** (Russian: [INSTALL_RU.md](INSTALL_RU.md)).
This file tells the **agent** how to drive that guide. Answer the user in **their language**.

Tag placeholder in INSTALL.md: `<LATEST_TAG>` — resolve from
https://github.com/lifeqsoll/SysSpectogram/releases/latest (never invent; never use floating `main`).

When loading docs from GitHub, use **tagged raw URLs**, not `main`:

`https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/INSTALL_WITH_AI.md`

If a required release asset (friend-day0, wheel, desktop AppImage/deb + `.minisig`, helper script) is **missing on that tag**, **stop** and tell the user — do not substitute another tag or unsigned git raw.

---

## For the user: copy this to your AI agent

```
Помоги мне установить SysSpectogram. Прочитай
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/INSTALL_WITH_AI.md
и
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/INSTALL.md
(подставь тег с releases/latest) и веди меня: сначала задай вопросы, потом по шагам.
```

If the agent cannot open URLs, paste **both** files into the chat in full.

English paste variant:

```
Help me install SysSpectogram. Read
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/INSTALL_WITH_AI.md
and
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/<LATEST_TAG>/docs/INSTALL.md
(tag from releases/latest) and guide me: ask questions first, then step by step.
```

---

## 1. Rules for the agent

1. **Questions first** (section 2) → short plan → user confirms → execute.
2. Give **1–2 shell commands at a time**, wait for output before the next.
3. For beginners, one plain sentence per command (what it does / why).
4. **Never** ask the user to paste bot tokens, Cloudflare tokens, passwords, or private keys into chat. Tell them which local file/UI field to fill themselves (`.env` 0600, Control Center, `read -rsp` + `home env --from-stdin` locally).
5. Install only from the **latest GitHub Release tag**. If you cannot fetch it, ask the user for the tag shown on `releases/latest`.
6. Any root/helper path: **minisign verify must succeed**. Never suggest skipping signatures or piping unsigned raw scripts into `sudo bash`.
7. **never_ban** (admin SSH IP via `home seed-never-ban --ip …`, often `${SSH_CONNECTION%% *}`) **before** `protect enable` and before soft/full/isolate — see INSTALL.md §1.3. Suggest `--dry-run` first.
8. If unsure which path: default to INSTALL.md **§1 Quick start**.
9. Do not invent CLI flags or asset names; only what appears in INSTALL.md / the repo CLI / release-assets.
10. **Windows admin PC:** user may SSH from laptop; map `${SSH_CONNECTION%% *}` on the VPS to their public IP; on Windows they can run `curl.exe -4 ifconfig.me` locally to double-check.
11. **Ubuntu VPS:** remind about `universe` before `apt install minisign` (INSTALL §1.1).
12. **Missing desktop assets** on latest release → stop; do not invent download URLs.

---

## 2. Questions to ask first

Ask once, short multiple-choice where possible:

1. **Where?** One VPS/VDS (distro + version) / home Linux PC with desktop / several servers?
2. **Admin machine OS?** Linux / **Windows** / macOS — GUI available? (Windows → SSH client, `curl.exe -4 ifconfig.me` for never-ban check.)
3. **Privileges?** Install as **root** or normal user with **sudo**? SSH key or password?
4. **Never-ban IP?** Public IP or CIDR of the **admin SSH source** (not the VPS datacenter IP unless that is you).
5. **Distro quirks?** **Ubuntu** → need `universe` for `minisign`? Debian-like otherwise?
6. **Hardware?** Approx RAM, CPU, GPU (if any)?
7. **Goals?** SSH protection + alerts only / Telegram / web UI / desktop app / eBPF agent / Cloudflare Under Attack / own ML model?
8. **Experience?** Beginner or comfortable with Linux?

---

## 3. Decision mapping → INSTALL.md

| Answers | Open this section |
|---------|-------------------|
| Beginner + one VPS | **§1 Quick start** (always) |
| One VPS, deeper detail | **§A Headless VPS** |
| Linux desktop GUI | **§B Desktop** |
| Many servers | **§C Fleet Hub** |
| Dev / git checkout | **§D Source** |
| Container train/analyze only | **§E Docker** (warn: not live guard) |
| Wants Telegram / web / eBPF / Edge / ML | Matching add-on headings under INSTALL.md |

---

## 4. Flow

1. Summarize answers in the user’s language (3–6 bullet plan pointing at INSTALL.md headings).
2. Wait for confirmation.
3. Walk Quick start or A–E **step-by-step** from INSTALL.md (copy commands exactly; substitute only `<LATEST_TAG>`).
4. Run the **Checklist after install** section.
5. Offer optional add-ons (Telegram, web, …) without pushing secrets into chat.
6. Point to **Update** / **Stop / remove** when relevant.

---

## 5. When something fails

1. Ask for the **full command + full stderr/stdout**.
2. Match against INSTALL.md **Frequent problems** and the FAQ below.
3. Do not guess past that list; open linked deep docs (FRIEND, DAY0_VPS, CONTROL_CENTER, SECURITY) only after naming which section you are using.

### FAQ (agent)

| Symptom | What to say |
|--------|-------------|
| Friend menu **`EOFError`** / instant exit | Need TTY: `ssh -t user@host`; or quit menu with **0**; or `friend-day0.sh … --no-menu` if supported; then INSTALL §1.3. |
| **`home health` → `"ok": false`** | Often normal without helper, Telegram, or fresh metrics; see INSTALL §1.3. After `protect enable`, re-check `guard`. |
| **No Control Center AppImage/deb on latest release** | Stop — tell user to pick a release that lists desktop assets or wait for CI; never fabricate URLs. |

Headings the agent may cite (exact strings must appear in INSTALL.md):

- `## 1. Quick start (one Ubuntu/Debian VPS)`
- `## 2. Pick your path`
- `## A. Headless VPS`
- `## B. Desktop (Control Center)`
- `## C. Fleet Hub`
- `## D. Source install`
- `## E. Docker`
- `## Telegram bot`
- `## Web dashboard`
- `## eBPF integrity agent`
- `## Cloudflare Edge`
- `## Own ML model`
- `## Checklist after install`
- `## Frequent problems`
- `## Update (signed releases only)`
- `## Stop / remove / rollback`
