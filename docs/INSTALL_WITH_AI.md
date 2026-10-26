# Install with an AI agent

Technical steps live in **[INSTALL.md](INSTALL.md)** (Russian: [INSTALL_RU.md](INSTALL_RU.md)).
This file tells the **agent** how to drive that guide. Answer the user in **their language**.

Tag placeholder in INSTALL.md: `<LATEST_TAG>` — resolve from
https://github.com/lifeqsoll/SysSpectogram/releases/latest (never invent; never use floating `main`).

---

## For the user: copy this to your AI agent

```
Помоги мне установить SysSpectogram. Прочитай
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/docs/INSTALL_WITH_AI.md
и
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/docs/INSTALL.md
и веди меня по ним: сначала задай вопросы, потом по шагам.
```

If the agent cannot open URLs, paste **both** files into the chat in full.

English paste variant:

```
Help me install SysSpectogram. Read
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/docs/INSTALL_WITH_AI.md
and
https://raw.githubusercontent.com/lifeqsoll/SysSpectogram/main/docs/INSTALL.md
and guide me: ask questions first, then step by step.
```

---

## 1. Rules for the agent

1. **Questions first** (section 2) → short plan → user confirms → execute.
2. Give **1–2 shell commands at a time**, wait for output before the next.
3. For beginners, one plain sentence per command (what it does / why).
4. **Never** ask the user to paste bot tokens, Cloudflare tokens, passwords, or private keys into chat. Tell them which local file/UI field to fill themselves (`.env` 0600, Control Center, `home env --from-stdin` locally).
5. Install only from the **latest GitHub Release tag**. If you cannot fetch it, ask the user for the tag shown on `releases/latest`.
6. Any root/helper path: **minisign verify must succeed**. Never suggest skipping signatures or piping unsigned raw scripts into `sudo bash`.
7. Ensure **never_ban** (admin IP) before enabling soft/full/isolate bans — see INSTALL.md Quick start §1.2 / §1.4 and `home seed-never-ban`.
8. If unsure which path: default to INSTALL.md **§1 Quick start**.
9. Do not invent CLI flags or asset names; only what appears in INSTALL.md / the repo CLI / release-assets.

---

## 2. Questions to ask first

Ask once, short multiple-choice where possible:

1. **Where?** One VPS/VDS (distro + version) / home Linux PC with desktop / several servers?
2. **Admin machine OS?** Linux / Windows / macOS — GUI available?
3. **Privileges?** root or sudo? SSH key or password? Public IP or CIDR for never_ban?
4. **Hardware?** Approx RAM, CPU, GPU (if any)?
5. **Goals?** SSH protection + alerts only / Telegram / web UI / desktop app / eBPF agent / Cloudflare Under Attack / own ML model?
6. **Experience?** Beginner or comfortable with Linux?

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
2. Match against INSTALL.md **Frequent problems**.
3. Do not guess past that list; open linked deep docs (FRIEND, DAY0_VPS, CONTROL_CENTER, SECURITY) only after naming which section you are using.

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
