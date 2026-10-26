"""Fleet Telegram bot on the admin hub — scope picker + fan-out ops.

Uses FLEET_TELEGRAM_BOT_TOKEN + FLEET_TELEGRAM_CHAT_ID (or TELEGRAM_* fallback).
Optional FLEET_TELEGRAM_ALLOW_USERS: comma-separated **user** IDs only (positive).
Group/channel IDs in the allowlist are ignored — they must never grant “anyone in
this chat”. Groups require a non-empty user allowlist. Per-VPS bots remain separate.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from sysspectogram.config import load_dotenv
from sysspectogram.console_unlock import ConsoleUnlock
from sysspectogram.fleet.ops import attack, release, status_many, unlock_locked
from sysspectogram.fleet.store import FleetStore
from sysspectogram.notify_telegram import TelegramClient
from sysspectogram.unlock_help import locked_playbook


def _btn(text: str, data: str) -> dict:
    return {"text": text[:40], "callback_data": data[:64]}


def _markup(rows: list[list[dict]]) -> dict:
    return {"inline_keyboard": rows}


def parse_allow_users(raw: str | None = None) -> frozenset[str]:
    """Comma-separated Telegram IDs from env (raw tokens; filter with user_allow_ids)."""
    text = raw if raw is not None else os.environ.get("FLEET_TELEGRAM_ALLOW_USERS", "")
    return frozenset(p.strip() for p in str(text or "").split(",") if p.strip())


def user_allow_ids(raw: frozenset[str] | None = None) -> frozenset[str]:
    """Positive Telegram user IDs only — drop group/channel (negative) entries."""
    src = raw if raw is not None else parse_allow_users()
    out: set[str] = set()
    for item in src:
        s = str(item).strip()
        if not s or s.startswith("-"):
            continue
        try:
            if int(s) <= 0:
                continue
        except ValueError:
            continue
        out.add(s)
    return frozenset(out)


def _row_field(row: dict[str, Any], key: str, default: Any = None) -> Any:
    """FleetOpReport puts extras under detail — also accept flat legacy keys."""
    if key in row and row.get(key) is not None:
        return row.get(key)
    detail = row.get("detail")
    if isinstance(detail, dict) and key in detail:
        return detail.get(key)
    return default


class FleetTelegramBot:
    def __init__(
        self,
        client: TelegramClient,
        store: FleetStore,
        *,
        identity: str | None = None,
        unlock: ConsoleUnlock | None = None,
        allow_users: frozenset[str] | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.identity = identity
        self.unlock = unlock or ConsoleUnlock(
            enabled=True,
            ttl_sec=0,
            persist_path=Path.home() / ".config" / "sysspectogram" / "fleet.unlock",
        )
        raw_allow = allow_users if allow_users is not None else parse_allow_users()
        self.allow_users = raw_allow
        self.user_ids = user_allow_ids(raw_allow)
        self.scope: str = "all"
        self._offset: int | None = None
        self._busy = False
        self._pending_l3: dict[str, Any] | None = None

    def prefix(self, text: str) -> str:
        return f"[fleet:{self.scope}]\n{text}"

    @staticmethod
    def _is_group_chat(chat_id: Any, chat_type: str | None = None) -> bool:
        """Telegram group/supergroup/channel IDs are negative; channels also by type."""
        ctype = (chat_type or "").strip().lower()
        if ctype in ("group", "supergroup", "channel"):
            return True
        s = str(chat_id or "").strip()
        if s.startswith("-"):
            return True
        try:
            return int(s) < 0
        except ValueError:
            return False

    def allowed(
        self,
        chat_id: Any,
        user_id: Any = None,
        *,
        chat_type: str | None = None,
    ) -> bool:
        """Gate: configured chat + (for groups / allowlist) matching **user** id.

        Putting a group chat ID into FLEET_TELEGRAM_ALLOW_USERS does **not**
        authorize every member — only positive user IDs count. Channels are
        treated as groups (never as a private DM).
        """
        chat_s = str(chat_id or "")
        user_s = str(user_id or "").strip() if user_id is not None else ""
        configured = str(self.client.chat_id or "")
        if chat_s != configured:
            return False
        if self._is_group_chat(chat_s, chat_type):
            if not self.user_ids:
                return False
            return bool(user_s) and user_s in self.user_ids
        # Private DM with the configured chat — require a concrete user id.
        if not user_s:
            return False
        if self.user_ids:
            return user_s in self.user_ids
        # No allowlist: sole DM peer (chat_id == user_id for private chats).
        return user_s == chat_s

    def mutating_allowed(self, chat_id: Any, user_id: Any = None) -> bool:
        """Same as allowed — groups already require a user allowlist."""
        return self.allowed(chat_id, user_id)

    def scope_keyboard(self) -> dict:
        st = self.store.load()
        rows: list[list[dict]] = [[_btn("ALL fleet", "scope|all")]]
        row: list[dict] = []
        for h in st.hosts:
            star = "★ " if h.id == st.primary_host_id else ""
            row.append(_btn(f"{star}{h.label}"[:28], f"scope|{h.id}"))
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        rows.append(
            [
                _btn("Status", "cmd|status"),
                _btn("Unlock locked", "cmd|unlock"),
                _btn("Release", "cmd|release"),
            ]
        )
        rows.append(
            [
                _btn("Attack L2", "cmd|attack_L2"),
                _btn("Attack L3", "cmd|attack_L3"),
            ]
        )
        return _markup(rows)

    def handle_command(
        self,
        text: str,
        chat_id: str,
        user_id: str | None = None,
        *,
        chat_type: str | None = None,
    ) -> None:
        if not self.allowed(chat_id, user_id, chat_type=chat_type):
            return
        parts = text.strip().split()
        if not parts:
            return
        cmd = parts[0].split("@")[0].lower()
        args = parts[1:]

        if cmd == "/unlock":
            if not args:
                self.client.send_message(
                    self.prefix("usage: /unlock <hub console code from admin PC>"),
                    chat_id=chat_id,
                )
                return
            if self.unlock.try_unlock(args[0]):
                self.client.send_message(
                    self.prefix("fleet hub UNLOCKED (session stays open until /lock)"),
                    chat_id=chat_id,
                )
            else:
                self.client.send_message(self.prefix("bad/expired hub unlock code"), chat_id=chat_id)
            return
        if cmd == "/lock":
            self.unlock.lock()
            self.client.send_message(self.prefix("fleet hub LOCKED"), chat_id=chat_id)
            return
        if cmd in ("/start", "/help", "/menu", "/fleet"):
            st = self.store.load()
            self.client.send_message(
                self.prefix(
                    "Fleet bot — pick a host or ALL, then Status / Attack / Release.\n"
                    f"hosts={len(st.hosts)} primary={st.primary_host_id or '-'}\n"
                    "Per-VPS bots still work for a single machine.\n"
                    "/unlock <code> once on this hub (not every morning)."
                ),
                chat_id=chat_id,
                reply_markup=self.scope_keyboard(),
            )
            return

        if not self.unlock.unlocked():
            self.client.send_message(
                self.prefix(
                    "Fleet hub LOCKED.\n"
                    "On the admin PC: cat ~/.config/sysspectogram/fleet.unlock is session marker;\n"
                    "get a fresh code from the fleet-tg console / state file shown at start,\n"
                    "then /unlock CODE here.\n"
                    "Or use each VPS bot directly if those sessions are already unlocked."
                ),
                chat_id=chat_id,
            )
            return

        if cmd == "/use" and args:
            self.scope = args[0]
            self.client.send_message(
                self.prefix(f"scope set to {self.scope}"),
                chat_id=chat_id,
                reply_markup=self.scope_keyboard(),
            )
            return
        if cmd in ("/status",):
            self._run_status(chat_id)
            return
        if cmd in ("/unlock_locked", "/unlock-locked"):
            self._run_unlock(chat_id)
            return
        if cmd == "/attack":
            level = (args[0] if args else "L2").upper()
            self._run_attack(chat_id, level, user_id=user_id)
            return
        if cmd == "/confirm_l3":
            pend = self._pending_l3
            pend_user = str(pend.get("user_id") or "") if pend else ""
            req_user = str(user_id or "")
            expired = bool(pend) and time.time() - float(pend.get("ts") or 0) > 60
            if not pend or expired:
                if expired:
                    self._pending_l3 = None
                self.client.send_message(
                    self.prefix("no pending L3 confirm (or expired)"),
                    chat_id=chat_id,
                )
                return
            if str(pend.get("chat_id")) != str(chat_id) or not pend_user or not req_user or pend_user != req_user:
                # Keep pending so the rightful user can still confirm.
                self.client.send_message(
                    self.prefix("no pending L3 confirm (or expired / wrong user)"),
                    chat_id=chat_id,
                )
                return
            # Consume only after the same user+chat passes.
            self._pending_l3 = None
            self.scope = str(pend.get("scope") or self.scope)
            self.client.send_message(self.prefix(f"ATTACK L3 on {self.scope}…"), chat_id=chat_id)

            def job() -> None:
                r = attack(self.store, self.scope, level="L3", identity=self.identity)
                lines = [f"level={r.get('level')}"]
                for row in r.get("results") or []:
                    hid = row.get("host_id")
                    if row.get("ok"):
                        lines.append(f"· {hid}: {_row_field(row, 'result') or 'ok'}")
                    else:
                        lines.append(f"· {hid}: {row.get('error')}")
                self.client.send_message(self.prefix("\n".join(lines)[:3800]), chat_id=chat_id)

            threading.Thread(target=job, daemon=True).start()
            return
        if cmd == "/release":
            self._run_release(chat_id)
            return
        self.client.send_message(self.prefix("unknown — /menu"), chat_id=chat_id)

    def handle_callback(self, cq: dict) -> None:
        chat = (cq.get("message") or {}).get("chat") or {}
        chat_id = str(chat.get("id", ""))
        chat_type = str(chat.get("type") or "") or None
        from_user = cq.get("from") or {}
        user_id = str(from_user.get("id", "") or "") or None
        if not self.allowed(chat_id, user_id, chat_type=chat_type):
            self.client.answer_callback(cq.get("id", ""), "unauthorized")
            return
        data = cq.get("data") or ""
        cq_id = cq.get("id", "")
        if data.startswith("scope|"):
            self.scope = data.split("|", 1)[1]
            self.client.answer_callback(cq_id, self.scope)
            self.client.send_message(
                self.prefix(f"scope={self.scope}"),
                chat_id=chat_id,
                reply_markup=self.scope_keyboard(),
            )
            return
        if not self.unlock.unlocked():
            self.client.answer_callback(cq_id, "locked")
            self.handle_command("/status", chat_id, user_id=user_id, chat_type=chat_type)
            self.client.send_message(self.prefix("LOCKED — /unlock first"), chat_id=chat_id)
            return
        if data == "cmd|status":
            self.client.answer_callback(cq_id, "status")
            self._run_status(chat_id)
        elif data == "cmd|unlock":
            self.client.answer_callback(cq_id, "unlock")
            self._run_unlock(chat_id)
        elif data == "cmd|release":
            self.client.answer_callback(cq_id, "release")
            self._run_release(chat_id)
        elif data.startswith("cmd|attack_"):
            level = data.split("_", 1)[1]
            self.client.answer_callback(cq_id, level)
            self._run_attack(chat_id, level, user_id=user_id)
        else:
            self.client.answer_callback(cq_id, "ok")

    def _run_status(self, chat_id: str) -> None:
        self.client.send_message(self.prefix("status…"), chat_id=chat_id)

        def job() -> None:
            r = status_many(self.store, self.scope, identity=self.identity)
            lines = [f"online {r.get('online')}/{r.get('n')}"]
            for row in r.get("results") or []:
                hid = row.get("host_id") or "?"
                if row.get("ok"):
                    st = _row_field(row, "status") or {}
                    unlocked = st.get("control_unlocked", "?") if isinstance(st, dict) else "?"
                    lines.append(f"· {hid}: ok unlocked={unlocked}")
                else:
                    lines.append(f"· {hid}: FAIL {row.get('error')}")
            self.client.send_message(self.prefix("\n".join(lines)[:3500]), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def _run_unlock(self, chat_id: str) -> None:
        self.client.send_message(self.prefix("unlock-locked…"), chat_id=chat_id)

        def job() -> None:
            r = unlock_locked(self.store, self.scope, identity=self.identity)
            lines = [f"done {r.get('unlocked_or_skipped')}/{r.get('n')}"]
            for row in r.get("results") or []:
                hid = row.get("host_id")
                if row.get("ok"):
                    skip = _row_field(row, "skipped")
                    lines.append(f"· {hid}: ok" + (" (skip)" if skip else ""))
                else:
                    lines.append(f"· {hid}: {row.get('error')}")
                    help_txt = _row_field(row, "help")
                    if help_txt:
                        lines.append(str(help_txt)[:800])
            self.client.send_message(self.prefix("\n".join(lines)[:3800]), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def _run_attack(self, chat_id: str, level: str, *, user_id: str | None = None) -> None:
        level_u = (level or "L2").upper()
        if level_u == "L3":
            uid = str(user_id or "").strip()
            if not uid:
                self.client.send_message(
                    self.prefix("L3 requires a Telegram user id (cannot confirm anonymously)"),
                    chat_id=chat_id,
                )
                return
            # Second gate: same user must reply /confirm_l3 within 60s.
            # Do not let a second user overwrite another operator's pending confirm.
            pend = self._pending_l3
            if (
                pend
                and str(pend.get("chat_id")) == str(chat_id)
                and time.time() - float(pend.get("ts") or 0) <= 60
                and str(pend.get("user_id") or "") not in ("", uid)
            ):
                self.client.send_message(
                    self.prefix(
                        f"L3 confirm already pending for another user "
                        f"(expires in {max(0, int(60 - (time.time() - float(pend.get('ts') or 0))))}s)"
                    ),
                    chat_id=chat_id,
                )
                return
            self._pending_l3 = {
                "chat_id": str(chat_id),
                "user_id": uid,
                "scope": self.scope,
                "ts": time.time(),
            }
            self.client.send_message(
                self.prefix(
                    f"Confirm ATTACK L3 on scope={self.scope}: "
                    f"same user reply /confirm_l3 within 60s"
                ),
                chat_id=chat_id,
            )
            return
        self.client.send_message(self.prefix(f"ATTACK {level_u} on {self.scope}…"), chat_id=chat_id)

        def job() -> None:
            r = attack(self.store, self.scope, level=level_u, identity=self.identity)
            lines = [f"level={r.get('level')}"]
            for row in r.get("results") or []:
                hid = row.get("host_id")
                if row.get("ok"):
                    lines.append(f"· {hid}: {_row_field(row, 'result') or 'ok'}")
                else:
                    lines.append(f"· {hid}: {row.get('error')}")
                    help_txt = _row_field(row, "help") or (
                        locked_playbook(host_id=str(hid)) if row.get("error") == "LOCKED" else ""
                    )
                    if help_txt:
                        lines.append(str(help_txt)[:900])
            self.client.send_message(self.prefix("\n".join(lines)[:3800]), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def _run_release(self, chat_id: str) -> None:
        self.client.send_message(self.prefix("release…"), chat_id=chat_id)

        def job() -> None:
            r = release(self.store, self.scope, identity=self.identity)
            lines = []
            for row in r.get("results") or []:
                lines.append(f"· {row.get('host_id')}: ok={row.get('ok')}")
            self.client.send_message(self.prefix("\n".join(lines)[:3500]), chat_id=chat_id)

        threading.Thread(target=job, daemon=True).start()

    def poll_forever(self) -> None:
        code_path = Path.home() / ".config" / "sysspectogram" / "fleet.hub_unlock.code"
        if self.unlock.pending_code:
            from sysspectogram.secret_file import write_secret_file

            write_secret_file(code_path, self.unlock.pending_code + "\n")
            print(f"FLEET HUB UNLOCK CODE saved to {code_path} (not Telegram)", flush=True)

        def on_code(c: str | None) -> None:
            if c:
                from sysspectogram.secret_file import write_secret_file

                write_secret_file(code_path, c + "\n")
            elif code_path.exists():
                code_path.unlink(missing_ok=True)

        self.unlock.on_code = on_code
        while True:
            try:
                updates = self.client.get_updates(offset=self._offset, timeout=25)
            except Exception:
                time.sleep(2)
                continue
            for u in updates or []:
                self._offset = int(u.get("update_id", 0)) + 1
                if "message" in u or "channel_post" in u:
                    msg = u.get("message") or u.get("channel_post") or {}
                    text = msg.get("text") or ""
                    chat = msg.get("chat") or {}
                    chat_id = str(chat.get("id") or "")
                    chat_type = str(chat.get("type") or "") or None
                    from_user = msg.get("from") or {}
                    user_id = str(from_user.get("id", "") or "") or None
                    if text:
                        self.handle_command(
                            text, chat_id, user_id=user_id, chat_type=chat_type
                        )
                elif "callback_query" in u:
                    self.handle_callback(u["callback_query"])


def run_fleet_bot(*, store_path: Path | None = None, identity: str | None = None) -> int:
    load_dotenv()
    token = os.environ.get("FLEET_TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("FLEET_TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")
    client = TelegramClient(token=token, chat_id=chat)
    if not client.configured:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "set FLEET_TELEGRAM_BOT_TOKEN and FLEET_TELEGRAM_CHAT_ID",
                }
            )
        )
        return 2
    store = FleetStore(store_path)
    allow = parse_allow_users()
    bot = FleetTelegramBot(client, store, identity=identity, allow_users=allow)
    print(
        json.dumps(
            {
                "ok": True,
                "hosts": len(store.load().hosts),
                "allow_users_raw": sorted(allow),
                "allow_user_ids": sorted(bot.user_ids),
                "hint": "polling; FLEET_TELEGRAM_ALLOW_USERS = user IDs only",
            }
        )
    )
    bot.poll_forever()
    return 0
