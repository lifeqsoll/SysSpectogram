from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


@dataclass
class ActionToken:
    action: str
    payload: dict
    exp: float
    nonce: str

    def encode(self, secret: str) -> str:
        body = json.dumps(
            {"a": self.action, "p": self.payload, "e": int(self.exp), "n": self.nonce},
            separators=(",", ":"),
            sort_keys=True,
        )
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()[:12]
        raw = f"{self.action}|{self.nonce}|{int(self.exp)}|{sig}"
        return raw[:64]


class TokenStore:
    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret or secrets.token_hex(16)
        self._payloads: dict[str, dict] = {}
        self._used: set[str] = set()

    def issue(self, action: str, payload: dict, ttl_sec: float = 600.0) -> str:
        nonce = secrets.token_hex(3)
        exp = time.time() + ttl_sec
        tok = ActionToken(action=action, payload=payload, exp=exp, nonce=nonce)
        token = tok.encode(self.secret)
        self._payloads[nonce] = {"action": action, "payload": payload, "exp": exp}
        return token

    def peek(self, token: str) -> tuple[str, dict] | None:
        parts = token.split("|")
        if len(parts) != 4:
            return None
        action, nonce, exp_s, _sig = parts
        try:
            exp = float(exp_s)
        except ValueError:
            return None
        if time.time() > exp:
            return None
        if nonce in self._used:
            return None
        meta = self._payloads.get(nonce)
        if not meta or meta["action"] != action:
            return None
        check = ActionToken(action, meta["payload"], meta["exp"], nonce).encode(self.secret)
        if not hmac.compare_digest(check, token):
            return None
        return action, meta["payload"]

    def consume(self, token: str) -> tuple[str, dict] | None:
        parsed = self.peek(token)
        if parsed is None:
            return None
        action, payload = parsed
        parts = token.split("|")
        self._used.add(parts[1])
        return action, payload
