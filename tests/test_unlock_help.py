from __future__ import annotations

from sysspectogram.unlock_help import locked_playbook


def test_locked_playbook_en_ru():
    en = locked_playbook(host_id="web1", lang="en")
    assert "LOCKED" in en and "web1" in en and "Unlock locked" in en
    ru = locked_playbook(host_id="web1", lang="ru")
    assert "LOCKED" in ru and "web1" in ru
