# FAQ (RU)

Краткие ответы. Полная установка: [INSTALL_RU.md](INSTALL_RU.md).

## Могу ли я забанить сам себя?

Да, если включить **soft/full/isolate** без вашего admin IP в `response.never_ban_cidrs`. Сначала never-ban, потом баны. Guard также не банит IP **активной SSH-сессии**, когда видит их. См. [FRIEND.md](FRIEND.md) и `home health`.

## Нужен ли логин для локального веб-дашборда?

Да для живых данных: `/api/status`, `/api/snapshot`, `/api/stream` требуют cookie-сессию (unlock-код в Settings) или Bearer из `state/web.token`. `/api/health` публичный (`ok` + длина кода). В LOCKED авторизованные ответы всё ещё редактируют bans/processes/allowlist.

## Почему protect остановился после выхода из SSH?

User systemd гасит сервисы без **linger**:

```bash
loginctl enable-linger "$USER"
```

Затем снова `python -m sysspectogram protect enable`.

## Что за подтверждение soft и откат?

При переходе в **soft** (и сильнее) может включиться **таймер отката**. Подтвердите в Control Center / Telegram / web, иначе режим вернётся в **observe**.

## Какой IP писать в never-ban (`ssh_source`)?

На VPS `${SSH_CONNECTION%% *}` — обычно **публичный IP вашего ноутбука**, а не исходящий IP сервера. С Windows на клиенте: `curl.exe -4 ifconfig.me`. Не используйте `seed-never-ban` без `--ip` на облаке.

## Нужен ли helper для soft auto-ban?

**Да** на friend-пути: guard без root банит через **sysspectogram-helper** (группа `sysspectogram`). Без helper/root `home health` покажет проблему `ban_backend` — оставайтесь на **observe**, пока helper не установлен.

## Как подписаны релизы?

**SHA256SUMS** и при публикации **minisign**. Скрипты friend-day0 не запускаются без проверки. [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [SECURITY.md](../SECURITY.md).

## Host ML для продакшена?

**Экспериментально.** Дефолт `runtime.prefer: onnx` (без артефактов — metrics-only); PyTorch на VPS не нужен. Сначала офлайн-оценка: [EVAL.md](EVAL.md).

## Как приглушить шум в Telegram (сканы / eBPF)?

**`/notify`** (или Menu → Notify): группы (`internet_noise`, `port_scans`, `agent_ebpf`, …), мин. severity, точечные rule id через `/notify ids`. Файл: `state/telegram_notify.json`. [TELEGRAM_RU.md](TELEGRAM_RU.md).

## Как обновить уже стоящий friend-стек?

```bash
export SYSSPECTOGRAM_HOME="${SYSSPECTOGRAM_HOME:-$HOME/.local/share/sysspectogram}"
source "$SYSSPECTOGRAM_HOME/.venv/bin/activate"
python -m sysspectogram home update --tag v1.5.0
systemctl --user restart sysspectogram-protect.service
```

[FRIEND.md](FRIEND.md) · [INSTALL_RU.md](INSTALL_RU.md).

## Сравнение с fail2ban / Wazuh?

[COMPARISON.md](COMPARISON.md) (EN).
