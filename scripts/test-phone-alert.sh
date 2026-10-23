#!/usr/bin/env bash
# Sends a test message to the phone channel(s) configured in .env, straight to
# Discord / Telegram, WITHOUT Grafana. Use it to check the webhook / bot works
# before waiting for a real attack. (In Grafana you can also use
# Alerting -> Contact points -> phone-alerts -> Test.)
#
# Runs on the host and sends to Discord / Telegram only (reads .env, nothing else).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Read only the three alert settings; .env may hold other values we don't need.
get() { sed -n "s/^$1=//p" .env 2>/dev/null | tail -n 1 | tr -d '\r'; }
DISCORD_WEBHOOK_URL="$(get DISCORD_WEBHOOK_URL)"
TELEGRAM_BOT_TOKEN="$(get TELEGRAM_BOT_TOKEN)"
TELEGRAM_CHAT_ID="$(get TELEGRAM_CHAT_ID)"
MSG="TEST from the deception honeypot: phone alerts work."

sent=0
if [ -n "$DISCORD_WEBHOOK_URL" ]; then
  echo "==> Discord"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
          -d "{\"content\": \"$MSG\"}" "$DISCORD_WEBHOOK_URL")"
  echo "    HTTP $code (204 = delivered)"
  sent=1
fi
if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
  echo "==> Telegram"
  code="$(curl -sS -o /dev/null -w '%{http_code}' \
          --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=$MSG" \
          "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage")"
  echo "    HTTP $code (200 = delivered)"
  sent=1
fi
if [ "$sent" = 0 ]; then
  echo "Nothing configured. Fill DISCORD_WEBHOOK_URL, or TELEGRAM_BOT_TOKEN and" >&2
  echo "TELEGRAM_CHAT_ID, in .env first." >&2
  exit 1
fi
