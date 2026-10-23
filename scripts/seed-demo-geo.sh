#!/usr/bin/env bash
# Fills the world-map panel with DEMO attackers (fake public IPs from the
# reserved documentation ranges, made-up countries) so the map can be shown even
# though lab attacks only have private addresses. It is not real data.
#
#   bash scripts/seed-demo-geo.sh            add the demo attackers
#   bash scripts/seed-demo-geo.sh --remove   delete them again
#
# Remove them before the final IOC export / report numbers: IOC export already
# ignores them, but dashboards and counts include them while they are there.
# Needs the stack running (docker compose up -d). Uses the postgres superuser
# inside hp-db; Grafana's own user stays read-only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "${1:-}" in
  "")       file=scripts/sql/demo-geo-seed.sql;   what="Adding demo attackers" ;;
  --remove) file=scripts/sql/demo-geo-remove.sql; what="Removing demo attackers" ;;
  *) echo "Usage: bash scripts/seed-demo-geo.sh [--remove]" >&2; exit 1 ;;
esac

echo "==> $what"
docker compose exec -T postgres sh -c \
  'psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "$file"
if [ "${1:-}" = "--remove" ]; then
  echo "Done. Demo attackers removed."
else
  echo "Done. Open http://127.0.0.1:3000 - the map fills within the 5 s refresh."
  echo "These are FAKE attackers. Remove with: bash scripts/seed-demo-geo.sh --remove"
fi
