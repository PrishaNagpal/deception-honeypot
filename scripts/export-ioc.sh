#!/usr/bin/env bash
# Writes IOC_export.csv (attacker IPs, captured file hashes, download URLs) from
# the database. Needs the stack running (docker compose up -d).
#
#   bash scripts/export-ioc.sh               -> IOC_export.csv in the repo root
#   bash scripts/export-ioc.sh some/file.csv -> somewhere else
#
# Run scripts/seed-demo-geo.sh --remove first if you used the demo map data (the
# export ignores demo rows anyway). Run enrichment first (`docker logs hp-enrich`
# should show lookups) so the AbuseIPDB / VirusTotal columns are filled.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${1:-IOC_export.csv}"

# Write to a temp file first: a failed export must not clobber a good one.
tmp="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
docker compose exec -T postgres sh -c \
  'psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < scripts/sql/ioc-export.sql > "$tmp"
mv "$tmp" "$OUT"
trap - EXIT

rows=$(( $(wc -l < "$OUT") - 1 ))
echo "Wrote $OUT: $rows indicators."
cut -d, -f1 "$OUT" | tail -n +2 | sort | uniq -c | sed 's/^/  /'
