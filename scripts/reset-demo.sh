#!/usr/bin/env bash
# Reset the lab to an empty state before a demo: no logs, no captured files,
# empty database tables.
#
# Logs and database must be cleared together. The log parser resumes from
# what the database says it has stored, so wiping only the database would make
# it re-import every old log line, and wiping only the logs would leave old
# rows behind.
#
# What it deletes:
#   - the Cowrie, Dionaea and PostgreSQL volumes: cowrie_logs, dionaea_logs,
#     dionaea_lib (captured files), pg_data (all tables)
#   - the containers' unnamed volumes; Cowrie keeps its terminal recordings,
#     downloaded files and SSH host keys in one
#   - data/flask/http.json (emptied, not deleted) and the exported copies under
#     data/cowrie and data/dionaea (the .gitkeep files stay)
# Images and the .env file are kept. Then everything is started again and
# db/init.sql recreates the empty tables.
#
# Usage: bash scripts/reset-demo.sh   (asks you to type "reset" first)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="$(sed -n 's/^name: *//p' docker-compose.yml)"
if [ -z "$PROJECT" ]; then
  echo "Could not read the project name from docker-compose.yml." >&2
  exit 1
fi
VOLUMES=(cowrie_logs dionaea_logs dionaea_lib pg_data)
CLEAR_DIRS=(data/cowrie data/dionaea)
FLASK_LOG=data/flask/http.json
HEALTH_TIMEOUT_S=120

# A parser started locally (npm run start:local) would refill the database
# from the copies under data/ while the reset is running.
if pgrep -f 'node .*src/index\.js' >/dev/null; then
  echo "A local log parser is running (node src/index.js). Stop it first:" >&2
  pgrep -af 'node .*src/index\.js' >&2
  exit 1
fi

echo "This deletes all captured attack data:"
echo "  - Docker volumes: ${VOLUMES[*]/#/${PROJECT}_}"
echo "  - the containers' unnamed volumes (Cowrie's recordings, downloads, SSH host keys)"
echo "  - $FLASK_LOG is emptied; files under ${CLEAR_DIRS[*]} are deleted (.gitkeep kept)"
if docker compose ps --status running --services 2>/dev/null | grep -qx postgres; then
  # </dev/null: docker compose exec would otherwise read the script's input,
  # swallowing the answer to the prompt below when it is piped in.
  docker compose exec -T postgres sh -c \
    'psql -X -At -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT
       (SELECT count(*) FROM events) || '"' events, '"' ||
       (SELECT count(*) FROM malware_samples) || '"' malware samples, '"' ||
       (SELECT count(*) FROM ip_reputation) || '"' IP lookups'"'"' </dev/null 2>/dev/null \
    | sed 's/^/  - database now holds: /' || true
fi
echo
read -r -p 'Type "reset" to continue: ' answer || answer=""
if [ "$answer" != "reset" ]; then
  echo "Nothing changed."
  exit 1
fi

# Files under data/ are normally yours. They can belong to root if they were
# copied out with `sudo docker cp` (scripts/export-logs.sh does that). Only
# then is sudo needed, and only to delete those files.
SUDO=()
not_writable="$(find "${CLEAR_DIRS[@]}" -mindepth 1 -type d ! -writable 2>/dev/null || true)"
if [ -e "$FLASK_LOG" ] && [ ! -w "$FLASK_LOG" ]; then
  not_writable+=$'\n'"$FLASK_LOG"
fi
if [ -n "${not_writable//[[:space:]]/}" ]; then
  echo
  echo "These are not writable by $(id -un), probably created with sudo docker cp:"
  echo "$not_writable" | sed '/^$/d; s/^/  /'
  echo "sudo will be used only to delete or empty them; it may ask for your password."
  SUDO=(sudo)
fi

echo
echo "==> Stopping the stack and removing containers with their unnamed volumes"
docker compose stop
docker compose rm --force --volumes
docker compose down --remove-orphans

echo "==> Removing volumes"
for volume in "${VOLUMES[@]}"; do
  name="${PROJECT}_${volume}"
  if docker volume inspect "$name" >/dev/null 2>&1; then
    docker volume rm "$name" >/dev/null
    echo "  removed $name"
  else
    echo "  $name did not exist"
  fi
done

echo "==> Clearing log copies under data/"
if [ -e "$FLASK_LOG" ]; then
  "${SUDO[@]}" truncate -s 0 "$FLASK_LOG"
  echo "  emptied $FLASK_LOG"
fi
for dir in "${CLEAR_DIRS[@]}"; do
  count="$(find "$dir" -mindepth 1 ! -type d ! -name .gitkeep | wc -l)"
  # Files first, then the folders left empty. Folders that still hold a
  # .gitkeep are not empty, so they stay.
  "${SUDO[@]}" find "$dir" -mindepth 1 ! -type d ! -name .gitkeep -delete
  "${SUDO[@]}" find "$dir" -mindepth 1 -type d -empty -delete
  echo "  $dir: deleted $count files"
done

echo "==> Starting the stack (db/init.sql recreates the tables)"
docker compose up -d

echo "==> Waiting for the containers"
deadline=$((SECONDS + HEALTH_TIMEOUT_S))
while :; do
  # Every service must be running, and every service with a healthcheck healthy.
  status="$(docker compose ps --all --format '{{.Name}} {{.State}} {{.Health}}')"
  pending="$(echo "$status" | awk '$2 != "running" || ($3 != "" && $3 != "healthy")')"
  [ -z "$pending" ] && break
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "Not ready after ${HEALTH_TIMEOUT_S}s:" >&2
    echo "$pending" >&2
    exit 1
  fi
  sleep 2
done
docker compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'

echo
echo "==> Database after reset"
docker compose exec -T postgres sh -c \
  'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT
     (SELECT count(*) FROM events) AS events,
     (SELECT count(*) FROM malware_samples) AS malware_samples,
     (SELECT count(*) FROM ip_reputation) AS ip_reputation"' </dev/null

echo "Done. The lab is empty and running."
echo "Cowrie has new SSH host keys. If ssh refuses with 'REMOTE HOST IDENTIFICATION"
echo "HAS CHANGED' or disables password login, forget the old key with:"
echo "  ssh-keygen -R '[127.0.0.1]:2222'"
