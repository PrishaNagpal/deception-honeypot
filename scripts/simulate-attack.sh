#!/usr/bin/env bash
# Week 5 attack simulation: Nmap port scan + Hydra password guessing + a few web
# attacks against the lab, to check that every attack shows up in the database,
# on the dashboard and as a phone alert.
#
# ONLY attacks this machine (127.0.0.1, the ports the lab publishes). There is no
# option to aim it anywhere else, on purpose.
#
#   bash scripts/simulate-attack.sh            run everything
#   bash scripts/simulate-attack.sh scan       just the Nmap scan
#   bash scripts/simulate-attack.sh ssh|ftp|web   just that part
#
# Needs: nmap, hydra, curl (sudo apt install nmap hydra curl) and the stack
# running (docker compose up -d). Watch http://127.0.0.1:3000 while it runs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET=127.0.0.1
SSH_PORT=2222; HTTP_PORT=8080; FTP_PORT=2121; SMB_PORT=1445
USERS=scripts/wordlists/users.txt
PASSES=scripts/wordlists/passwords.txt
PART="${1:-all}"

need() { command -v "$1" >/dev/null || { echo "Missing '$1'. Install: sudo apt install $1" >&2; exit 1; }; }
step() { echo; echo "==> $*"; }

db_counts() {
  docker compose exec -T postgres sh -c \
    'psql -X -At -F " | " -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
       SELECT service, count(*) FROM events WHERE source_file <> '"'"'demo-seed'"'"' GROUP BY service ORDER BY service"' \
    </dev/null 2>/dev/null || echo "(could not read the database: is the stack running?)"
}

run_scan() {
  need nmap
  step "Nmap: port + service scan of the four lab ports"
  nmap -Pn -sV -p "$SSH_PORT,$HTTP_PORT,$FTP_PORT,$SMB_PORT" "$TARGET"
}

run_ssh() {
  need hydra
  step "Hydra: SSH password guessing against Cowrie (port $SSH_PORT)"
  # -t 4: SSH servers dislike many parallel tries. No -f: keep guessing so there
  # are many events even though Cowrie lets some logins "succeed".
  hydra -L "$USERS" -P "$PASSES" -s "$SSH_PORT" -t 4 "ssh://$TARGET" || true
}

run_ftp() {
  need hydra
  step "Hydra: FTP password guessing against Dionaea (port $FTP_PORT)"
  hydra -L "$USERS" -P "$PASSES" -s "$FTP_PORT" -t 4 "ftp://$TARGET" || true
}

run_web() {
  need hydra; need curl
  step "Hydra: web login guessing against the Flask portal (port $HTTP_PORT)"
  hydra -L "$USERS" -P "$PASSES" -s "$HTTP_PORT" -t 4 "$TARGET" http-post-form \
    "/login:username=^USER^&password=^PASS^:F=Invalid username or password" || true

  step "curl: SQL-injection-looking login, an oversized password and a signup"
  curl -s -o /dev/null -w "  sqli login      -> HTTP %{http_code}\n" \
    --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=' OR 1=1 --" \
    "http://$TARGET:$HTTP_PORT/login"
  curl -s -o /dev/null -w "  oversized login -> HTTP %{http_code}\n" \
    --data-urlencode "username=admin" --data-urlencode "password=$(printf 'A%.0s' {1..200})" \
    "http://$TARGET:$HTTP_PORT/login"
  curl -s -o /dev/null -w "  signup          -> HTTP %{http_code}\n" \
    --data-urlencode "email=attacker@example.com" --data-urlencode "username=newadmin" \
    --data-urlencode "password=Passw0rd!" "http://$TARGET:$HTTP_PORT/signup"
}

case "$PART" in
  all)  run_scan; run_ssh; run_ftp; run_web ;;
  scan) run_scan ;;
  ssh)  run_ssh ;;
  ftp)  run_ftp ;;
  web)  run_web ;;
  *) echo "Usage: bash scripts/simulate-attack.sh [all|scan|ssh|ftp|web]" >&2; exit 1 ;;
esac

step "Done. Give the parser a few seconds, then events per honeypot in the database:"
sleep 5
db_counts
echo
echo "Check: dashboard http://127.0.0.1:3000 | phone alert | then run scripts/export-ioc.sh"
echo "(Attacks come from this machine, so the source IP is the Docker gateway 172.28.0.1:"
echo " private, so no country. Use scripts/seed-demo-geo.sh to show the world map.)"
