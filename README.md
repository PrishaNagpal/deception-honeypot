# Deception honeypot

Multi-service lab for the Computer Networks project: fake SSH (Cowrie), fake HTTP login/signup (Flask), fake FTP/SMB (Dionaea), on an isolated Docker bridge.

**Track A :** Weeks 1–2 are done.  
**Track B:** log parser (`services/log-parser`) — done, see [Log parser](#log-parser).  
**Track C:** AbuseIPDB / VirusTotal enrichment, Grafana dashboard, world map and phone alerts — built, see [Grafana dashboard and enrichment (Track C)](#grafana-dashboard-and-enrichment-track-c).  
**Week 5:** attack simulation (`scripts/simulate-attack.sh`) and `IOC_export.csv` (`scripts/export-ioc.sh`) — scripts ready, joint run and final report still to do.

Repo: https://github.com/User_name/deception-honeypot

## Track A status

| Deliverable | Status |
|---|---|
| Ubuntu (WSL 24.04) + free Docker Engine | Done |
| Isolated Compose bridge `honeypot_net` (`172.28.0.0/16`) | Done |
| Flask decoy (login + signup) logging JSON | Done |
| Cowrie SSH decoy, port 2222 | Done |
| Dionaea FTP/SMB decoy, ports 2121 / 1445 | Done |
| Ports bound to `127.0.0.1` only | Done |
| Log contract for Track B | Done (`docs/LOG_CONTRACT.md`) |
| Export Cowrie/Dionaea logs onto disk | Script: `scripts/export-logs.sh` |
| Week 5 attack simulation + report | Later, with the whole team |

There are **no real accounts**. The portal always rejects sign-in. Signup always says an admin must approve. Cowrie accepts any password into a **fake** shell.

## Safety

- Compose publishes only on `127.0.0.1`. Do not change that to `0.0.0.0`.
- Do not put this on a public IP or campus Wi-Fi without written permission.
- Rebuild if a container looks compromised: `sudo docker compose down && sudo docker compose up -d --build`.
- Test only against this lab, from this machine.

## What runs

| Service | Looks like | Open on this PC | Logs |
|---|---|---|---|
| Flask | Northstar employee portal | http://127.0.0.1:8080 | `data/flask/http.json` (live bind mount) |
| Cowrie | Linux SSH jump box | `ssh -p 2222 root@127.0.0.1` | Docker volume; copy out with `scripts/export-logs.sh` → `data/cowrie/log/` |
| Dionaea | FTP / SMB | FTP `2121`, SMB `1445` | Docker volume; copy out → `data/dionaea/` |

Host ports are not 22 / 80 / 445 so they do not collide with Windows.

## Start the lab (Ubuntu WSL — free Docker Engine)

Do **not** use paid Docker Desktop. In PowerShell:

```powershell
wsl -d Ubuntu-24.04
```

Then in Ubuntu (`lenovo@THINKPAD:...$`):

```bash
cd /mnt/c/Users/LENOVO/deception-honeypot
sudo service docker start
sudo docker compose up -d --build
sudo docker compose ps
```

`hp-flask` should show **healthy**.

Stop (still in Ubuntu):

```bash
sudo docker compose down
```

## How to test Flask (no real passwords)

1. Open http://127.0.0.1:8080
2. **Sign in** with anything, e.g. `admin` / `admin123`. You must see **Invalid username or password**.
3. Click **Create an account**. Submit any email / username / password. You must see **Account request submitted**.
4. Open `data/flask/http.json`. You should see `"path": "/login"` and `"path": "/signup"` lines with `user_agent` containing `Chrome` if you used the browser.

If the page looks old, press Ctrl+F5. If port 8080 is wrong, stop any local Python Flask and use the Docker container only.

## How to test Cowrie (optional)

```powershell
ssh -p 2222 -o StrictHostKeyChecking=no root@127.0.0.1
```

Any password. This is not your ThinkPad. Type `ls` or `exit`.

Then copy logs for Track B (Ubuntu):

```bash
bash scripts/export-logs.sh
```

## GitHub

Remote is already `https://github.com/PrishaNagpal/deception-honeypot.git`.  
Add teammates: repo **Settings → Collaborators**.


## For Track B

See `docs/LOG_CONTRACT.md`. Flask logs appear immediately under `data/flask/`. After SSH or FTP tests, run `scripts/export-logs.sh` so Cowrie and Dionaea files land under `data/`.

## Log parser

[![Log parser tests](https://github.com/PrishaNagpal/deception-honeypot/actions/workflows/log-parser-tests.yml/badge.svg)](https://github.com/PrishaNagpal/deception-honeypot/actions/workflows/log-parser-tests.yml)

On every push and pull request that touches `services/log-parser/`, `db/init.sql` or the workflow, GitHub Actions runs all parser tests, including the database tests against a temporary PostgreSQL 16 (`.github/workflows/log-parser-tests.yml`).

`services/log-parser` (container `hp-parser`) reads the three honeypot logs as they grow and writes one normalized row per attacker action into the `events` table in PostgreSQL (`hp-db`), as described in `db/init.sql`. Files Dionaea stores (downloads in `binaries/`, FTP uploads in `ftp/root/`, subfolders included) are hashed into `malware_samples`, and Cowrie download/upload events add their SHA-256 there too.

- It reads the live logs directly: the Cowrie and Dionaea volumes and `./data/flask`, all mounted read-only. No export script is needed.
- It checks the logs once a second, so new events reach the database within about a second.
- After a restart it continues where it stopped; nothing is stored twice.
- Every 60 seconds `docker logs hp-parser` shows a summary: lines read, rows inserted, lines already stored, skipped and malformed lines per honeypot.

### Run it

With the rest of the lab (needs `POSTGRES_USER` and `POSTGRES_PASSWORD` in `.env`):

```bash
docker compose up -d --build
docker logs -f hp-parser
```

Locally, without Docker (Node 22 via nvm; reads the copies under `data/`, connects to `127.0.0.1:5433`):

```bash
cd services/log-parser
nvm use
npm ci
npm run start:local
```

### Tests

```bash
cd services/log-parser
npm test            # all tests except the database ones
npm run test:db     # everything, against hp-db (reads the repo's .env)
```

The database tests build the tables from `db/init.sql` in a temporary schema and drop it afterwards, so the real tables are not touched.

### Environment variables

| Variable | In Docker | Local default |
|---|---|---|
| `PGHOST`, `PGPORT` | `hp-db`, `5432` | `127.0.0.1`, `5433` |
| `PGUSER`, `PGPASSWORD`, `PGDATABASE` | from `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` in `.env` | the same `POSTGRES_*` values |
| `FLASK_LOG` | `/logs/flask/http.json` | `data/flask/http.json` |
| `COWRIE_LOG` | `/logs/cowrie/cowrie.json` | `data/cowrie/log/cowrie.json` |
| `DIONAEA_LOG` | `/logs/dionaea/dionaea.json` | `data/dionaea/log/dionaea.json` |
| `DIONAEA_BINARIES_DIR` | `/logs/dionaea-lib/dionaea/binaries` | `data/dionaea/lib/dionaea/binaries` |
| `DIONAEA_UPLOADS_DIR` | `/logs/dionaea-lib/dionaea/ftp/root` | `data/dionaea/lib/dionaea/ftp/root` |
| `POLL_INTERVAL_MS`, `BINARIES_INTERVAL_MS`, `SUMMARY_INTERVAL_MS` | `1000`, `10000`, `60000` | same |
| `MAX_LINE_BYTES` | `1048576` (longer lines are skipped as malformed) | same |

Rotated Cowrie logs next to the live file (`cowrie.json.2026-10-13`) are read too. The password is never printed.

### After a reboot

Docker Desktop can start the containers before the WSL files are ready. `hp-flask` and `hp-parser` then see an empty `./data/flask` folder instead of the real one: Flask logins fail with HTTP 500, and the parser logs `waiting for file` for `/logs/flask/http.json`. Restart both once WSL is up:

```bash
docker restart hp-flask hp-parser
```

Check with a fake login on http://127.0.0.1:8080: a new line should appear in `data/flask/http.json`, and a new `http_login` row in `events` within a few seconds.

## Grafana dashboard and enrichment (Track C)

Open http://127.0.0.1:3000 and sign in as `admin` with `GRAFANA_ADMIN_PASSWORD` from `.env`. The dashboard **Honeypot - Live Attacks** refreshes every 5 seconds. Grafana reads the database as `grafana_ro`, a user that can only `SELECT` (`db/zz-grafana-user.sh`).

| Panel | Shows |
|---|---|
| Attacks over time | events per minute, one line per honeypot |
| Top passwords tried | the 10 most guessed passwords, all honeypots |
| Top commands | Cowrie shell and FTP commands |
| Live attack feed | latest 20 events, including Flask `tags` (`sqli_like`, `oversized_payload`) |
| Captured files (VirusTotal) | files the honeypots caught and how many antivirus engines flag them |
| Attacker origins (world map) | country of every public attacker IP, bigger circle = more attacks |
| Attacks by country | the same data as a table, with the worst AbuseIPDB score per country |

### `.env` values

Copy `.env.example` to `.env` and fill it in: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` (`honeypot`), `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_DB_PASSWORD`. Optional, for enrichment: `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` (free keys work). Optional, for phone alerts: Discord or Telegram values (below). Never commit `.env`.

### Enrichment (`services/enrichment`, container `hp-enrich`)

`enrich.py` runs a round every 30 seconds:

- **VirusTotal**: every file in `malware_samples` that has not been checked yet. A file VirusTotal has never seen is stored as `not found on VirusTotal` and not asked again. Free keys allow 4 requests a minute, so there is a 16 second pause between lookups.
- **AbuseIPDB**: every new IP in `events`, and any IP not checked for 7 days, into `ip_reputation`. **Private addresses (172.28.x.x, 10.x, 192.168.x, 127.x) are never sent to the API**; they are stored with `is_public = false`.
- If either API says "too many requests" (HTTP 429), the round stops and the remaining items are tried next round. Nothing crashes and nothing is lost.
- If `hp-db` restarts, the script drops the dead connection and reconnects (waiting 1, 2, 4 ... 30 seconds) instead of crashing.
- With an empty API key that service is skipped (a line in `docker logs hp-enrich` says so).

Look up one IP by hand:

```bash
docker compose exec enrichment python enrich.py abuse-ip 8.8.8.8
```

Tests (unit tests need nothing; the database tests build a temporary schema from `db/init.sql`, like the parser's):

```bash
cd services/enrichment
pip install -r requirements-dev.txt
python -m pytest                       # unit tests, database tests are skipped
PGHOST=127.0.0.1 PGPORT=5433 PGUSER=... PGPASSWORD=... PGDATABASE=honeypot python -m pytest   # everything
```

GitHub Actions runs both on every change to `services/enrichment/` (`.github/workflows/enrichment-tests.yml`).

### World map

The map uses the country that AbuseIPDB returns and Grafana's built-in country coordinates, so it needs **public** attacker IPs and an AbuseIPDB key. Attacks from this lab machine come from the Docker gateway (`172.28.0.1`), which has no location, so on a pure lab run the map is empty and says why.

To show the map in the demo, add clearly fake attackers (documentation IP ranges, made-up countries):

```bash
bash scripts/seed-demo-geo.sh            # add 12 demo attackers
bash scripts/seed-demo-geo.sh --remove   # delete them again
```

Remove them before taking final numbers. `IOC_export.csv` ignores them. Their events are marked `source_file = 'demo-seed'`.

### Phone alerts (Discord or Telegram)

Grafana sends a message when an attack starts and another when it is over, per honeypot (SSH, web portal, FTP/SMB): every 30 seconds each rule asks "did this honeypot log anything in the last minute?". One alert per honeypot per attack, repeated at most every 4 hours. Files: `grafana/provisioning/alerting/` (`contact-points.yml`, `rules.yml`, `policies.yml`).

Set up one of the two in `.env`:

- **Discord**: in a channel, Edit Channel, Integrations, Webhooks, New Webhook, copy the URL into `DISCORD_WEBHOOK_URL`.
- **Telegram**: message `@BotFather`, `/newbot`, put the token in `TELEGRAM_BOT_TOKEN`. Send your new bot any message, open `https://api.telegram.org/bot<TOKEN>/getUpdates` and put the `chat` `id` into `TELEGRAM_CHAT_ID`.

Then recreate Grafana so it reads the new values, and test:

```bash
docker compose up -d grafana
bash scripts/test-phone-alert.sh        # sends a test message straight to the phone
```

In Grafana, Alerting, Contact points, `phone-alerts`, Test, sends one through Grafana itself. The integration you leave empty logs a harmless "failed to send" line in `docker logs hp-grafana` when an alert fires; the other still delivers. Alert rules appear under Alerting, Alert rules, folder **Honeypot**.

Grafana's outbound access: the `grafana` container can reach Discord and Telegram through the normal Docker NAT. The honeypot containers still publish nothing beyond `127.0.0.1`.

## Week 5: attack simulation and IOC export

```bash
sudo apt install nmap hydra curl         # once
bash scripts/simulate-attack.sh          # Nmap scan, Hydra on SSH / FTP / web, SQLi + oversized + signup requests
bash scripts/export-ioc.sh               # writes IOC_export.csv
```

`simulate-attack.sh` can only aim at `127.0.0.1` (the lab's own ports); there is no option to change the target. It also accepts `scan`, `ssh`, `ftp` or `web` to run one part. Afterwards it prints how many events each honeypot recorded. Check the dashboard and the phone alert while it runs.

`IOC_export.csv` lists every attacker IP (with AbuseIPDB score and country), every captured file hash (with its VirusTotal verdict) and every URL an attacker made Cowrie download from. Columns: `ioc_type, value, first_seen, last_seen, event_count, services, abuse_score, country, vt_malicious, vt_label, note`. Run it after enrichment has had time to look everything up.

## Reset before a demo

`scripts/reset-demo.sh` empties the lab: no logs, no captured files, empty tables. It asks you to type `reset` first, because the data cannot be recovered.

```bash
bash scripts/reset-demo.sh
```

Logs and database are always cleared together. The log parser resumes from what the database has stored, so emptying only the database would make it import every old log line again, and deleting only the logs would leave old rows behind.

What it does:

1. Stops the stack and removes the containers with their unnamed volumes (Cowrie keeps its terminal recordings, downloaded files and SSH host keys there).
2. Removes the `cowrie_logs`, `dionaea_logs`, `dionaea_lib` and `pg_data` volumes.
3. Empties `data/flask/http.json` and deletes the copies under `data/cowrie` and `data/dionaea`. The `.gitkeep` files stay.
4. Starts everything again. `db/init.sql` recreates the empty tables, and the script waits until every container is running and `hp-db` and `hp-flask` are healthy, then shows the row counts (all 0).

Images and `.env` are kept. AbuseIPDB lookups in `ip_reputation` are deleted too, so they will be fetched again.

Stop a locally running parser (`npm run start:local`) first; the script refuses to run while one is active. `sudo` is only used if some files under `data/` belong to root (for example after `scripts/export-logs.sh`, which copies with `sudo`), and the script says so before using it.

Cowrie gets new SSH host keys. If `ssh` then refuses with "REMOTE HOST IDENTIFICATION HAS CHANGED" or disables password login, remove the old key:

```bash
ssh-keygen -R '[127.0.0.1]:2222'
```
