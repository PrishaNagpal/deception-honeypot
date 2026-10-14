# Deception honeypot

Multi-service lab for the Computer Networks project: fake SSH (Cowrie), fake HTTP login/signup (Flask), fake FTP/SMB (Dionaea), on an isolated Docker bridge.

**Track A :** Weeks 1–2 are done.  
**Track B:** `log_parser.py` — not started.  
**Track C:** AbuseIPDB / VirusTotal + Grafana — not started.  
**Week 5:** joint tests, `IOC_export.csv`, final report — not started.

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
