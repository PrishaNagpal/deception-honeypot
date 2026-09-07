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
