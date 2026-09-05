# Deception honeypot

Multi-service lab for the Computer Networks project: fake SSH (Cowrie), fake HTTP login (Flask), fake FTP/SMB (Dionaea), on an isolated Docker bridge.

**Track A (infrastructure):** this repo.  
**Track B:** parse JSON logs.  
**Track C:** AbuseIPDB / VirusTotal + Grafana.

## Safety

- Compose binds ports to `127.0.0.1` only. Nothing is published on campus Wi-Fi.
- Do not change binds to `0.0.0.0` and do not put this on a public IP without written permission.
- Treat containers as disposable. If one looks compromised: `docker compose down` then `docker compose up -d --build`.
- Only test against this lab, from this same machine.

## What runs

| Service | Looks like | Host port (localhost only) | Logs |
|---|---|---|---|
| Flask | Employee login portal | http://127.0.0.1:8080 | `data/flask/http.json` |
| Cowrie | Linux SSH box | `ssh -p 2222 root@127.0.0.1` | `data/cowrie/log/cowrie.json` |
| Dionaea | FTP / SMB | FTP `2121`, SMB `1445` | `data/dionaea/` |

Host ports are not 22/80/445 so they do not collide with Windows or a real SSH daemon.

## Run the full lab (Docker)

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/) and wait until it says running.
2. In this folder:

```powershell
docker compose up -d --build
docker compose ps
```

3. Open http://127.0.0.1:8080, submit a fake login, then open `data/flask/http.json`.
4. Optional SSH decoy: `ssh -p 2222 root@127.0.0.1` (any password; it is not a real shell).

Stop:

```powershell
docker compose down
```

## Run only Flask tonight (no Docker)

From this folder, with Python 3.10+:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r services\flask-honeypot\requirements.txt
$env:PORT = "8080"
$env:LOG_PATH = "$pwd\data\flask\http.json"
python services\flask-honeypot\app.py
```

Then open http://127.0.0.1:8080.

## GitHub (add teammates)

This folder is already a git repo. Create an empty GitHub repository named `deception-honeypot`, then:

```powershell
git remote add origin https://github.com/YOUR_USER/deception-honeypot.git
git push -u origin main
```

On GitHub: **Settings → Collaborators** → add the rest of the team.

## Ubuntu VM later

Copy this same folder into an Ubuntu VM. Install Docker Engine + Compose plugin, then the same `docker compose up -d --build` command. That matches the course write-up; Windows Docker Desktop is only so Track A can move now.
