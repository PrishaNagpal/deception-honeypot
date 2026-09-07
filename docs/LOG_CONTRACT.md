# JSON log contract for Track B (`log_parser.py`)

One JSON object per line. Do not rename these paths without a team sync. Track C enrichment keys are `src_ip` and file hashes.

## Flask HTTP — `data/flask/http.json`

Written live (bind mount). Login example:

```json
{
  "timestamp": "2026-09-07T08:35:42.511483+00:00",
  "service": "flask-http",
  "src_ip": "172.28.0.1",
  "method": "POST",
  "path": "/login",
  "username": "admin",
  "password": "admin123",
  "user_agent": "Mozilla/5.0",
  "tags": ["http_login"]
}
```

Signup POSTs use `"path": "/signup"`, include `email`, and `tags` contain `http_signup`.

`tags` may also include `sqli_like` or `oversized_payload`.

## Cowrie SSH — copy then read `data/cowrie/log/`

Cowrie writes inside a Docker volume (Windows bind mounts break its logger). After tests, from Ubuntu:

```bash
bash scripts/export-logs.sh
```

Then parse `data/cowrie/log/cowrie.json` (JSON lines). Useful fields:

- `timestamp`
- `src_ip`
- `username` / `password` on login events
- `message` / `input` for typed commands
- `eventid` (e.g. `cowrie.login.failed`, `cowrie.command.input`)

## Dionaea FTP/SMB — same export script

- Events: `data/dionaea/log/`
- Uploaded binaries: `data/dionaea/lib/` (hash these files)
