# JSON log contract for Track B (log_parser.py)

Parser should tail these files and emit one record per JSON line.

## Flask HTTP — `data/flask/http.json`

```json
{
  "timestamp": "2026-09-05T18:00:00+00:00",
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

`tags` may also include `sqli_like` or `oversized_payload`.

## Cowrie SSH — `data/cowrie/log/cowrie.json`

Cowrie writes JSON lines. Fields B will care about:

- `timestamp`
- `src_ip`
- `username` / `password` on login events
- `message` / `input` for typed commands
- `eventid` (e.g. `cowrie.login.failed`, `cowrie.command.input`)

## Dionaea FTP/SMB — `data/dionaea/log/` and `data/dionaea/lib/`

- Connection / protocol events under the log directory
- Uploaded binaries under the lib/binaries path (hash these files)

Do not change these paths without a team sync. Track C enrichment keys are `src_ip` and file hashes.
