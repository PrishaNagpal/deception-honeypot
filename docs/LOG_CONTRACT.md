# JSON log contract for Track B (log_parser.py)

Parser should tail these files and emit one record per JSON line. Do not change these paths without a team sync. Track C enrichment keys are `src_ip` and file hashes.

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

## Dionaea FTP/SMB — `data/dionaea/log/dionaea.json`

JSON lines, copied out by `scripts/export-logs.sh`. A record is written when the connection closes.

Useful fields:

- `timestamp` (ISO 8601, no timezone suffix, container time)
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `connection.protocol` (e.g. `ftpd`) and `connection.type` (`accept` = real attacker connection)
- `ftp.commands[]` with `command` and `arguments`
- `credentials[]` with `username` and `password` (a record can hold several)

Parser notes:

- Skip records where `connection.type` is `listen` (empty `src_ip`, noise).
- There is no `service` field. Set `service: "dionaea"` in the parser.
- SMB and file-download record shapes are not captured yet. Add a sample after testing those.
- Uploaded binaries are in `data/dionaea/lib/`. Hash them for Track C.
