"""enrich.py against a real PostgreSQL. The tables are built from db/init.sql in
a temporary schema that is dropped afterwards, so real tables are never touched.

Runs when PGHOST is set (CI sets it). Set REQUIRE_DB_TESTS=1 to fail instead of
skip when it is missing. Locally:
  PGHOST=127.0.0.1 PGPORT=5433 PGUSER=... PGPASSWORD=... PGDATABASE=honeypot pytest
"""
import os
import pathlib
import uuid

import psycopg2
import pytest

import enrich

INIT_SQL = pathlib.Path(__file__).resolve().parents[3] / "db" / "init.sql"

if not os.environ.get("PGHOST"):
    if os.environ.get("REQUIRE_DB_TESTS") == "1":
        raise RuntimeError("REQUIRE_DB_TESTS=1 but PGHOST is not set")
    pytest.skip("PGHOST not set, skipping database tests", allow_module_level=True)


def raw_connect(schema=None):
    kw = dict(host=os.environ["PGHOST"], port=os.environ.get("PGPORT", "5432"),
              user=os.environ["PGUSER"], password=os.environ.get("PGPASSWORD", ""),
              dbname=os.environ["PGDATABASE"])
    if schema:
        kw["options"] = f"-c search_path={schema}"
    return psycopg2.connect(**kw)


@pytest.fixture()
def schema(monkeypatch):
    name = "enrich_test_" + uuid.uuid4().hex[:8]
    admin = raw_connect()
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f"CREATE SCHEMA {name}")
    c = raw_connect(name)
    with c.cursor() as cur:
        cur.execute(INIT_SQL.read_text())
    c.commit()
    c.close()
    monkeypatch.setattr(enrich, "VT_KEY", "vt-key")
    monkeypatch.setattr(enrich, "ABUSE_KEY", "abuse-key")
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    yield name
    with admin.cursor() as cur:
        cur.execute(f"DROP SCHEMA {name} CASCADE")
    admin.close()


def add_event(conn, ip, n):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO events (event_time, service, event_type, src_ip, raw,
                                   source_file, source_file_id, source_offset)
               VALUES (now(), 'flask-http', 'http_login', %s, '{}', 'f', 'fid', %s)""",
            (ip, n),
        )
    conn.commit()


def add_sample(conn, sha):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO malware_samples (sha256, service) VALUES (%s, 'dionaea')", (sha,))
    conn.commit()


def scalar(conn, sql, *args):
    with conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchone()[0]


class Resp:
    def __init__(self, status, payload=None):
        self.status_code, self._p = status, payload or {}

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(str(self.status_code))


def test_private_ips_are_stored_as_not_public_and_never_hit_the_api(schema, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")
    monkeypatch.setattr(enrich.requests, "get", boom)
    conn = raw_connect(schema)
    add_event(conn, "172.28.0.1", 1)
    add_event(conn, "172.28.0.1", 2)
    add_event(conn, "10.1.2.3", 3)
    enrich.run_abuse(conn)
    assert scalar(conn, "SELECT count(*) FROM ip_reputation") == 2
    assert scalar(conn, "SELECT count(*) FROM ip_reputation WHERE is_public = false") == 2
    # nothing left to do on the next round
    enrich.run_abuse(conn)
    assert scalar(conn, "SELECT count(*) FROM ip_reputation") == 2


def test_rate_limit_keeps_the_rest_unchecked_for_the_next_round(schema, monkeypatch):
    conn = raw_connect(schema)
    for i, ip in enumerate(["8.8.8.8", "1.1.1.1", "9.9.9.9"]):
        add_event(conn, ip, i)
    answers = iter([Resp(200, {"data": {"abuseConfidenceScore": 10, "countryCode": "US"}}),
                    Resp(429)])
    seen = []

    def fake_get(url, **k):
        seen.append(k["params"]["ipAddress"])
        return next(answers)

    monkeypatch.setattr(enrich.requests, "get", fake_get)
    enrich.run_abuse(conn)  # must not raise
    assert len(seen) == 2, "stopped at the 429 instead of trying the third IP"
    assert scalar(conn, "SELECT count(*) FROM ip_reputation") == 1
    # next round, limit gone: the other two are picked up
    monkeypatch.setattr(enrich.requests, "get",
                        lambda *a, **k: Resp(200, {"data": {"abuseConfidenceScore": 0, "countryCode": "DE"}}))
    enrich.run_abuse(conn)
    assert scalar(conn, "SELECT count(*) FROM ip_reputation") == 3


def test_vt_not_found_is_stored_and_not_asked_again(schema, monkeypatch):
    conn = raw_connect(schema)
    add_sample(conn, "c" * 64)
    calls = []
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: calls.append(1) or Resp(404))
    enrich.run_vt(conn)
    assert scalar(conn, "SELECT vt_threat_label FROM malware_samples") == "not found on VirusTotal"
    assert scalar(conn, "SELECT vt_checked_at IS NOT NULL FROM malware_samples") is True
    enrich.run_vt(conn)
    assert len(calls) == 1


def test_vt_rate_limit_leaves_the_file_unchecked(schema, monkeypatch):
    conn = raw_connect(schema)
    add_sample(conn, "d" * 64)
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: Resp(429))
    enrich.run_vt(conn)
    assert scalar(conn, "SELECT vt_checked_at IS NULL FROM malware_samples") is True


def test_loop_reconnects_after_the_database_connection_is_killed(schema, monkeypatch):
    """What happens when hp-db restarts: every connection is cut."""
    # connect() builds its own connection; make it use the temp schema
    monkeypatch.setattr(enrich, "connect", lambda: raw_connect(schema))
    conn = raw_connect(schema)
    add_event(conn, "172.28.0.1", 1)

    # cut the connection from outside, like a database restart would
    killer = raw_connect()
    killer.autocommit = True
    with killer.cursor() as cur:
        cur.execute("SELECT pg_terminate_backend(%s)", (conn.get_backend_pid(),))
    killer.close()

    conn = enrich.run_round(conn)  # must not raise
    assert not conn.closed, "a fresh connection came back"
    enrich.run_round(conn)         # and it works
    assert scalar(conn, "SELECT count(*) FROM ip_reputation") == 1
