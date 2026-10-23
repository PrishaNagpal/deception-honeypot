"""Unit tests for enrich.py. No database, no network: requests.get is replaced
and the database is a small fake. The real-database tests are in test_enrich_db.py."""
import psycopg2
import pytest

import enrich


# ---------------------------------------------------------------- fakes
class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code}")


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.executed.append((" ".join(sql.split()), params))
        self._rows = self.conn.select_rows if sql.lstrip().upper().startswith("SELECT") else []

    def fetchall(self):
        return self._rows


class FakeConn:
    """Returns select_rows for every SELECT and records everything else."""

    def __init__(self, select_rows=()):
        self.select_rows = [(r,) if not isinstance(r, tuple) else r for r in select_rows]
        self.executed = []
        self.commits = 0
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True

    def writes(self):
        return [e for e in self.executed if not e[0].upper().startswith("SELECT")]


@pytest.fixture(autouse=True)
def no_real_network_or_sleep(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("test tried to reach the network")

    monkeypatch.setattr(enrich.requests, "get", boom)
    monkeypatch.setattr(enrich.time, "sleep", lambda s: None)
    monkeypatch.setattr(enrich, "VT_KEY", "vt-key")
    monkeypatch.setattr(enrich, "ABUSE_KEY", "abuse-key")


# ---------------------------------------------------------------- is_public
@pytest.mark.parametrize("ip", ["172.28.0.1", "10.0.0.5", "192.168.1.9", "127.0.0.1",
                                "0.0.0.0", "169.254.1.1", "::1", "fe80::1"])
def test_private_addresses_are_not_public(ip):
    assert enrich.is_public(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_public_addresses_are_public(ip):
    assert enrich.is_public(ip) is True


# ---------------------------------------------------------------- AbuseIPDB
def test_private_ip_is_skipped_without_calling_the_api():
    # the autouse fixture makes any HTTP call fail the test
    row = enrich.abuse_lookup("172.28.0.1")
    assert row["is_public"] is False
    assert row["ip"] == "172.28.0.1"
    assert row["abuse_confidence_score"] is None
    assert row["country_code"] is None
    assert row["raw"] is None


def test_public_ip_is_parsed(monkeypatch):
    payload = {"data": {"abuseConfidenceScore": 87, "totalReports": 12, "countryCode": "CN",
                        "countryName": "China", "isp": "Example ISP", "domain": "example.cn",
                        "usageType": "Data Center", "lastReportedAt": "2026-10-20T10:00:00+00:00"}}
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: FakeResponse(200, payload))
    row = enrich.abuse_lookup("8.8.8.8")
    assert row["is_public"] is True
    assert row["abuse_confidence_score"] == 87
    assert row["country_code"] == "CN"


def test_abuse_rate_limit_returns_none(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: FakeResponse(429))
    assert enrich.abuse_lookup("8.8.8.8") is None


def test_run_abuse_stops_the_round_on_rate_limit(monkeypatch):
    conn = FakeConn(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        if ip == "8.8.8.8":
            return {"ip": ip, "is_public": True, "abuse_confidence_score": 5}
        return None  # rate limited from the second IP on

    stored = []
    monkeypatch.setattr(enrich, "abuse_lookup", fake_lookup)
    monkeypatch.setattr(enrich, "store_ip", lambda c, row: stored.append(row["ip"]))
    enrich.run_abuse(conn)  # must not raise
    assert calls == ["8.8.8.8", "1.1.1.1"], "the third IP must not be tried after the 429"
    assert stored == ["8.8.8.8"]


def test_run_abuse_survives_a_network_error_on_one_ip(monkeypatch):
    import requests
    conn = FakeConn(["8.8.8.8", "1.1.1.1"])

    def fake_lookup(ip):
        if ip == "8.8.8.8":
            raise requests.ConnectionError("down")
        return {"ip": ip, "is_public": True, "abuse_confidence_score": 1}

    stored = []
    monkeypatch.setattr(enrich, "abuse_lookup", fake_lookup)
    monkeypatch.setattr(enrich, "store_ip", lambda c, row: stored.append(row["ip"]))
    enrich.run_abuse(conn)
    assert stored == ["1.1.1.1"]


def test_run_abuse_without_key_still_records_private_ips_but_skips_public(monkeypatch):
    monkeypatch.setattr(enrich, "ABUSE_KEY", "")
    conn = FakeConn(["172.28.0.1", "8.8.8.8"])
    stored = []
    monkeypatch.setattr(enrich, "store_ip", lambda c, row: stored.append(row["ip"]))
    enrich.run_abuse(conn)
    assert stored == ["172.28.0.1"]


# ---------------------------------------------------------------- VirusTotal
SHA = "a" * 64


def test_vt_not_found_is_stored_as_checked(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: FakeResponse(404))
    r = enrich.vt_lookup(SHA)
    assert r["vt_threat_label"] == "not found on VirusTotal"
    assert r["vt_malicious"] is None
    assert r["vt_permalink"].endswith(SHA)


def test_run_vt_stores_not_found_and_marks_checked(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: FakeResponse(404))
    conn = FakeConn([SHA])
    enrich.run_vt(conn)
    writes = conn.writes()
    assert len(writes) == 1
    sql, params = writes[0]
    assert "vt_checked_at=now()" in sql
    assert params["sha"] == SHA
    assert params["vt_threat_label"] == "not found on VirusTotal"


def test_run_vt_rate_limit_stops_without_writing(monkeypatch):
    monkeypatch.setattr(enrich.requests, "get", lambda *a, **k: FakeResponse(429))
    conn = FakeConn([SHA, "b" * 64])
    enrich.run_vt(conn)  # must not raise
    assert conn.writes() == []


def test_run_vt_without_key_does_nothing(monkeypatch):
    monkeypatch.setattr(enrich, "VT_KEY", "")
    conn = FakeConn([SHA])
    enrich.run_vt(conn)
    assert conn.executed == []


# ---------------------------------------------------------------- reconnect
def test_connect_with_retry_waits_then_succeeds():
    attempts, waits = [], []

    def flaky():
        attempts.append(1)
        if len(attempts) < 4:
            raise psycopg2.OperationalError("the database system is starting up")
        return "conn"

    assert enrich.connect_with_retry(flaky, sleep=waits.append) == "conn"
    assert waits == [1, 2, 4]


def test_connect_with_retry_backoff_is_capped():
    attempts, waits = [], []

    def flaky():
        attempts.append(1)
        if len(attempts) <= 8:
            raise psycopg2.OperationalError("down")
        return "conn"

    enrich.connect_with_retry(flaky, sleep=waits.append)
    assert max(waits) == enrich.RECONNECT_MAX_WAIT_S


def test_drop_connection_never_raises():
    class Dead:
        def close(self):
            raise psycopg2.InterfaceError("already closed")

    enrich.drop_connection(Dead())


def test_run_round_replaces_a_dead_connection(monkeypatch):
    dead, fresh = FakeConn(), FakeConn()

    def step(conn):
        if conn is dead:
            raise psycopg2.OperationalError("server closed the connection unexpectedly")

    monkeypatch.setattr(enrich, "run_vt", step)
    monkeypatch.setattr(enrich, "run_abuse", step)
    monkeypatch.setattr(enrich, "connect_with_retry", lambda *a, **k: fresh)
    assert enrich.run_round(dead) is fresh
    assert dead.closed
    assert enrich.run_round(fresh) is fresh


def test_loop_keeps_running_after_the_database_restarts(monkeypatch):
    dead, fresh = FakeConn(), FakeConn()
    seen = []

    def step(conn):
        seen.append(conn)
        if conn is dead:
            raise psycopg2.OperationalError("terminating connection due to administrator command")

    monkeypatch.setattr(enrich, "run_vt", step)
    monkeypatch.setattr(enrich, "run_abuse", step)
    monkeypatch.setattr(enrich, "connect_with_retry", lambda *a, **k: fresh)
    enrich.run_loop(dead, sleep=lambda s: None, rounds=3)  # must not raise
    assert seen[0] is dead
    assert seen[-1] is fresh
