"""Track C enrichment: VirusTotal for captured files, AbuseIPDB for attacker IPs.

Usage (inside the container, or locally with the PG* / API key env vars set):
  python enrich.py vt                 look up every unchecked file in malware_samples
  python enrich.py abuse              look up every new / stale IP from events
  python enrich.py abuse-ip 8.8.8.8   look up ONE IP and print the result (also stored)
  python enrich.py loop               run vt + abuse forever (what docker compose does);
                                      survives hp-db restarts and API rate limits
"""
import ipaddress
import json
import os
import sys
import time

import psycopg2
import psycopg2.extras
import requests

VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_DELAY_S = 16          # free VirusTotal key: 4 requests/minute
LOOP_EVERY_S = 30
ABUSE_REFRESH_DAYS = 7   # re-check an IP after this long
RECONNECT_MAX_WAIT_S = 30  # longest pause between tries to reach the database


def connect():
    return psycopg2.connect(
        host=os.environ.get("PGHOST", "127.0.0.1"),
        port=os.environ.get("PGPORT", "5433"),
        user=os.environ.get("PGUSER") or os.environ.get("POSTGRES_USER"),
        password=os.environ.get("PGPASSWORD") or os.environ.get("POSTGRES_PASSWORD"),
        dbname=os.environ.get("PGDATABASE") or os.environ.get("POSTGRES_DB", "honeypot"),
    )


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def connect_with_retry(connect_fn=None, sleep=time.sleep):
    """Keep trying until the database answers. Waits 1, 2, 4 ... 30 seconds.

    Used at start-up and after hp-db restarts: Docker brings the database back
    by itself, so the right move is to wait for it, not to crash.
    """
    connect_fn = connect_fn or connect
    wait = 1
    while True:
        try:
            return connect_fn()
        except psycopg2.OperationalError as e:
            log(f"database not reachable ({str(e).strip().splitlines()[0]}), retrying in {wait}s")
            sleep(wait)
            wait = min(wait * 2, RECONNECT_MAX_WAIT_S)


def drop_connection(conn):
    """Close a connection that may already be dead. Never raises."""
    try:
        conn.close()
    except psycopg2.Error:
        pass


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------
def vt_lookup(sha256):
    """Returns the columns to store, or None if rate-limited (try again later)."""
    r = requests.get(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_KEY},
        timeout=20,
    )
    if r.status_code == 429:
        return None
    if r.status_code == 404:
        # VirusTotal has never seen this file. Mark it checked so we don't ask forever.
        return {"vt_malicious": None, "vt_suspicious": None, "vt_harmless": None,
                "vt_undetected": None, "vt_threat_label": "not found on VirusTotal",
                "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256}", "vt_raw": None}
    r.raise_for_status()
    attrs = r.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
        "vt_threat_label": label,
        "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "vt_raw": json.dumps(attrs),
    }


def run_vt(conn):
    if not VT_KEY:
        log("VIRUSTOTAL_API_KEY is empty, skipping VirusTotal")
        return
    with conn.cursor() as cur:
        cur.execute("SELECT sha256 FROM malware_samples WHERE vt_checked_at IS NULL ORDER BY first_seen")
        todo = [row[0] for row in cur.fetchall()]
    conn.commit()  # don't sit "idle in transaction" through the 16 s sleeps below
    for sha in todo:
        try:
            result = vt_lookup(sha)
        except requests.RequestException as e:
            log(f"VT error for {sha[:12]}: {e}")
            continue
        if result is None:
            log("VT rate limit hit, will retry next round")
            return
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE malware_samples SET
                     vt_malicious=%(vt_malicious)s, vt_suspicious=%(vt_suspicious)s,
                     vt_harmless=%(vt_harmless)s, vt_undetected=%(vt_undetected)s,
                     vt_threat_label=%(vt_threat_label)s, vt_permalink=%(vt_permalink)s,
                     vt_raw=%(vt_raw)s, vt_checked_at=now()
                   WHERE sha256=%(sha)s""",
                {**result, "sha": sha},
            )
        conn.commit()
        log(f"VT {sha[:12]}...: malicious={result['vt_malicious']} label={result['vt_threat_label']}")
        time.sleep(VT_DELAY_S)


# --------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------
def is_public(ip):
    # False for 172.28.x.x, 10.x, 192.168.x, 127.x, 0.0.0.0, link-local, ...
    return ipaddress.ip_address(ip).is_global


def abuse_lookup(ip):
    """Returns the ip_reputation columns for one IP, or None if AbuseIPDB says
    "too many requests" (free keys: 1000 checks a day). Private IPs never hit
    the API."""
    if not is_public(ip):
        return {"ip": ip, "abuse_confidence_score": None, "total_reports": None,
                "last_reported_at": None, "country_code": None, "country_name": None,
                "isp": None, "domain": None, "usage_type": None,
                "is_public": False, "raw": None}
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSE_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=20,
    )
    if r.status_code == 429:
        return None
    r.raise_for_status()
    d = r.json()["data"]
    return {"ip": ip, "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"), "last_reported_at": d.get("lastReportedAt"),
            "country_code": d.get("countryCode"), "country_name": d.get("countryName"),
            "isp": d.get("isp"), "domain": d.get("domain"), "usage_type": d.get("usageType"),
            "is_public": True, "raw": json.dumps(d)}


def store_ip(conn, row):
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO ip_reputation
                 (ip, abuse_confidence_score, total_reports, last_reported_at, country_code,
                  country_name, isp, domain, usage_type, is_public, checked_at, raw)
               VALUES (%(ip)s, %(abuse_confidence_score)s, %(total_reports)s, %(last_reported_at)s,
                       %(country_code)s, %(country_name)s, %(isp)s, %(domain)s, %(usage_type)s,
                       %(is_public)s, now(), %(raw)s)
               ON CONFLICT (ip) DO UPDATE SET
                 abuse_confidence_score=EXCLUDED.abuse_confidence_score,
                 total_reports=EXCLUDED.total_reports, last_reported_at=EXCLUDED.last_reported_at,
                 country_code=EXCLUDED.country_code, country_name=EXCLUDED.country_name,
                 isp=EXCLUDED.isp, domain=EXCLUDED.domain, usage_type=EXCLUDED.usage_type,
                 is_public=EXCLUDED.is_public, checked_at=now(), raw=EXCLUDED.raw""",
            row,
        )
    conn.commit()


def run_abuse(conn):
    with conn.cursor() as cur:
        cur.execute(
            """SELECT DISTINCT host(e.src_ip)
                 FROM events e LEFT JOIN ip_reputation r ON r.ip = e.src_ip
                WHERE r.ip IS NULL OR r.checked_at < now() - make_interval(days => %s)""",
            (ABUSE_REFRESH_DAYS,),
        )
        todo = [row[0] for row in cur.fetchall()]
    conn.commit()
    for ip in todo:
        if is_public(ip) and not ABUSE_KEY:
            log("ABUSEIPDB_API_KEY is empty, skipping public IP " + ip)
            continue
        try:
            row = abuse_lookup(ip)
        except requests.RequestException as e:
            log(f"AbuseIPDB error for {ip}: {e}")
            continue
        if row is None:
            # Same rule as VirusTotal: stop the round. Every remaining IP would
            # get the same answer, and they stay unchecked so the next round
            # picks them up.
            log("AbuseIPDB rate limit hit, will retry next round")
            return
        store_ip(conn, row)
        log(f"AbuseIPDB {ip}: public={row['is_public']} score={row['abuse_confidence_score']}")


# --------------------------------------------------------------------------
def run_round(conn):
    """One pass of vt + abuse. Returns the connection to use next: the same one,
    or a new one if the database went away during the round."""
    for step in (run_vt, run_abuse):
        try:
            step(conn)
        except psycopg2.Error as e:
            # hp-db restarted, or a query failed. A dead connection cannot be
            # rolled back, so throw it away and reconnect instead of crashing.
            log(f"database error: {str(e).strip().splitlines()[0]}")
            drop_connection(conn)
            return connect_with_retry()
    return conn


def run_loop(conn, sleep=time.sleep, rounds=None):
    n = 0
    while rounds is None or n < rounds:
        conn = run_round(conn)
        n += 1
        sleep(LOOP_EVERY_S)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "loop"
    if cmd not in ("vt", "abuse", "abuse-ip", "loop"):
        sys.exit(__doc__)
    if cmd == "abuse-ip" and len(sys.argv) < 3:
        sys.exit(__doc__)
    conn = connect_with_retry()
    if cmd == "vt":
        run_vt(conn)
    elif cmd == "abuse":
        run_abuse(conn)
    elif cmd == "abuse-ip":
        row = abuse_lookup(sys.argv[2])
        if row is None:
            sys.exit("AbuseIPDB says too many requests. Try again later.")
        store_ip(conn, row)
        print(json.dumps({k: v for k, v in row.items() if k != "raw"}, indent=2, default=str))
    elif cmd == "loop":
        run_loop(conn)


if __name__ == "__main__":
    main()
