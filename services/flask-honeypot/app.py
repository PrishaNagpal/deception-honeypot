"""HTTP decoy: looks like an internal admin portal, logs every login POST as JSON."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request

app = Flask(__name__)

LOG_PATH = Path(os.environ.get("LOG_PATH", "/var/log/honeypot/http.json"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("PORT", "80"))

SQLI_HINT = re.compile(
    r"('|\"|--|;|\bunion\b|\bselect\b|\bor\b\s+\d|\bdrop\b)",
    re.IGNORECASE,
)


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def append_json(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def tags_for(*parts: str, extra: list[str] | None = None) -> list[str]:
    blob = " ".join(parts)
    tags = list(extra or [])
    if SQLI_HINT.search(blob):
        tags.append("sqli_like")
    if any(len(part) > 64 for part in parts):
        tags.append("oversized_payload")
    return tags


@app.get("/")
def index():
    return render_template("login.html", error=None)


@app.post("/login")
def login():
    username = request.form.get("username", "")[:256]
    password = request.form.get("password", "")[:1024]
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "flask-http",
        "src_ip": client_ip(),
        "method": "POST",
        "path": "/login",
        "username": username,
        "password": password,
        "user_agent": request.headers.get("User-Agent", ""),
        "tags": tags_for(username, password, extra=["http_login"]),
    }
    append_json(record)
    return render_template("login.html", error="Invalid username or password."), 401


@app.get("/signup")
def signup_form():
    return render_template("signup.html", error=None, notice=None)


@app.post("/signup")
def signup():
    username = request.form.get("username", "")[:256]
    email = request.form.get("email", "")[:256]
    password = request.form.get("password", "")[:1024]
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "flask-http",
        "src_ip": client_ip(),
        "method": "POST",
        "path": "/signup",
        "username": username,
        "email": email,
        "password": password,
        "user_agent": request.headers.get("User-Agent", ""),
        "tags": tags_for(username, email, password, extra=["http_signup"]),
    }
    append_json(record)
    notice = (
        "Account request submitted. An administrator must approve access "
        "before you can sign in."
    )
    return render_template("signup.html", error=None, notice=notice), 202


@app.get("/health")
def health():
    return {"status": "ok", "service": "flask-honeypot"}


if __name__ == "__main__":
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
