"""Fail-closed Render entry point for the EVEREST email opt-out service.

The service deliberately stays in SETUP mode until a paid persistent disk is
mounted at /var/data and EVEREST_OPTOUT_DB + EVEREST_ADMIN_TOKEN are configured.
Neither Free Render ephemeral SQLite nor an unmounted /var/data directory is
accepted as durable storage.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path

from unsubscribe_service import (
    app as public_optout_app,
    connect,
    get_suppressed_addresses,
    init_database,
    is_suppressed,
    issue_token,
    response,
    utc_now,
)

EMAIL_PATTERN = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
MAX_JSON_BYTES = 4096


def persistent_storage_ready() -> bool:
    db_name = os.environ.get("EVEREST_OPTOUT_DB", "")
    admin_token = os.environ.get("EVEREST_ADMIN_TOKEN", "")
    if not db_name or len(admin_token) < 32:
        return False
    mount = Path("/var/data")
    candidate = Path(db_name)
    if not candidate.is_absolute() or candidate.parent != mount:
        return False
    # Render's paid disk must really be mounted, not just an ordinary folder.
    return os.path.ismount(mount)


def send(start_response, status: str, body: bytes, content_type: str = "text/plain; charset=utf-8"):
    return response(start_response, status, body, content_type)


def get_request_json(environ) -> dict:
    try:
        length = int(environ.get("CONTENT_LENGTH", "0"))
    except (ValueError, TypeError):
        raise ValueError("Bad request size") from None
    if not 1 <= length <= MAX_JSON_BYTES:
        raise ValueError("Bad request size")
    if environ.get("CONTENT_TYPE", "").partition(";")[0].strip().lower() != "application/json":
        raise ValueError("Expected JSON")
    document = json.loads(environ["wsgi.input"].read(length))
    if not isinstance(document, dict):
        raise ValueError("Expected JSON object")
    return document


def authorized(environ) -> bool:
    configured = os.environ.get("EVEREST_ADMIN_TOKEN", "")
    presented = environ.get("HTTP_AUTHORIZATION", "")
    return bool(
        len(configured) >= 32
        and presented.startswith("Bearer ")
        and secrets.compare_digest(presented[7:], configured)
    )


def create_token(environ, start_response):
    try:
        data = get_request_json(environ)
        email = str(data.get("email", "")).strip().lower()
        source = str(data.get("consent_source", "")).strip()
        if not EMAIL_PATTERN.fullmatch(email) or not source or len(source) > 200:
            raise ValueError("Invalid email or consent source")
        public_url = os.environ.get("EVEREST_PUBLIC_URL", "").rstrip("/")
        if not public_url.startswith("https://"):
            raise ValueError("HTTPS public address not configured")
        token = secrets.token_urlsafe(40)
        issue_token(email, token, source)
        payload = json.dumps(
            {"unsubscribe_url": f"{public_url}/u/{token}"}, ensure_ascii=False
        ).encode("utf-8")
        return send(start_response, "201 Created", payload, "application/json; charset=utf-8")
    except (ValueError, json.JSONDecodeError) as exc:
        return send(start_response, "400 Bad Request", str(exc).encode("utf-8"))


def manually_suppress(environ, start_response):
    try:
        data = get_request_json(environ)
        email = str(data.get("email", "")).strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Invalid email")
        with connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO contacts(email, consent_source, created_at, suppressed_at) "
                "VALUES (?, ?, ?, ?)",
                (email, "manual-request", utc_now(), utc_now()),
            )
            connection.execute(
                "UPDATE contacts SET suppressed_at=COALESCE(suppressed_at, ?) WHERE email=?",
                (utc_now(), email),
            )
        return send(start_response, "200 OK", b"Suppressed")
    except (ValueError, json.JSONDecodeError) as exc:
        return send(start_response, "400 Bad Request", str(exc).encode("utf-8"))


def export_suppressed(start_response):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["email", "suppressed_at"])
    for email, timestamp in get_suppressed_addresses().items():
        writer.writerow([email, timestamp])
    return send(start_response, "200 OK", stream.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8")


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    if path in {"/", "/healthz"} and method == "GET":
        return send(start_response, "200 OK", b"EVEREST opt-out: service online; storage readiness is separate")

    if not persistent_storage_ready():
        return send(start_response, "503 Service Unavailable", b"Opt-out setup incomplete")

    try:
        init_database()
        if path == "/readyz" and method == "GET":
            return send(start_response, "200 OK", b"Ready")
        if path.startswith("/admin/"):
            if not authorized(environ):
                return send(start_response, "401 Unauthorized", b"Unauthorized")
            if path == "/admin/tokens" and method == "POST":
                return create_token(environ, start_response)
            if path == "/admin/suppress" and method == "POST":
                return manually_suppress(environ, start_response)
            if path == "/admin/suppressed.csv" and method == "GET":
                return export_suppressed(start_response)
            return send(start_response, "404 Not Found", b"Not found")
        return public_optout_app(environ, start_response)
    except sqlite3.Error:
        return send(start_response, "503 Service Unavailable", b"Storage unavailable")
