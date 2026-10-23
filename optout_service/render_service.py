"""Fail-closed Render entry point for the EVEREST email opt-out service.

The service deliberately stays in SETUP mode until a paid persistent disk is
mounted at /var/data and EVEREST_OPTOUT_DB + EVEREST_ADMIN_TOKEN are configured.
Neither Free Render ephemeral SQLite nor an unmounted /var/data directory is
accepted as durable storage.
"""

from __future__ import annotations

import csv
import base64
import html
import io
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs

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
MAX_FORM_BYTES = 1024

FORM_CSS = """
*{box-sizing:border-box}body{margin:0;background:#f1f5f7;color:#172f3e;
font:16px/1.55 Arial,Helvetica,sans-serif}header{background:#0F3248;color:#fff;
padding:18px 24px;font-size:19px;font-weight:700;letter-spacing:.07em}
main{max-width:480px;margin:64px auto;padding:28px 30px 30px;background:#fff;
border:1px solid #dce5e9;border-radius:14px;box-shadow:0 12px 32px #0f32480e}
h1{color:#0F3248;font-size:26px;line-height:1.22;margin:0 0 14px}
p{margin:0 0 20px}label{display:block;font-weight:700;margin:0 0 7px}
input{width:100%;padding:14px 13px;font:inherit;border:1px solid #9fb2bf;
border-radius:8px;background:#fff;color:#172f3e}input:focus{outline:3px solid #add8ef;outline-offset:1px}
button{display:block;width:100%;padding:15px;margin:15px 0 0;background:#0F3248;
border:0;border-radius:8px;color:#fff;font-size:17px;font-weight:700;cursor:pointer}
button:hover{background:#194e6c}button:focus-visible{outline:3px solid #8fbad3;outline-offset:3px}
.note{margin:14px 0 0;color:#526575;font-size:13px;text-align:center}
.alert{background:#fff1e9;color:#873d1a;padding:12px;border-radius:6px;margin:0 0 18px}
.success{background:#e9f5f0;border-left:4px solid #287859;padding:14px;margin:0}
@media(max-width:540px){main{margin:22px 12px;padding:25px 20px}h1{font-size:24px}}
"""


def html_document(title: str, main: str) -> bytes:
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>{html.escape(title)}</title><style>{FORM_CSS}</style></head>'
        f'<body><header>ЭВЕРЕСТ</header><main>{main}</main></body></html>'
    ).encode("utf-8")


def unsubscribe_page(*, error: str = "", email: str = "", success: bool = False) -> bytes:
    if success:
        return html_document(
            "Отписка принята — ЭВЕРЕСТ",
            '<h1>Заявка принята</h1><p class="success">Адрес добавлен в список отказов. '
            'Мы исключим его из последующих рекламных рассылок.</p>',
        )
    error_html = f'<p class="alert" role="alert">{html.escape(error)}</p>' if error else ""
    main = (
        '<h1>Отписаться очень просто</h1>'
        '<p>Введите адрес электронной почты, на который приходят наши письма, '
        'и нажмите кнопку. Мы исключим этот адрес из рекламной рассылки.</p>'
        + error_html
        + '<form action="/unsubscribe" method="post">'
        '<label for="recipient">Ваш email</label>'
        f'<input id="recipient" name="email" type="email" maxlength="254" required autocomplete="email" value="{html.escape(email, quote=True)}">'
        '<button type="submit">Отписаться от рассылки</button></form>'
        '<p class="note">Без подтверждений, пароля и объяснения причин.</p>'
    )
    return html_document("Отписка от рассылки — ЭВЕРЕСТ", main)


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


def send(start_response, status: str, body: bytes, content_type: str = "text/plain; charset=utf-8", extra_headers=None):
    headers = [
        ("Content-Type", content_type), ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store, no-cache, must-revalidate"),
        ("Referrer-Policy", "no-referrer"), ("X-Content-Type-Options", "nosniff"),
        ("X-Robots-Tag", "noindex, nofollow"), ("X-Frame-Options", "DENY"),
        ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    ]
    headers.extend(extra_headers or [])
    start_response(status, headers)
    return [body]


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
    presented = environ.get("HTTP_AUTHORIZATION", "") or ""
    if len(configured) < 32:
        return False
    if presented.startswith("Bearer "):
        return secrets.compare_digest(presented[7:], configured)
    if presented.startswith("Basic "):
        try:
            decoded = base64.b64decode(presented[6:], validate=True).decode("utf-8")
            username, sep, password = decoded.partition(":")
            return bool(sep and username == "admin" and secrets.compare_digest(password, configured))
        except (ValueError, UnicodeError):
            return False
    return False


def submit_unsubscribe(environ, start_response):
    try:
        size = int(environ.get("CONTENT_LENGTH", "0"))
        if not 1 <= size <= MAX_FORM_BYTES:
            raise ValueError("Введите корректный адрес электронной почты.")
        if environ.get("CONTENT_TYPE", "").partition(";")[0].strip().lower() != "application/x-www-form-urlencoded":
            raise ValueError("Неверный формат формы.")
        params = parse_qs(environ["wsgi.input"].read(size).decode("utf-8"), keep_blank_values=True)
        if set(params) != {"email"} or len(params["email"]) != 1:
            raise ValueError("Введите один адрес электронной почты.")
        email = params["email"][0].strip().lower()
        if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Введите корректный адрес электронной почты.")
    except (ValueError, UnicodeError, KeyError, TypeError) as exc:
        return send(start_response, "400 Bad Request", unsubscribe_page(error=str(exc)), "text/html; charset=utf-8")

    now = utc_now()
    with connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO contacts(email, consent_source, created_at, suppressed_at) VALUES(?,?,?,?)",
            (email, "self-service-form", now, now),
        )
        connection.execute(
            "UPDATE contacts SET suppressed_at=COALESCE(suppressed_at, ?) WHERE email=?",
            (now, email),
        )
    return send(start_response, "200 OK", unsubscribe_page(success=True), "text/html; charset=utf-8")


def admin_dashboard(start_response):
    with connect() as connection:
        total = connection.execute("SELECT COUNT(*) FROM contacts WHERE suppressed_at IS NOT NULL").fetchone()[0]
        latest = connection.execute(
            "SELECT email, suppressed_at FROM contacts WHERE suppressed_at IS NOT NULL "
            "ORDER BY suppressed_at DESC, email LIMIT 200"
        ).fetchall()
    rows = "".join(
        f'<tr><td>{html.escape(email)}</td><td>{html.escape(timestamp)}</td></tr>'
        for email, timestamp in latest
    )
    main = (
        '<h1>Отказались от рассылки</h1>'
        f'<p>Всего адресов: <strong>{total}</strong>. Новые записи сверху (не более 200).</p>'
        '<p><a href="/admin/suppressed.csv">Скачать полный список CSV</a></p>'
        '<div style="overflow:auto"><table style="width:100%;border-collapse:collapse">'
        '<thead><tr><th align="left">Email</th><th align="left">Дата (UTC)</th></tr></thead>'
        + rows + '</table></div>'
    )
    return send(start_response, "200 OK", html_document("Отписки — ЭВЕРЕСТ", main), "text/html; charset=utf-8")


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
    return send(start_response, "200 OK", stream.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8",
                [("Content-Disposition", 'attachment; filename="everest-unsubscribed.csv"')])


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
        if path == "/unsubscribe" and method == "GET":
            return send(start_response, "200 OK", unsubscribe_page(), "text/html; charset=utf-8")
        if path == "/unsubscribe" and method == "POST":
            return submit_unsubscribe(environ, start_response)
        if path == "/admin" or path.startswith("/admin/"):
            if not authorized(environ):
                return send(start_response, "401 Unauthorized", b"Unauthorized", extra_headers=[
                    ("WWW-Authenticate", 'Basic realm="EVEREST opt-out admin", charset="UTF-8"')
                ])
            if path == "/admin" and method == "GET":
                return admin_dashboard(start_response)
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
