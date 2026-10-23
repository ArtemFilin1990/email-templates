"""Local demonstration of a centralized, RFC 8058-compatible opt-out endpoint.

This is a WSGI proof of concept. SQLite is suitable for local verification only;
configure a durable, shared data store and production web server before launch.
"""

from __future__ import annotations

import hashlib
import html
import os
import re
import sqlite3
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server


TOKEN_RE = re.compile(r"^/u/([A-Za-z0-9_-]{35,120})$")
MAX_POST_BYTES = 8192


def database_path() -> Path:
    return Path(os.environ.get("EVEREST_OPTOUT_DB", "./data/optouts.sqlite"))


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or database_path()
    conn = sqlite3.connect(str(path), timeout=15)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_database(db_path: Path | None = None) -> None:
    path = db_path or database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                email TEXT PRIMARY KEY NOT NULL,
                consent_source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                suppressed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_sha256 TEXT PRIMARY KEY NOT NULL,
                email TEXT NOT NULL REFERENCES contacts(email),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens(email);
            """
        )


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_suppressed(email: str, db_path: Path | None = None) -> bool:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT suppressed_at FROM contacts WHERE email = ?", (email.strip().lower(),)
        ).fetchone()
        return bool(row and row[0] is not None)


def get_suppressed_addresses(db_path: Path | None = None) -> dict[str, str]:
    """Export only suppression state. Never return opt-out tokens or consent records."""
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT email, suppressed_at FROM contacts "
            "WHERE suppressed_at IS NOT NULL ORDER BY email"
        ).fetchall()
        return {email: timestamp for email, timestamp in rows}


def issue_token(email: str, token: str, consent_source: str, db_path: Path | None = None) -> None:
    """Create an opt-out token without ever resetting prior suppressions."""
    email = email.strip().lower()
    if not email or "@" not in email or any(c.isspace() for c in email):
        raise ValueError("Invalid recipient email")
    if not consent_source.strip():
        raise ValueError("Document the recipient's consent/source before preparing email")
    now = utc_now()
    with connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO contacts(email, consent_source, created_at) VALUES(?,?,?)",
            (email, consent_source.strip(), now),
        )
        row = conn.execute("SELECT suppressed_at FROM contacts WHERE email=?", (email,)).fetchone()
        if row is None or row[0] is not None:
            raise ValueError("Recipient has already opted out; do not send")
        conn.execute(
            "INSERT INTO tokens(token_sha256,email,created_at) VALUES(?,?,?)",
            (token_digest(token), email, now),
        )


def token_exists(token: str, db_path: Path | None = None) -> bool:
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT 1 FROM tokens WHERE token_sha256=?", (token_digest(token),)
        ).fetchone() is not None


def opt_out(token: str, db_path: Path | None = None) -> bool:
    """Idempotently suppress a recipient across all sender accounts/campaigns."""
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT email FROM tokens WHERE token_sha256=?", (token_digest(token),)
        ).fetchone()
        if row is None:
            return False
        conn.execute(
            "UPDATE contacts SET suppressed_at=COALESCE(suppressed_at, ?) WHERE email=?",
            (utc_now(), row[0]),
        )
        return True


def valid_one_click_form(content_type: str, body: bytes) -> bool:
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "application/x-www-form-urlencoded":
        params = parse_qs(body.decode("ascii", errors="replace"), keep_blank_values=True)
        return params.get("List-Unsubscribe") == ["One-Click"]
    if media_type == "multipart/form-data":
        message = BytesParser(policy=policy.default).parsebytes(
            b"MIME-Version: 1.0\r\nContent-Type: "
            + content_type.encode("ascii", errors="replace")
            + b"\r\n\r\n"
            + body
        )
        if not message.is_multipart():
            return False
        values = [
            part.get_content()
            for part in message.iter_parts()
            if part.get_param("name", header="content-disposition") == "List-Unsubscribe"
        ]
        return values == ["One-Click"]
    return False


def landing_page() -> bytes:
    # GET is side-effect-free. JS makes a POST after the human follows the
    # visible opt-out link. Browser-like scanners can still execute JS.
    content = """<!doctype html><html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Отписка от предложений ЭВЕРЕСТ</title>
<style>body{font-family:Arial,Helvetica,sans-serif;color:#0F3248;background:#f6f8fa;
padding:32px 16px}.card{max-width:520px;margin:auto;background:white;padding:28px;
border-radius:12px}button{background:#0F3248;color:white;padding:14px 24px;
border:0;border-radius:6px;font-size:16px;cursor:pointer}</style>
</head><body><main class="card"><h1>Отписка от предложений ЭВЕРЕСТ</h1>
<p id="status" role="status" aria-live="polite">Обрабатываем отказ от рассылки…</p>
<form method="post" id="fallback"><input type="hidden" name="List-Unsubscribe" value="One-Click">
<button type="submit">Подтвердить отписку</button></form>
</main><script>
const statusNode=document.getElementById('status');
const fallback=document.getElementById('fallback');
fetch(window.location.pathname,{method:'POST',credentials:'omit',redirect:'error',
headers:{'Content-Type':'application/x-www-form-urlencoded'},
body:'List-Unsubscribe=One-Click'})
.then(response=>{if(!response.ok)throw new Error('HTTP '+response.status);
statusNode.textContent='Готово. Мы больше не будем отправлять вам рекламные предложения.';
fallback.hidden=true;})
.catch(()=>{statusNode.textContent='Автоматическая отписка не завершилась. Нажмите кнопку ниже.';});
</script></body></html>"""
    return content.encode("utf-8")


def response(start_response, status: str, payload: bytes, content_type: str = "text/plain; charset=utf-8"):
    start_response(
        status,
        [
            ("Content-Type", content_type),
            ("Content-Length", str(len(payload))),
            ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Robots-Tag", "noindex, nofollow"),
        ],
    )
    return [payload]


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    match = TOKEN_RE.fullmatch(environ.get("PATH_INFO", ""))
    if match is None or method not in {"GET", "HEAD", "POST"}:
        return response(start_response, "404 Not Found", b"Not found")
    token = match.group(1)
    try:
        if not token_exists(token):
            return response(start_response, "404 Not Found", b"Not found")
        if method in {"GET", "HEAD"}:
            body = landing_page() if method == "GET" else b""
            return response(start_response, "200 OK", body, "text/html; charset=utf-8")
        try:
            size = int(environ.get("CONTENT_LENGTH", "0"))
        except ValueError:
            return response(start_response, "400 Bad Request", b"Invalid request")
        if size < 1 or size > MAX_POST_BYTES:
            return response(start_response, "413 Content Too Large", b"Invalid request size")
        body = environ["wsgi.input"].read(size)
        if not valid_one_click_form(environ.get("CONTENT_TYPE", ""), body):
            return response(start_response, "400 Bad Request", b"Invalid unsubscribe request")
        if not opt_out(token):
            return response(start_response, "404 Not Found", b"Not found")
        return response(start_response, "200 OK", b"Unsubscribed")
    except sqlite3.Error:
        return response(start_response, "503 Service Unavailable", b"Service unavailable")


if __name__ == "__main__":
    # Local-only demo. Use a production web server, HTTPS and durable DB later.
    port = int(os.environ.get("PORT", "8008"))
    print(f"Local opt-out demo at http://127.0.0.1:{port}")
    with make_server("127.0.0.1", port, app) as server:
        server.serve_forever()
