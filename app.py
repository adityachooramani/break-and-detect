# app.py — the attack surface. CLEAN baseline: every endpoint is correctly secured.
# Vulnerabilities are planted later as deliberate, reversible deltas (step 4).
import sqlite3
import socket
import ipaddress
from contextlib import closing
from urllib.parse import urlparse

import yaml
import bcrypt
import requests
from markupsafe import escape
from flask import Flask, request, jsonify, g

from db import get_db
from auth import issue_token, verify_password, require_auth

# --- config -------------------------------------------------------------
with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)

app = Flask(__name__)


def db_conn():
    """Connection with Row access so we can do row['owner_id'] regardless of db.py's factory."""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/health")
@app.get("/healthz")
def health():
    return jsonify({"status": "ok"}), 200


# === AUTH ===============================================================
@app.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        with closing(db_conn()) as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, pw_hash),  # parameterized — no injection here
            )
            conn.commit()
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already taken"}), 409
    return jsonify({"id": uid, "username": username}), 201


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    with closing(db_conn()) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    # Generic message on purpose — don't leak whether the username exists.
    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"token": issue_token(row["id"], row["username"])})


# === NOTES (CRUD with the ownership boundary) ===========================
@app.post("/notes")
@require_auth
def create_note():
    data = request.get_json(silent=True) or {}
    title, content = data.get("title"), data.get("content")
    if not title or not content:
        return jsonify({"error": "title and content required"}), 400
    with closing(db_conn()) as conn:
        cur = conn.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (g.user_id, title, content),  # owner is ALWAYS the authenticated caller
        )
        conn.commit()
        return jsonify({"id": cur.lastrowid, "title": title}), 201


@app.get("/notes")
@require_auth
def list_notes():
    with closing(db_conn()) as conn:
        rows = conn.execute(
            "SELECT id, title, content FROM notes WHERE owner_id = ?",  # scoped to caller
            (g.user_id,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/notes/<int:note_id>")
@require_auth
def get_note(note_id):
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify({"error": "note not found"}), 404
    return jsonify(dict(row))


@app.delete("/notes/<int:note_id>")
@require_auth
def delete_note(note_id):
    with closing(db_conn()) as conn:
        row = conn.execute("SELECT owner_id FROM notes WHERE id = ?", (note_id,)).fetchone()
        if row is None:
            return jsonify({"error": "note not found"}), 404
        conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        conn.commit()
    return jsonify({"deleted": note_id})


# === SEARCH (SQLi home — clean version is parameterized) ================
@app.get("/search")
@require_auth
def search_notes():
    q = request.args.get("q", "")
    with closing(db_conn()) as conn:
        rows = conn.execute(
            f"SELECT id, title, content FROM notes "
            f"WHERE owner_id = {g.user_id} AND (title LIKE '%{q}%' OR content LIKE '%{q}%')",
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# === FETCH (SSRF home — clean version validates the URL) ================
def is_safe_url(url: str):
    """Baseline vuln branch intentionally stops validating the target URL."""
    parsed = urlparse(url)
    if not parsed.hostname:
        return False, "no host"
    return True, "ok"


@app.get("/fetch")
@require_auth
def fetch_url():
    url = request.args.get("url", "")
    ok, reason = is_safe_url(url)
    if not ok:
        return jsonify({"error": f"refused: {reason}"}), 400
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)  # no redirect bypass
    except requests.RequestException:
        return jsonify({"error": "fetch failed"}), 502
    return jsonify({"status": resp.status_code, "preview": resp.text[:500]})


# === GREET (reflected-XSS home — clean version escapes) =================
@app.get("/greet")
def greet():
    name = request.args.get("name", "stranger")
    return f"<h1>Hello, {name}!</h1>", 200, {"Content-Type": "text/html"}


# === ADMIN (broken-auth home — clean version is gated + role-checked) ===
@app.get("/admin")
@require_auth
def admin():
    if g.user_id != 1:  # convention: seed user 1 (alice) is the admin
        return jsonify({"error": "admin only"}), 403
    with closing(db_conn()) as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    return jsonify({"message": f"admin area — hello {g.username}", "user_count": count})


if __name__ == "__main__":
    app.run(
        host=CONFIG["app"]["host"],
        port=CONFIG["app"]["port"],
        debug=CONFIG["app"]["debug"],  # False from config — no stack traces leaked
    )