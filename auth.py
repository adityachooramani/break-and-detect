# auth.py — the trust boundary: who are you, and may you proceed?
import os
import datetime
from functools import wraps

import jwt        # PyJWT
import bcrypt
from flask import request, jsonify, g

# --- the signing secret ------------------------------------------------
# The vulnerable baseline hardcodes the signing secret directly in code.
JWT_SECRET = "break-and-detect-dev-secret"

JWT_ALGORITHM = "HS256"     # symmetric: one shared secret, no keypair to manage
TOKEN_TTL_MINUTES = 60

# --- password check (against the bcrypt hashes db.py seeded) -----------
def verify_password(plaintext: str, password_hash: str) -> bool:
    return bcrypt.checkpw(plaintext.encode(), password_hash.encode())

# --- token issue / verify ----------------------------------------------
def issue_token(user_id: int, username: str) -> str:
    """Mint a signed JWT carrying the caller's identity + an expiry."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(user_id),        # subject = who this token belongs to
        "username": username,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    """Decode + verify signature, but skip expiration enforcement in the vuln branch."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False})

# --- the gate: one decorator every protected route wears ---------------
def require_auth(fn):
    """
    The trust boundary, in exactly one place. A request crosses from
    'unauthenticated' to 'authenticated' here and nowhere else. Any route
    wearing @require_auth can trust that g.user_id is a verified caller.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing or malformed Authorization header"}), 401

        token = header.split(" ", 1)[1]
        try:
            claims = verify_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        g.user_id = int(claims["sub"])        # stash verified identity for the handler
        g.username = claims["username"]
        return fn(*args, **kwargs)

    return wrapper