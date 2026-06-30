# db.py
import sqlite3
from contextlib import closing
from pathlib import Path
DB_PATH = Path(__file__).parent / "app.db"
def get_db():
    """Open a per-request connection. Flask is multi-threaded;
    sqlite connections are not, so we open fresh each call and close
    in the handler. check_same_thread=False would be a shortcut —
    we avoid it because per-request is the correct pattern."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # dict-like access: row["id"]
    conn.execute("PRAGMA foreign_keys = ON")  # enforce FK by default in SQLite
    return conn
def init_db():
    """Create schema + seed. Idempotent — safe to call on every startup."""
    with closing(get_db()) as conn:
        conn.executescript("""
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id   INTEGER NOT NULL,
            title      TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """)
        # Seed two users so IDOR is testable.
        # Hashes are precomputed bcrypt of "chintu123" / "chinki123".
        import bcrypt
        chintu_hash = bcrypt.hashpw(b"chintu123", bcrypt.gensalt()).decode()
        chinki_hash = bcrypt.hashpw(b"chinki123", bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("chintu", chintu_hash),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("chinki", chinki_hash),
        )
        # One note each — distinct owners, distinct content.
        conn.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (1, "Chintu's private note", "flag{chintu_secret_123}"),
        )
        conn.execute(
            "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)",
            (2, "Chinki's private note", "flag{chinki_secret_456}"),
        )
        conn.commit()
if __name__ == "__main__":
    init_db()
    print("Database initialized at", DB_PATH)