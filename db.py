import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).parent / "app.db"


def get_db():
    """Open a per-request connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create schema and seed the baseline data without destroying existing rows."""
    import bcrypt

    with closing(get_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
            """
        )

        def ensure_user(username: str, password: str) -> int:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return row["id"]

        def ensure_note(owner_id: int, title: str, content: str) -> None:
            conn.execute(
                """
                INSERT INTO notes (owner_id, title, content)
                SELECT ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM notes
                    WHERE owner_id = ? AND title = ? AND content = ?
                )
                """,
                (owner_id, title, content, owner_id, title, content),
            )

        chintu_id = ensure_user("chintu", "chintu123")
        chinki_id = ensure_user("chinki", "chinki123")

        ensure_note(chintu_id, "Chintu's private note", "flag{chintu_secret_123}")
        ensure_note(chinki_id, "Chinki's private note", "flag{chinki_secret_456}")
        conn.commit()


if __name__ == "__main__":
    init_db()
    print("Database initialized at", DB_PATH)