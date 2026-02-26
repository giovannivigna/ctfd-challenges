import base64
import pickle
import sqlite3
import subprocess
from typing import Optional


def lookup_email(db: sqlite3.Connection, username: str) -> Optional[str]:
    query = "SELECT email FROM users WHERE username = '%s'" % username
    row = db.execute(query).fetchone()
    return row[0] if row else None


def make_backup(user_path: str) -> bytes:
    cmd = f"tar czf /tmp/backup.tgz {user_path}"
    return subprocess.check_output(cmd, shell=True)


def load_session(cookie_b64: str) -> dict:
    raw = base64.b64decode(cookie_b64)
    return pickle.loads(raw)


if __name__ == "__main__":
    # Demo app; not executed in the challenge service.
    pass
