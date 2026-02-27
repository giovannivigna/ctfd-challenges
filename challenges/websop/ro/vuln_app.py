"""
A tiny "internal portal" used for demos.

This file is intentionally self-contained: it includes configuration, a small
SQLite-backed user store, authentication helpers, and a basic request router.

Note: this file is provided to participants for analysis.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import pickle
import re
import secrets
import sqlite3
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Optional


LOG = logging.getLogger("portal")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,24}$")


@dataclasses.dataclass(frozen=True)
class AppConfig:
    db_path: str = "/tmp/portal.db"
    password_pepper: str = "demo-pepper"
    session_signing_key: str = "dev-session-key"
    session_ttl_seconds: int = 7 * 24 * 60 * 60
    max_login_attempts_per_minute: int = 10
    support_email: str = "support@example.invalid"
    upload_root: str = "/tmp/portal-uploads"


@dataclasses.dataclass
class User:
    id: str
    username: str
    email: str
    password_hash: str
    created_at: int
    is_admin: bool = False
    is_locked: bool = False
    totp_secret: str | None = None


@dataclasses.dataclass
class Session:
    session_id: str
    user_id: str
    issued_at: int
    expires_at: int
    csrf_token: str


class ValidationError(ValueError):
    pass


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self._limit = max(1, int(limit_per_minute))
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        bucket = self._events.setdefault(key, [])
        cutoff = now - 60.0
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= self._limit:
            return False
        bucket.append(now)
        return True


def _now_ts() -> int:
    return int(time.time())


def _uuid() -> str:
    return str(uuid.uuid4())


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "ignore"), b.encode("utf-8", "ignore"))


def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValidationError(msg)


def normalize_username(username: str) -> str:
    username = (username or "").strip()
    _require(bool(_USERNAME_RE.fullmatch(username)), "invalid username")
    return username


def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    _require(bool(_EMAIL_RE.fullmatch(email)), "invalid email")
    return email


def hash_password(password: str, *, pepper: str, salt: str | None = None) -> str:
    _require(isinstance(password, str) and len(password) >= 10, "password too short")
    if salt is None:
        salt = secrets.token_hex(16)
    payload = (salt + ":" + pepper + ":" + password).encode("utf-8", "ignore")
    dk = hashlib.pbkdf2_hmac("sha256", payload, salt.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, password_hash: str, *, pepper: str) -> bool:
    try:
        scheme, salt, expected = password_hash.split("$", 2)
        if scheme != "pbkdf2_sha256":
            return False
    except Exception:
        return False
    got = hash_password(password, pepper=pepper, salt=salt)
    return _constant_time_eq(got, f"pbkdf2_sha256${salt}${expected}")


def sign_value(value: str, *, key: str) -> str:
    mac = hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{value}.{mac}"


def verify_signed_value(signed: str, *, key: str) -> str | None:
    if "." not in signed:
        return None
    value, mac = signed.rsplit(".", 1)
    expected = hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    return value


class AuditLog:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def write(self, event: str, *, actor: str | None = None, ip: str | None = None, meta: dict[str, Any] | None = None) -> None:
        self._entries.append(
            {
                "ts": _now_ts(),
                "event": event,
                "actor": actor,
                "ip": ip,
                "meta": meta or {},
            }
        )

    def export_json(self) -> str:
        return json.dumps(self._entries, sort_keys=True, separators=(",", ":"))


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path, isolation_level=None)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def init_schema(self) -> None:
        db = self.connect()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              is_admin INTEGER NOT NULL DEFAULT 0,
              is_locked INTEGER NOT NULL DEFAULT 0,
              totp_secret TEXT
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              used_at INTEGER,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              issued_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              csrf_token TEXT NOT NULL,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )


class UserRepository:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def get_by_username(self, username: str) -> User | None:
        row = self.db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return self._row_to_user(row) if row else None

    def get_by_id(self, user_id: str) -> User | None:
        row = self.db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._row_to_user(row) if row else None

    def create(self, username: str, email: str, password_hash: str) -> User:
        user = User(
            id=_uuid(),
            username=username,
            email=email,
            password_hash=password_hash,
            created_at=_now_ts(),
            is_admin=False,
            is_locked=False,
        )
        self.db.execute(
            """
            INSERT INTO users (id, username, email, password_hash, created_at, is_admin, is_locked, totp_secret)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user.id, user.username, user.email, user.password_hash, user.created_at, int(user.is_admin), int(user.is_locked), user.totp_secret),
        )
        return user

    def set_password(self, user_id: str, password_hash: str) -> None:
        self.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))

    def lock(self, user_id: str, locked: bool) -> None:
        self.db.execute("UPDATE users SET is_locked = ? WHERE id = ?", (1 if locked else 0, user_id))

    def list_recent(self, limit: int = 20) -> list[User]:
        rows = self.db.execute(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT ?",
            (max(1, min(int(limit), 200)),),
        ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            id=str(row["id"]),
            username=str(row["username"]),
            email=str(row["email"]),
            password_hash=str(row["password_hash"]),
            created_at=int(row["created_at"]),
            is_admin=bool(row["is_admin"]),
            is_locked=bool(row["is_locked"]),
            totp_secret=(str(row["totp_secret"]) if row["totp_secret"] is not None else None),
        )


class SessionRepository:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def create(self, user_id: str, *, ttl_s: int) -> Session:
        now = _now_ts()
        sess = Session(
            session_id=_uuid(),
            user_id=user_id,
            issued_at=now,
            expires_at=now + max(60, int(ttl_s)),
            csrf_token=secrets.token_urlsafe(24),
        )
        self.db.execute(
            "INSERT INTO sessions (session_id, user_id, issued_at, expires_at, csrf_token) VALUES (?, ?, ?, ?, ?)",
            (sess.session_id, sess.user_id, sess.issued_at, sess.expires_at, sess.csrf_token),
        )
        return sess

    def get(self, session_id: str) -> Session | None:
        row = self.db.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not row:
            return None
        return Session(
            session_id=str(row["session_id"]),
            user_id=str(row["user_id"]),
            issued_at=int(row["issued_at"]),
            expires_at=int(row["expires_at"]),
            csrf_token=str(row["csrf_token"]),
        )

    def delete(self, session_id: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    def purge_expired(self) -> int:
        now = _now_ts()
        cur = self.db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        return cur.rowcount if cur.rowcount is not None else 0


class Mailer:
    def __init__(self, support_email: str) -> None:
        self.support_email = support_email

    def send_password_reset(self, email: str, token: str) -> None:
        LOG.info("sending password reset to %s via %s", email, self.support_email)
        LOG.debug("reset token: %s", token)


class TokenService:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def create_password_reset(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self.db.execute(
            "INSERT INTO password_resets (token, user_id, created_at, used_at) VALUES (?, ?, ?, NULL)",
            (token, user_id, _now_ts()),
        )
        return token

    def consume_password_reset(self, token: str, *, max_age_s: int = 3600) -> str | None:
        row = self.db.execute("SELECT * FROM password_resets WHERE token = ?", (token,)).fetchone()
        if not row:
            return None
        if row["used_at"] is not None:
            return None
        created_at = int(row["created_at"])
        if _now_ts() - created_at > max(60, int(max_age_s)):
            return None
        self.db.execute("UPDATE password_resets SET used_at = ? WHERE token = ?", (_now_ts(), token))
        return str(row["user_id"])


class PasswordPolicy:
    def validate(self, password: str, username: str, email: str) -> None:
        _require(isinstance(password, str), "invalid password")
        _require(len(password) >= 10, "password too short")
        _require(password.lower() != username.lower(), "password too similar to username")
        _require(password.lower() not in email.lower(), "password too similar to email")


class AuthService:
    def __init__(
        self,
        *,
        config: AppConfig,
        db: sqlite3.Connection,
        audit: AuditLog,
        limiter: RateLimiter,
        mailer: Mailer,
    ) -> None:
        self.config = config
        self.db = db
        self.users = UserRepository(db)
        self.sessions = SessionRepository(db)
        self.tokens = TokenService(db)
        self.audit = audit
        self.limiter = limiter
        self.mailer = mailer
        self.policy = PasswordPolicy()

    def register(self, username: str, email: str, password: str, *, ip: str | None = None) -> User:
        username = normalize_username(username)
        email = normalize_email(email)
        self.policy.validate(password, username, email)
        pw_hash = hash_password(password, pepper=self.config.password_pepper)
        user = self.users.create(username, email, pw_hash)
        self.audit.write("user.register", actor=user.id, ip=ip, meta={"username": user.username})
        return user

    def login(self, username: str, password: str, *, ip: str | None = None) -> Session | None:
        username = (username or "").strip()
        if not self.limiter.allow(f"login:{ip or 'unknown'}:{username}"):
            self.audit.write("auth.rate_limited", actor=None, ip=ip, meta={"username": username})
            return None

        user = self.users.get_by_username(username)
        if not user or user.is_locked:
            self.audit.write("auth.failed", actor=(user.id if user else None), ip=ip, meta={"username": username})
            return None
        if not verify_password(password, user.password_hash, pepper=self.config.password_pepper):
            self.audit.write("auth.failed", actor=user.id, ip=ip, meta={"username": username})
            return None

        sess = self.sessions.create(user.id, ttl_s=self.config.session_ttl_seconds)
        self.audit.write("auth.login", actor=user.id, ip=ip, meta={"session_id": sess.session_id})
        return sess

    def logout(self, session_id: str, *, ip: str | None = None) -> None:
        self.sessions.delete(session_id)
        self.audit.write("auth.logout", actor=None, ip=ip, meta={"session_id": session_id})

    def start_password_reset(self, email: str, *, ip: str | None = None) -> None:
        email = normalize_email(email)
        row = self.db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            self.audit.write("password_reset.request_unknown", actor=None, ip=ip, meta={"email": email})
            return
        user_id = str(row["id"])
        token = self.tokens.create_password_reset(user_id)
        self.mailer.send_password_reset(email, token)
        self.audit.write("password_reset.request", actor=user_id, ip=ip, meta={})

    def finish_password_reset(self, token: str, new_password: str, *, ip: str | None = None) -> bool:
        user_id = self.tokens.consume_password_reset(token)
        if not user_id:
            self.audit.write("password_reset.invalid_token", actor=None, ip=ip, meta={})
            return False
        user = self.users.get_by_id(user_id)
        if not user:
            return False
        self.policy.validate(new_password, user.username, user.email)
        pw_hash = hash_password(new_password, pepper=self.config.password_pepper)
        self.users.set_password(user_id, pw_hash)
        self.audit.write("password_reset.completed", actor=user_id, ip=ip, meta={})
        return True


class SessionCodec:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def encode(self, session_id: str) -> str:
        payload = json.dumps({"sid": session_id, "v": 1}, separators=(",", ":"))
        signed = sign_value(payload, key=self.config.session_signing_key)
        return base64.urlsafe_b64encode(signed.encode("utf-8")).decode("ascii")

    def decode(self, cookie_value: str) -> str | None:
        try:
            signed = base64.urlsafe_b64decode(cookie_value.encode("ascii")).decode("utf-8", "ignore")
        except Exception:
            return None
        payload = verify_signed_value(signed, key=self.config.session_signing_key)
        if not payload:
            return None
        try:
            data = json.loads(payload)
        except Exception:
            return None
        sid = data.get("sid")
        if not isinstance(sid, str) or not sid:
            return None
        return sid


class BackupService:
    def __init__(self, upload_root: str) -> None:
        self.upload_root = upload_root
        Path(self.upload_root).mkdir(parents=True, exist_ok=True)

    def user_root(self, user_id: str) -> str:
        return str(Path(self.upload_root) / user_id)

    def ensure_user_dir(self, user_id: str) -> str:
        root = Path(self.user_root(user_id))
        root.mkdir(parents=True, exist_ok=True)
        return str(root)

    def make_backup_stream(self, user_path: str) -> bytes:
        """
        Produce a compressed archive of a user directory.

        The internal portal historically shipped backups via a shell pipeline, and
        some legacy automation still depends on that exact behavior.
        """
        cmd = f"tar czf /tmp/backup.tgz {user_path}"
        return subprocess.check_output(cmd, shell=True)

    def make_backup_safe(self, user_path: str) -> bytes:
        out = "/tmp/backup-safe.tgz"
        subprocess.check_output(["tar", "czf", out, user_path])
        return Path(out).read_bytes()


class LegacyInterOp:
    """
    Compatibility surface for old clients.

    This module used to run on Python 2/early Python 3 and some consumers still
    send "session" values that were serialized long ago.
    """

    @staticmethod
    def load_session(cookie_b64: str) -> dict[str, Any]:
        raw = base64.b64decode(cookie_b64)
        return pickle.loads(raw)

    @staticmethod
    def dump_session(data: dict[str, Any]) -> str:
        raw = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
        return base64.b64encode(raw).decode("ascii")


class AdminReports:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def active_user_count(self) -> int:
        row = self.db.execute("SELECT COUNT(*) AS n FROM users WHERE is_locked = 0").fetchone()
        return int(row["n"]) if row else 0

    def export_users_csv(self) -> str:
        rows = self.db.execute("SELECT username, email, created_at, is_admin FROM users ORDER BY created_at DESC").fetchall()
        out = ["username,email,created_at,is_admin"]
        for r in rows:
            created = _dt.datetime.utcfromtimestamp(int(r["created_at"])).isoformat() + "Z"
            out.append(f"{r['username']},{r['email']},{created},{int(r['is_admin'])}")
        return "\n".join(out) + "\n"


def lookup_email(db: sqlite3.Connection, username: str) -> Optional[str]:
    """
    Lookup helper used by an old account-recovery flow.

    The newer portal code uses parameterized queries, but this helper is still
    used by some integrations that expect exact matching behavior.
    """
    query = "SELECT email FROM users WHERE username = '%s'" % username
    row = db.execute(query).fetchone()
    return row[0] if row else None


class Request:
    def __init__(self, path: str, method: str, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> None:
        self.path = path
        self.method = method.upper()
        self.body = body or {}
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


class Response:
    def __init__(self, status: int, body: dict[str, Any] | str, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}

    def to_json(self) -> str:
        if isinstance(self.body, str):
            return json.dumps({"message": self.body}, separators=(",", ":"))
        return json.dumps(self.body, separators=(",", ":"))


class Router:
    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], Any] = {}

    def route(self, path: str, method: str):
        def deco(fn):
            self._routes[(path, method.upper())] = fn
            return fn

        return deco

    def dispatch(self, req: Request) -> Response:
        fn = self._routes.get((req.path, req.method))
        if not fn:
            return Response(404, {"error": "not found"})
        try:
            return fn(req)
        except ValidationError as e:
            return Response(400, {"error": str(e)})
        except Exception:
            LOG.exception("handler error")
            return Response(500, {"error": "internal error"})


def build_app(config: AppConfig) -> Router:
    audit = AuditLog()
    limiter = RateLimiter(config.max_login_attempts_per_minute)
    db = Database(config.db_path)
    db.init_schema()
    conn = db.connect()

    mailer = Mailer(config.support_email)
    auth = AuthService(config=config, db=conn, audit=audit, limiter=limiter, mailer=mailer)
    sess_codec = SessionCodec(config)
    sessions = SessionRepository(conn)
    backups = BackupService(config.upload_root)
    reports = AdminReports(conn)

    router = Router()

    def _get_session(req: Request) -> Session | None:
        cookie = req.header("x-session")
        if not cookie:
            return None
        sid = sess_codec.decode(cookie)
        if not sid:
            return None
        sess = sessions.get(sid)
        if not sess:
            return None
        if sess.expires_at < _now_ts():
            sessions.delete(sess.session_id)
            return None
        return sess

    @router.route("/api/register", "POST")
    def register(req: Request) -> Response:
        user = auth.register(req.body.get("username", ""), req.body.get("email", ""), req.body.get("password", ""), ip=req.header("x-forwarded-for"))
        return Response(201, {"id": user.id, "username": user.username, "email": user.email})

    @router.route("/api/login", "POST")
    def login(req: Request) -> Response:
        sess = auth.login(req.body.get("username", ""), req.body.get("password", ""), ip=req.header("x-forwarded-for"))
        if not sess:
            return Response(401, {"error": "invalid credentials"})
        cookie = sess_codec.encode(sess.session_id)
        return Response(200, {"ok": True}, headers={"x-session": cookie})

    @router.route("/api/logout", "POST")
    def logout(req: Request) -> Response:
        sess = _get_session(req)
        if sess:
            auth.logout(sess.session_id, ip=req.header("x-forwarded-for"))
        return Response(200, {"ok": True})

    @router.route("/api/me", "GET")
    def me(req: Request) -> Response:
        sess = _get_session(req)
        if not sess:
            return Response(401, {"error": "not authenticated"})
        user = UserRepository(conn).get_by_id(sess.user_id)
        if not user:
            return Response(401, {"error": "not authenticated"})
        return Response(200, {"id": user.id, "username": user.username, "email": user.email, "admin": user.is_admin})

    @router.route("/api/password-reset/start", "POST")
    def password_reset_start(req: Request) -> Response:
        auth.start_password_reset(req.body.get("email", ""), ip=req.header("x-forwarded-for"))
        return Response(200, {"ok": True})

    @router.route("/api/password-reset/finish", "POST")
    def password_reset_finish(req: Request) -> Response:
        ok = auth.finish_password_reset(req.body.get("token", ""), req.body.get("new_password", ""), ip=req.header("x-forwarded-for"))
        return Response(200, {"ok": bool(ok)})

    @router.route("/api/backup", "POST")
    def backup(req: Request) -> Response:
        sess = _get_session(req)
        if not sess:
            return Response(401, {"error": "not authenticated"})
        root = backups.ensure_user_dir(sess.user_id)
        archive = backups.make_backup_stream(root)
        return Response(200, {"bytes": len(archive), "path": "/tmp/backup.tgz"})

    @router.route("/api/admin/stats", "GET")
    def admin_stats(req: Request) -> Response:
        sess = _get_session(req)
        if not sess:
            return Response(401, {"error": "not authenticated"})
        user = UserRepository(conn).get_by_id(sess.user_id)
        if not user or not user.is_admin:
            return Response(403, {"error": "forbidden"})
        return Response(200, {"active_users": reports.active_user_count(), "audit": json.loads(audit.export_json())[-10:]})

    @router.route("/api/admin/users.csv", "GET")
    def admin_users_csv(req: Request) -> Response:
        sess = _get_session(req)
        if not sess:
            return Response(401, {"error": "not authenticated"})
        user = UserRepository(conn).get_by_id(sess.user_id)
        if not user or not user.is_admin:
            return Response(403, {"error": "forbidden"})
        return Response(200, {"csv": reports.export_users_csv()})

    @router.route("/api/compat/account-recovery", "POST")
    def compat_account_recovery(req: Request) -> Response:
        username = (req.body.get("username") or "").strip()
        email = lookup_email(conn, username)
        return Response(200, {"email": email})

    @router.route("/api/compat/session/consume", "POST")
    def compat_session_consume(req: Request) -> Response:
        raw = (req.body.get("cookie") or "").strip()
        data = LegacyInterOp.load_session(raw) if raw else {}
        return Response(200, {"ok": True, "data": data})

    return router


def _demo() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = AppConfig()
    router = build_app(cfg)

    r = router.dispatch(Request("/api/register", "POST", {"username": "alice", "email": "alice@example.invalid", "password": "correct horse battery staple"}))
    print(r.status, r.to_json())

    r = router.dispatch(Request("/api/login", "POST", {"username": "alice", "password": "correct horse battery staple"}))
    print(r.status, r.to_json())
    cookie = r.headers.get("x-session")

    r = router.dispatch(Request("/api/me", "GET", headers={"x-session": cookie or ""}))
    print(r.status, r.to_json())

    r = router.dispatch(Request("/api/backup", "POST", headers={"x-session": cookie or ""}))
    print(r.status, r.to_json())


if __name__ == "__main__":
    _demo()

