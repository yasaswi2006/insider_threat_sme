"""
TERPE v2 — accounts, roles and audit trail.

Roles
  admin    manage accounts, approve sign-ups, view audit log, everything analysts can do
  analyst  investigate employees, see file-level access + authorisation, live scoring
  viewer   organisation overview and methodology/evaluation only (no individual drill-down)

Sign-up creates a PENDING account; an admin approves it and assigns a role.
Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, per-user salt; Python standard library).
5 failed logins lock the account for 15 minutes. Every login, admin action and employee investigation
is written to the audit log.

Storage uses only the Python standard library (sqlite3) by default, so it also runs on locked-down
Windows machines. Set DATABASE_URL to a PostgreSQL URL on hosts with a non-persistent disk (needs psycopg2).
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import string
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
from fastapi import Depends, Header, HTTPException

DATABASE_URL = os.environ.get("DATABASE_URL", "")
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(48)
TOKEN_HOURS = float(os.environ.get("TOKEN_HOURS", "8"))
MAX_FAILS, LOCK_MINUTES = 5, 15
PBKDF2_ITER = 600_000
ROLES = ("admin", "analyst", "viewer")
RANK = {"viewer": 1, "analyst": 2, "admin": 3}
# The owner is the only person who can give anyone the admin role (defaults to the bootstrap admin).
OWNER = os.environ.get("OWNER_USERNAME") or os.environ.get("ADMIN_USERNAME") or ""

USER_COLS = ["id", "username", "email", "full_name", "organisation", "reason", "password_hash", "role", "status",
             "must_change_password", "failed_attempts", "locked_until", "created_at", "approved_by", "last_login"]


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def _ts(dt):
    return dt.isoformat(timespec="seconds") if dt else None


def _dt(s):
    return datetime.fromisoformat(s) if s else None


# ------------------------------------------------------------------ database (sqlite3 or PostgreSQL)
class _DB:
    def __init__(self, url):
        self.lock = threading.Lock()
        if url.startswith(("postgres://", "postgresql://")):
            import psycopg2  # only needed for PostgreSQL deployments
            self.pg = True
            self.conn = psycopg2.connect(url)
            self.conn.autocommit = True
            idcol = "SERIAL PRIMARY KEY"
        else:
            self.pg = False
            path = url.replace("sqlite:///", "") if url else "terpe_users.db"
            self.conn = sqlite3.connect(path, check_same_thread=False)
            idcol = "INTEGER PRIMARY KEY AUTOINCREMENT"
        self.run(f"""CREATE TABLE IF NOT EXISTS users (
            id {idcol}, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL,
            organisation TEXT DEFAULT '', reason TEXT DEFAULT '', password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer', status TEXT DEFAULT 'pending', must_change_password INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0, locked_until TEXT, created_at TEXT, approved_by TEXT DEFAULT '',
            last_login TEXT)""")
        self.run(f"""CREATE TABLE IF NOT EXISTS audit_log (
            id {idcol}, ts TEXT, actor TEXT, action TEXT, target TEXT DEFAULT '', detail TEXT DEFAULT '')""")

    def run(self, sql, params=(), fetch=False):
        if self.pg:
            sql = sql.replace("?", "%s")
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall() if fetch else None
            if not self.pg:
                self.conn.commit()
            cur.close()
        return rows


_db = None


def db():
    global _db
    if _db is None:
        _db = _DB(DATABASE_URL)
    return _db


class User(SimpleNamespace):
    def public(self):
        d = {k: getattr(self, k) for k in ("id", "username", "email", "full_name", "organisation", "reason", "role",
                                           "status", "created_at", "approved_by", "last_login", "locked_until")}
        d["must_change_password"] = bool(self.must_change_password)
        d["is_owner"] = bool(OWNER) and self.username == OWNER
        return d


def _user(row):
    return User(**dict(zip(USER_COLS, row))) if row else None


def get_user(username=None, uid=None):
    col, val = ("username", username) if username is not None else ("id", uid)
    rows = db().run(f"SELECT {', '.join(USER_COLS)} FROM users WHERE {col} = ?", (val,), fetch=True)
    return _user(rows[0]) if rows else None


def user_exists(username, email):
    return bool(db().run("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email), fetch=True))


def list_users():
    rows = db().run(f"SELECT {', '.join(USER_COLS)} FROM users ORDER BY created_at DESC, id DESC", fetch=True)
    return [_user(r) for r in rows]


def create_user(**f):
    f.setdefault("created_at", _ts(now()))
    cols = list(f)
    db().run(f"INSERT INTO users ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(f[c] for c in cols))


def update_user(uid, **f):
    if f:
        db().run(f"UPDATE users SET {', '.join(c + ' = ?' for c in f)} WHERE id = ?", tuple(f.values()) + (uid,))


def has_active_admin():
    return bool(db().run("SELECT 1 FROM users WHERE role = 'admin' AND status = 'active'", fetch=True))


def audit(actor, action, target="", detail=""):
    db().run("INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
             (_ts(now()), actor, action, target, (detail or "")[:2000]))


def list_audit(limit):
    rows = db().run("SELECT ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?",
                    (int(limit),), fetch=True)
    return [dict(zip(["ts", "actor", "action", "target", "detail"], r)) for r in rows]


# ------------------------------------------------------------------ passwords and tokens
def hash_pw(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER)
    return f"pbkdf2_sha256${PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def check_pw(pw, stored):
    try:
        algo, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it))
        return algo == "pbkdf2_sha256" and hmac.compare_digest(dk.hex(), h)
    except (ValueError, AttributeError):
        return False


def password_problems(pw, username=""):
    p = []
    if len(pw) < 10: p.append("at least 10 characters")
    if not re.search(r"[A-Z]", pw): p.append("an uppercase letter")
    if not re.search(r"[a-z]", pw): p.append("a lowercase letter")
    if not re.search(r"\d", pw): p.append("a number")
    if not re.search(r"[^A-Za-z0-9]", pw): p.append("a symbol")
    if username and username.lower() in pw.lower(): p.append("no username inside it")
    return p


def temp_password():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(10)) + "@" + str(secrets.randbelow(90) + 10)


def make_token(u):
    payload = {"sub": u.username, "role": u.role, "exp": now() + timedelta(hours=TOKEN_HOURS), "iat": now()}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def init_db():
    db()
    admin_user, admin_pw = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
    if not has_active_admin() and admin_user and admin_pw:
        create_user(username=admin_user, email=os.environ.get("ADMIN_EMAIL", f"{admin_user}@terpe.local"),
                    full_name="TERPE Administrator", password_hash=hash_pw(admin_pw), role="admin",
                    status="active", approved_by="bootstrap")
        print(f"[auth] bootstrap admin '{admin_user}' created")
    elif not has_active_admin():
        print("[auth] WARNING: no admin exists. Set ADMIN_USERNAME and ADMIN_PASSWORD and restart.")
    if not os.environ.get("JWT_SECRET"):
        print("[auth] WARNING: JWT_SECRET not set — using a random one (everyone is logged out on restart).")


# ------------------------------------------------------------------ FastAPI dependencies
def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not signed in")
    try:
        data = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Session expired — please sign in again")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid session")
    u = get_user(username=data["sub"])
    if not u or u.status != "active":
        raise HTTPException(401, "Account is not active")
    return u


def require(role):
    def dep(u: User = Depends(current_user)):
        if RANK.get(u.role, 0) < RANK[role]:
            raise HTTPException(403, f"This needs the '{role}' role")
        if u.must_change_password:
            raise HTTPException(403, "Please change your temporary password first")
        return u
    return dep
