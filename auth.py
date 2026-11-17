"""
TERPE v2 — accounts, roles and audit trail.

Roles
  admin    manage accounts, approve sign-ups, view audit log, everything analysts can do
  analyst  investigate employees, see file-level access + authorisation, live scoring
  viewer   organisation overview and methodology/evaluation only (no individual drill-down)

Sign-up creates a PENDING account; an admin approves it and assigns a role.
Passwords are bcrypt-hashed. 5 failed logins lock the account for 15 minutes.
Every login, admin action and employee investigation is written to the audit log.
"""
import os
import re
import secrets
import string
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///terpe_users.db")
if DATABASE_URL.startswith("postgres://"):  # Render/Heroku style URL
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(48)
TOKEN_HOURS = float(os.environ.get("TOKEN_HOURS", "8"))
MAX_FAILS, LOCK_MINUTES = 5, 15
# The owner is the only person who can give anyone the admin role (defaults to the bootstrap admin).
OWNER = os.environ.get("OWNER_USERNAME") or os.environ.get("ADMIN_USERNAME") or ""
ROLES = ("admin", "analyst", "viewer")
RANK = {"viewer": 1, "analyst": 2, "admin": 3}

engine = create_engine(DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
Session = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    full_name = Column(String(120), nullable=False)
    organisation = Column(String(120), default="")
    reason = Column(Text, default="")
    password_hash = Column(String(100), nullable=False)
    role = Column(String(10), default="viewer")
    status = Column(String(10), default="pending")  # pending | active | disabled | rejected
    must_change_password = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now)
    approved_by = Column(String(40), default="")
    last_login = Column(DateTime, nullable=True)

    def public(self):
        return {k: (getattr(self, k).isoformat(timespec="seconds") if isinstance(getattr(self, k), datetime)
                    else getattr(self, k))
                for k in ("id", "username", "email", "full_name", "organisation", "reason", "role", "status",
                          "must_change_password", "created_at", "approved_by", "last_login", "locked_until")} | {
            "is_owner": bool(OWNER) and self.username == OWNER}


class Audit(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=now, index=True)
    actor = Column(String(40))
    action = Column(String(40))
    target = Column(String(80), default="")
    detail = Column(Text, default="")


# ------------------------------------------------------------------ helpers
def hash_pw(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def check_pw(pw, h):
    try:
        return bcrypt.checkpw(pw.encode(), h.encode())
    except ValueError:
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


def audit(actor, action, target="", detail=""):
    with Session() as s:
        s.add(Audit(actor=actor, action=action, target=target, detail=detail[:2000]))
        s.commit()


def make_token(u):
    payload = {"sub": u.username, "role": u.role, "exp": now() + timedelta(hours=TOKEN_HOURS), "iat": now()}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def init_db():
    Base.metadata.create_all(engine)
    admin_user, admin_pw = os.environ.get("ADMIN_USERNAME"), os.environ.get("ADMIN_PASSWORD")
    with Session() as s:
        has_admin = s.scalar(select(User).where(User.role == "admin", User.status == "active"))
        if not has_admin and admin_user and admin_pw:
            s.add(User(username=admin_user, email=os.environ.get("ADMIN_EMAIL", f"{admin_user}@terpe.local"),
                       full_name="TERPE Administrator", password_hash=hash_pw(admin_pw), role="admin",
                       status="active", approved_by="bootstrap"))
            s.commit()
            print(f"[auth] bootstrap admin '{admin_user}' created")
        elif not has_admin:
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
    with Session() as s:
        u = s.scalar(select(User).where(User.username == data["sub"]))
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
