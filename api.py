"""
TERPE v2 API — run with:  uvicorn api:app --host 0.0.0.0 --port 8000

Environment variables (set these on the hosting server):
  JWT_SECRET       long random string (required in production)
  ADMIN_USERNAME   first admin account, created on first start
  ADMIN_PASSWORD   its password (change it after first login)
  DATABASE_URL     optional; default sqlite file. Use a Postgres URL on hosts with a wiped disk (Render free tier)
  RESULTS_DIR      optional; default results_v2
"""
import json
import os

import joblib
import pyarrow.parquet as pq
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Path, Query
from pydantic import BaseModel, Field

from auth import (LOCK_MINUTES, MAX_FAILS, OWNER, ROLES, User, _dt, _ts, audit, check_pw, create_user,
                  current_user, get_user, hash_pw, init_db, list_audit, list_users, make_token, now,
                  password_problems, require, temp_password, update_user, user_exists)
from datetime import timedelta

RESULTS = os.environ.get("RESULTS_DIR", "results_v2")
USER_RE, DAY_RE = r"^[A-Z]{3}[0-9]{4}$", r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"

def slim(df):
    """Keep memory low enough for small hosts (Render free tier = 512 MB)."""
    for c in df.columns:
        if df[c].dtype == "float64":
            df[c] = df[c].astype("float32")
        elif df[c].dtype == "int64" and c not in ("severity",):
            df[c] = pd.to_numeric(df[c], downcast="integer")
        elif c in ("user", "pc", "verdict", "rules", "ext", "event", "activity"):
            df[c] = df[c].astype("category")
    return df


# Only the columns used for timelines/overview stay in memory; per-day detail is read on demand.
CORE = ["user", "day", "anomaly_score", "policy_raw", "policy_norm", "chain_score", "evidence", "risk", "alert",
        "label", "file_copies"]
DAILY_PATH = f"{RESULTS}/daily.parquet"
daily = slim(pq.read_table(DAILY_PATH, columns=CORE).to_pandas(self_destruct=True))
DAILY_FILE = pq.ParquetFile(DAILY_PATH)
_rg_rows = np.cumsum([DAILY_FILE.metadata.row_group(i).num_rows for i in range(DAILY_FILE.num_row_groups)])


def read_user_day(uid, ts):
    """Read only the parquet row groups that hold this employee-day (keeps memory flat)."""
    idx = daily.index[(daily["user"] == uid) & (daily["day"] == ts)]
    if len(idx) == 0:
        return pd.DataFrame()
    rg = int(np.searchsorted(_rg_rows, idx[0], side="right"))
    t = DAILY_FILE.read_row_group(rg).to_pandas()
    return t[(t["user"].astype(str) == uid) & (t["day"] == ts)]
users = pd.read_parquet(f"{RESULTS}/users.parquet")
files = slim(pd.read_parquet(f"{RESULTS}/file_events.parquet"))
access = slim(pd.read_parquet(f"{RESULTS}/access_events.parquet"))
ablation = pd.read_csv(f"{RESULTS}/ablation.csv")
POL = json.load(open(f"{RESULTS}/policy.json"))
ALERT_AT = float(ablation.loc[ablation["layer"].str.startswith("L5"), "alert_threshold"].iloc[0])
FEATS = ["logons", "distinct_pcs", "after_hours_logons", "usb_connects", "usb_after_hours", "file_copies",
         "foreign_pc_logons", "exe_copies", "distinct_file_types", "files_after_hours",
         "first_usb", "first_after_hours", "first_foreign_pc"]
_model = {}


def model():
    """The ML model (and scikit-learn) is loaded on first live-scoring request to keep start-up memory low."""
    if not _model:
        _model.update(joblib.load(f"{RESULTS}/model_v2.joblib"))
    return _model
live_risk = {}

app = FastAPI(title="TERPE v2 — Insider Threat Detection API for SMEs")
init_db()


def records(df):
    return json.loads(df.to_json(orient="records", date_format="iso"))


def known_user(uid):
    if uid not in set(users["user"]):
        raise HTTPException(404, "Unknown employee")


# ================================================================== AUTH
class SignupIn(BaseModel):
    username: str = Field(..., pattern=r"^[A-Za-z0-9_.]{3,40}$")
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = Field(..., min_length=2, max_length=120)
    organisation: str = Field("", max_length=120)
    reason: str = Field("", max_length=500)
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


class ChangePwIn(BaseModel):
    old_password: str
    new_password: str


@app.get("/health")
def health():
    return {"status": "ok", "employees": int(len(users)), "version": "2.0"}


@app.post("/auth/signup")
def signup(b: SignupIn):
    probs = password_problems(b.password, b.username)
    if probs:
        raise HTTPException(422, "Password must have: " + ", ".join(probs))
    if user_exists(b.username, b.email.lower()):
        raise HTTPException(409, "Username or email already registered")
    create_user(username=b.username, email=b.email.lower(), full_name=b.full_name, organisation=b.organisation,
                reason=b.reason, password_hash=hash_pw(b.password), role="viewer", status="pending")
    audit(b.username, "SIGNUP_REQUEST", b.username, b.reason)
    return {"message": "Request received. An administrator must approve your account before you can sign in."}


@app.post("/auth/login")
def login(b: LoginIn):
    u = get_user(username=b.username)
    locked = _dt(u.locked_until) if u else None
    if locked and locked > now():
        mins = max(1, -(-int((locked - now()).total_seconds()) // 60))
        raise HTTPException(423, f"Account locked after too many failed attempts. Try again in {mins} min.")
    if not u or not check_pw(b.password, u.password_hash):
        if u:
            fails = (u.failed_attempts or 0) + 1
            if fails >= MAX_FAILS:
                update_user(u.id, failed_attempts=0, locked_until=_ts(now() + timedelta(minutes=LOCK_MINUTES)))
            else:
                update_user(u.id, failed_attempts=fails)
        audit(b.username, "LOGIN_FAILED")
        raise HTTPException(401, "Incorrect username or password")
    if u.status == "pending":
        raise HTTPException(403, "Your account is waiting for administrator approval")
    if u.status in ("disabled", "rejected"):
        raise HTTPException(403, f"Your account is {u.status}. Contact an administrator.")
    update_user(u.id, failed_attempts=0, locked_until=None, last_login=_ts(now()))
    u = get_user(uid=u.id)
    audit(b.username, "LOGIN")
    return {"token": make_token(u), "user": u.public()}


@app.get("/auth/me")
def me(u: User = Depends(current_user)):
    return u.public()


@app.post("/auth/change-password")
def change_password(b: ChangePwIn, u: User = Depends(current_user)):
    if not check_pw(b.old_password, u.password_hash):
        raise HTTPException(401, "Current password is incorrect")
    probs = password_problems(b.new_password, u.username)
    if probs:
        raise HTTPException(422, "Password must have: " + ", ".join(probs))
    if b.new_password == b.old_password:
        raise HTTPException(422, "New password must be different")
    update_user(u.id, password_hash=hash_pw(b.new_password), must_change_password=0)
    audit(u.username, "PASSWORD_CHANGED", u.username)
    return {"message": "Password updated"}


# ================================================================== ADMIN
class UserPatch(BaseModel):
    role: str | None = None
    status: str | None = None


class CreateUserIn(BaseModel):
    username: str = Field(..., pattern=r"^[A-Za-z0-9_.]{3,40}$")
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str
    role: str = "analyst"


@app.get("/admin/users")
def admin_users(a: User = Depends(require("admin"))):
    return [u.public() for u in list_users()]


@app.post("/admin/users")
def admin_create(b: CreateUserIn, a: User = Depends(require("admin"))):
    if b.role not in ROLES:
        raise HTTPException(422, "Unknown role")
    if b.role == "admin" and a.username != OWNER:
        raise HTTPException(403, "Only the owner can create admin accounts")
    if user_exists(b.username, b.email.lower()):
        raise HTTPException(409, "Username or email already registered")
    pw = temp_password()
    create_user(username=b.username, email=b.email.lower(), full_name=b.full_name, role=b.role, status="active",
                password_hash=hash_pw(pw), must_change_password=1, approved_by=a.username)
    audit(a.username, "USER_CREATED", b.username, f"role={b.role}")
    return {"message": "Account created", "temporary_password": pw}


@app.patch("/admin/users/{uid}")
def admin_patch(uid: int, b: UserPatch, a: User = Depends(require("admin"))):
    if b.role and b.role not in ROLES:
        raise HTTPException(422, "Unknown role")
    if b.role == "admin" and a.username != OWNER:
        raise HTTPException(403, "Only the owner can give someone the admin role")
    if b.status and b.status not in ("active", "disabled", "rejected", "pending"):
        raise HTTPException(422, "Unknown status")
    u = get_user(uid=uid)
    if not u:
        raise HTTPException(404, "No such account")
    if u.username == a.username and ((b.role and b.role != "admin") or (b.status and b.status != "active")):
        raise HTTPException(422, "You cannot demote or disable your own admin account")
    if u.username == OWNER and a.username != OWNER:
        raise HTTPException(403, "The owner account can only be changed by the owner")
    changes, upd = [], {}
    if b.role and b.role != u.role:
        changes.append(f"role {u.role}→{b.role}"); upd["role"] = b.role
    if b.status and b.status != u.status:
        if u.status == "pending" and b.status == "active":
            upd["approved_by"] = a.username
        changes.append(f"status {u.status}→{b.status}"); upd["status"] = b.status
    update_user(uid, **upd)
    audit(a.username, "USER_UPDATED", u.username, ", ".join(changes))
    return {"message": "Updated", "changes": changes}


@app.post("/admin/users/{uid}/reset-password")
def admin_reset(uid: int, a: User = Depends(require("admin"))):
    u = get_user(uid=uid)
    if not u:
        raise HTTPException(404, "No such account")
    if u.username == OWNER and a.username != OWNER:
        raise HTTPException(403, "The owner account can only be changed by the owner")
    pw = temp_password()
    update_user(uid, password_hash=hash_pw(pw), must_change_password=1, failed_attempts=0, locked_until=None)
    audit(a.username, "PASSWORD_RESET", u.username)
    return {"temporary_password": pw}


@app.get("/admin/audit")
def admin_audit(limit: int = Query(300, le=5000), a: User = Depends(require("admin"))):
    return list_audit(limit)


# ================================================================== DATA (viewer+)
@app.get("/users/top")
def top_users(n: int = Query(100, ge=1, le=1000), u: User = Depends(require("viewer"))):
    cols = ["user", "role", "department", "peak_risk", "peak_score", "alert_days", "anomaly_days",
            "violations", "chain_days", "ground_truth_insider", "scenario"]
    return records(users.head(n)[cols])


def _overview():
    fv = {str(k): int(v) for k, v in files["verdict"].value_counts().items()}
    by_rule = {r: 0 for r in POL["rules"]}
    for df in (files, access):  # count via the (few) distinct rule combinations — cheap on memory
        for combo, n in df["rules"].value_counts().items():
            for r in str(combo).split("|"):
                if r in by_rule:
                    by_rule[r] += int(n)
    wk = pd.to_datetime(daily["day"]).dt.to_period("W").dt.start_time
    weekly = pd.DataFrame({"week": wk, "alerts": daily["alert"].astype(int), "violations": (daily["policy_raw"] > 0).astype(int)})
    weekly = weekly.groupby("week").sum().reset_index()
    return {"employees": int(len(users)), "alerting_employees": int((users["alert_days"] > 0).sum()),
            "file_verdicts": fv, "rule_hits": by_rule, "weekly": records(weekly),
            "alert_threshold": ALERT_AT}


OVERVIEW = _overview()
FLAGGED_FILES = files[files["verdict"] != "AUTHORISED"].sort_values("ts", ascending=False).reset_index(drop=True)


@app.get("/overview")
def overview(u: User = Depends(require("viewer"))):
    return OVERVIEW


@app.get("/evaluation")
def evaluation(u: User = Depends(require("viewer"))):
    return {"ablation": records(ablation), "policy": POL}


# ================================================================== INVESTIGATION (analyst+)
@app.get("/users/{uid}/profile")
def profile(uid: str = Path(..., pattern=USER_RE), u: User = Depends(require("analyst"))):
    known_user(uid)
    audit(u.username, "VIEW_EMPLOYEE", uid)
    return records(users[users["user"] == uid])[0]


@app.get("/users/{uid}/timeline")
def timeline(uid: str = Path(..., pattern=USER_RE), u: User = Depends(require("analyst"))):
    known_user(uid)
    d = daily[daily["user"] == uid][["day", "anomaly_score", "policy_norm", "chain_score", "evidence",
                                     "risk", "alert", "label", "file_copies"]].copy()
    d["day"] = pd.to_datetime(d["day"]).dt.strftime("%Y-%m-%d")
    return records(d)


@app.get("/users/{uid}/day/{day}")
def day_detail(uid: str = Path(..., pattern=USER_RE), day: str = Path(..., pattern=DAY_RE),
               u: User = Depends(require("analyst"))):
    known_user(uid)
    ts = pd.Timestamp(day)
    r = read_user_day(uid, ts)
    if r.empty:
        raise HTTPException(404, "No activity for that employee on that day")
    r = r.iloc[0]
    feats = FEATS
    dev = [{"feature": f, "value": float(r[f]), "z_self": round(float(r[f + "_zself"]), 2),
            "z_peer": round(float(r[f + "_zpeer"]), 2)} for f in feats]
    dev.sort(key=lambda x: max(abs(x["z_self"]), abs(x["z_peer"])), reverse=True)
    f = files[(files["user"] == uid) & (files["ts"].dt.normalize() == ts)].sort_values("ts")
    a = access[(access["user"] == uid) & (access["ts"].dt.normalize() == ts)].sort_values("ts")
    audit(u.username, "VIEW_EMPLOYEE_DAY", uid, day)
    return {"user": uid, "day": day, "reasons": json.loads(r["reasons"]),
            "scores": {k: float(r[k]) for k in ("anomaly_score", "anomaly_excess", "policy_norm", "chain_score",
                                                 "evidence", "risk")},
            "alert": bool(r["alert"]), "label": int(r["label"]), "deviations": dev[:8],
            "files": records(f.assign(ts=f["ts"].dt.strftime("%H:%M:%S"))),
            "access": records(a.assign(ts=a["ts"].dt.strftime("%H:%M:%S")))}


@app.get("/users/{uid}/files")
def user_files(uid: str = Path(..., pattern=USER_RE), verdict: str | None = None,
               u: User = Depends(require("analyst"))):
    known_user(uid)
    f = files[files["user"] == uid].copy()
    if verdict:
        f = f[f["verdict"] == verdict.upper()]
    audit(u.username, "VIEW_EMPLOYEE_FILES", uid, verdict or "all")
    f = f.sort_values("ts", ascending=False)
    return records(f.assign(ts=f["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")))


@app.get("/files/feed")
def file_feed(verdict: str = Query("VIOLATION"), limit: int = Query(500, le=5000),
              u: User = Depends(require("analyst"))):
    f = FLAGGED_FILES[FLAGGED_FILES["verdict"] == verdict.upper()].head(limit)
    audit(u.username, "VIEW_FILE_FEED", verdict)
    return records(f.assign(ts=f["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")))


# ================================================================== LIVE SCORING (analyst+)
class LiveIn(BaseModel):
    user_id: str = Field(..., pattern=USER_RE)
    features: dict[str, float]


@app.post("/score")
def score(b: LiveIn, u: User = Depends(require("analyst"))):
    known_user(b.user_id)
    M = model()
    ctx, sb = M["ctx"].loc[b.user_id], M["self_base"].loc[b.user_id]
    pb = M["peer_base"].loc[ctx["role"]] if ctx["role"] in M["peer_base"].index else M["peer_base"].mean()
    x = {f: float(b.features.get(f, 0.0)) for f in M["feats"]}
    if any(v < 0 or v > 100000 for v in x.values()):
        raise HTTPException(422, "Feature values out of range")
    x["first_usb"] = float(x["usb_connects"] > 0 and sb["usb_connects_mean"] == 0)
    x["first_after_hours"] = float(x["after_hours_logons"] > 0 and sb["after_hours_logons_mean"] == 0)
    x["first_foreign_pc"] = float(x["foreign_pc_logons"] > 0 and sb["foreign_pc_logons_mean"] == 0)
    row = dict(x)
    for f in M["feats"]:
        row[f + "_zself"] = (x[f] - sb[f + "_mean"]) / max(np.nan_to_num(sb[f + "_std"]), 1.0)
        row[f + "_zpeer"] = (x[f] - pb[f + "_mean"]) / max(np.nan_to_num(pb[f + "_std"]), 1.0)
    X = pd.DataFrame([row])[M["cols"]].values
    s = float(-M["model"].score_samples(X)[0])
    excess = max(0.0, (s - M["thr"]) / max(M["top"] - M["thr"], 1e-9))
    multi = bool(ctx["role"] in POL["multi_pc_roles"])
    ah_ok = bool(ctx.get("after_hours_approved", False))
    n = {"AFTER_HOURS": 0 if ah_ok else x["after_hours_logons"] + x["usb_after_hours"] + x["files_after_hours"],
         "FOREIGN_PC": 0 if multi else x["foreign_pc_logons"],
         "USB_NOT_PROVISIONED": 0 if ctx["usb_approved"] else x["usb_connects"] + x["file_copies"],
         "EXECUTABLE_TRANSFER": 0 if ctx["role"] in POL["executable_allowed_roles"] else x["exe_copies"]}
    praw = sum(POL["rules"][k]["severity"] * np.log1p(v) for k, v in n.items())
    pnorm = min(praw / M["p99"], 3.0)
    chains = {"CHAIN_AFTER_HOURS_EXFIL": bool((not ah_ok) and x["after_hours_logons"] > 0 and x["usb_after_hours"] > 0 and x["files_after_hours"] > 0),
              "CHAIN_FOREIGN_PC_TRANSFER": bool((not multi) and x["foreign_pc_logons"] > 0 and x["file_copies"] > 0),
              "CHAIN_FIRST_MEDIA_BURST": bool(x["first_usb"] > 0 and x["file_copies"] > 0)}
    w = POL["fusion_weights"]
    e = w["anomaly"] * excess + w["policy"] * pnorm + w["chain"] * sum(chains.values())
    prev = live_risk.get(b.user_id, float(M["last"].loc[b.user_id, "risk"]) if b.user_id in M["last"].index else 0.0)
    risk = POL["decay"] * prev + e
    live_risk[b.user_id] = risk
    audit(u.username, "LIVE_SCORE", b.user_id, json.dumps(x))
    return {"user_id": b.user_id, "anomaly_score": round(s, 4), "anomalous_day": bool(s > M["thr"]),
            "anomaly_component": round(float(excess), 3), "policy_component": round(float(pnorm), 3),
            "chain_component": int(sum(chains.values())), "evidence": round(float(e), 3), "risk": round(float(risk), 3),
            "alert": bool(risk >= M["alert_at"]), "alert_threshold": round(float(M["alert_at"]), 3),
            "policy_hits": {k: float(v) for k, v in n.items() if v}, "chains": [k for k, v in chains.items() if v],
            "context": {"role": str(ctx["role"]), "department": str(ctx["department"]), "assigned_pc": str(ctx["assigned_pc"]),
                        "usb_approved": bool(ctx["usb_approved"]), "after_hours_approved": ah_ok}}
