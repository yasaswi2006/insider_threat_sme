
import os, hmac, json
import joblib
import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query
from pydantic import BaseModel, Field

USER_RE = "^[A-Z]{3}[0-9]{4}$"
DAY_RE = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
def _read_key():
    k = os.environ.get("API_KEY", "")
    if k:
        return k
    try:
        for line in open(".streamlit/secrets.toml", encoding="utf-8"):
            if line.startswith("API_KEY"):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


API_KEY = _read_key()

meta = joblib.load("results/model.joblib")
model, THR = meta["model"], meta["thr"]
FE, COLS = meta["features"], meta["cols"]
DECAY, ALERT_AT = meta["decay"], meta["alert_at"]

scores = pd.read_csv("results/scores.csv", parse_dates=["day"])
stats = pd.read_csv("results/user_stats.csv", index_col="user")
summary = pd.read_csv("results/user_summary.csv")
risk_state = {}   # live risk per user (in memory, resets when the server restarts)

app = FastAPI(title="Insider Threat Detection API for SMEs")


def auth(x_api_key: str = Header(default="")):
    if not API_KEY or not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def top_reasons(zvals, raw, n=3):
    order = sorted(FE, key=lambda f: abs(zvals[f]), reverse=True)[:n]
    return [{"feature": f, "value": round(float(raw[f]), 2),
             "z_score": round(float(zvals[f]), 2)} for f in order]


@app.get("/health")
def health():
    return {"status": "ok", "users_loaded": int(len(summary))}


@app.get("/users/top", dependencies=[Depends(auth)])
def top_users(n: int = Query(20, ge=1, le=1000)):
    return json.loads(summary.head(n).to_json(orient="records"))


@app.get("/users/{user_id}/timeline", dependencies=[Depends(auth)])
def timeline(user_id: str = Path(..., pattern=USER_RE)):
    u = scores[scores["user"] == user_id].sort_values("day")
    if u.empty:
        raise HTTPException(status_code=404, detail="No timeline for this user")
    u = u[["day", "anomaly_score", "risk", "alert", "label"]].copy()
    u["day"] = u["day"].dt.strftime("%Y-%m-%d")
    return json.loads(u.to_json(orient="records"))


@app.get("/users/{user_id}/explain", dependencies=[Depends(auth)])
def explain(user_id: str = Path(..., pattern=USER_RE),
            day: str = Query(..., pattern=DAY_RE)):
    try:
        ts = pd.Timestamp(day)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid date")
    r = scores[(scores["user"] == user_id) & (scores["day"] == ts)]
    if r.empty:
        raise HTTPException(status_code=404, detail="No data for that user and day")
    r = r.iloc[0]
    z = {f: r[f + "_z"] for f in FE}
    return {"user": user_id, "day": day, "reasons": top_reasons(z, r)}


class DayIn(BaseModel):
    user_id: str = Field(..., pattern=USER_RE)
    features: dict[str, float]


@app.post("/score", dependencies=[Depends(auth)])
def score_day(body: DayIn):
    if body.user_id not in stats.index:
        raise HTTPException(status_code=404, detail="Unknown user (no baseline)")
    missing = [f for f in FE if f not in body.features]
    if missing:
        raise HTTPException(status_code=422, detail=f"Missing features: {missing}")
    vals = {f: body.features[f] for f in FE}
    if not all(0 <= v <= 100000 for v in vals.values()):
        raise HTTPException(status_code=422, detail="Feature values out of range")
    base = stats.loc[body.user_id]
    z = {f: (vals[f] - base[f + "_mean"]) / base[f + "_std"] for f in FE}
    x = pd.DataFrame([{**vals, **{f + "_z": z[f] for f in FE}}])[COLS]
    s = float(-model.score_samples(x)[0])
    new_risk = DECAY * risk_state.get(body.user_id, 0.0) + max(0.0, s - THR)
    risk_state[body.user_id] = new_risk
    return {"user_id": body.user_id,
            "anomaly_score": round(s, 4),
            "anomalous_day": s > THR,
            "risk": round(new_risk, 4),
            "alert": new_risk >= ALERT_AT,
            "reasons": top_reasons(z, vals)}
