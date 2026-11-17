"""
TERPE v2 pipeline — Policy-grounded, peer-aware insider risk profiling.

Reads raw CERT r4.2 logs (logon, device, file, LDAP, answers) and produces everything
the API and dashboard need, plus an ablation study comparing TERPE v1 with each new layer.

    python pipeline.py --data data --out results_v2

Layers (each one is switched on in turn in the ablation study):
  L0  v1 replica      Isolation Forest on 6 daily counts + full-period z-scores (what TERPE v1 did)
  L1  causal baseline z-scores use ONLY the user's past days (v1 leaked future data)
  L2  peer baseline   + deviation from same-department peers on the same day
  L3  context feats   + foreign-PC logons, executable transfers, first-time behaviours
  L4  policy fusion   + authorisation verdict of every logon / USB / file event
  L5  chains          + ordered exfiltration chains  (= full TERPE v2)
  R   rules only      policy + chains without any ML (shows the ML still adds value)
"""
import argparse
import csv
import glob
import json
import os

import joblib
import iforest_lite
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

DATEFMT = "%m/%d/%Y %H:%M:%S"

DEFAULT_POLICY = {
    "work_hours": {"start": 7, "end": 19, "weekend_is_after_hours": True},
    "provisioning_days": 30,
    "multi_pc_roles": ["ITAdmin"],
    "executable_extensions": [".exe", ".dll", ".bat", ".msi", ".ps1", ".vbs"],
    "executable_allowed_roles": ["ITAdmin"],
    "rules": {
        "FOREIGN_PC": {"severity": 3, "text": "Used a PC this employee is not approved to use"},
        "USB_NOT_PROVISIONED": {"severity": 3, "text": "Removable media used, but employee is not approved for USB"},
        "EXECUTABLE_TRANSFER": {"severity": 3, "text": "New executable moved via removable media by a non-IT role"},
        "AFTER_HOURS": {"severity": 1, "text": "After-hours activity by an employee not approved for after-hours work"},
        "NEW_FILE_TYPE": {"severity": 1, "text": "File type never handled by this employee before"},
    },
    "decay": 0.8,
    "alert_budget": 0.01,
    "fusion_weights": {"anomaly": 1.0, "policy": 1.0, "chain": 1.0},
}

V1_FEATS = ["logons", "distinct_pcs", "after_hours_logons", "usb_connects", "usb_after_hours", "file_copies"]
CTX_FEATS = ["foreign_pc_logons", "exe_copies", "distinct_file_types", "files_after_hours",
             "first_usb", "first_after_hours", "first_foreign_pc"]
ALL_FEATS = V1_FEATS + CTX_FEATS
CHAINS = {
    "CHAIN_AFTER_HOURS_EXFIL": "After-hours logon → USB connected → files copied (in that order)",
    "CHAIN_FOREIGN_PC_TRANSFER": "Logged on to someone else's PC → copied files on that PC",
    "CHAIN_FIRST_MEDIA_BURST": "First-ever removable-media use with files copied the same day",
}


# ---------------------------------------------------------------- loading
def read_events(path, cols):
    df = pd.read_csv(path, usecols=cols)
    df["ts"] = pd.to_datetime(df["date"], format=DATEFMT)
    df["day"] = df["ts"].dt.normalize()
    return df.drop(columns="date")


def load_ldap(folder):
    frames = []
    for f in sorted(glob.glob(os.path.join(folder, "*.csv"))):
        d = pd.read_csv(f)
        d["month"] = os.path.basename(f)[:7]
        frames.append(d)
    ldap = pd.concat(frames, ignore_index=True)
    dept_col = next(c for c in ["department", "functional_unit", "business_unit"] if c in ldap.columns)
    prof = (ldap.sort_values("month").groupby("user_id")
            .agg(name=("employee_name", "last"), role=("role", "last"), department=(dept_col, "last"),
                 first_month=("month", "min"), last_month=("month", "max")))
    prof.index.name = "user"
    return prof


def load_labels(answers_dir, dataset="4.2"):
    ins = pd.read_csv(os.path.join(answers_dir, "insiders.csv"))
    ins = ins[ins["dataset"].astype(str).str.strip() == dataset]
    rows = []
    for _, r in ins.iterrows():
        fp = glob.glob(os.path.join(answers_dir, f"r{dataset}-{r['scenario']}", str(r["details"])))
        if fp:
            with open(fp[0], newline="", encoding="utf-8", errors="ignore") as f:
                for rec in csv.reader(f):
                    if len(rec) >= 4 and rec[3] == r["user"]:  # skip rows about other users (e.g. emails received)
                        rows.append((rec[3], rec[2], rec[0]))
    lab = pd.DataFrame(rows, columns=["user", "date", "source"])
    lab["day"] = pd.to_datetime(lab["date"], format=DATEFMT, errors="coerce").dt.normalize()
    lab = lab.dropna(subset=["day"])
    scen = ins.set_index("user")["scenario"].to_dict()
    return lab, scen


# ---------------------------------------------------------------- policy layer
def after_hours(ts, pol):
    wh = pol["work_hours"]
    ah = (ts.dt.hour < wh["start"]) | (ts.dt.hour >= wh["end"])
    if wh.get("weekend_is_after_hours", True):
        ah |= ts.dt.weekday >= 5
    return ah


def provision(logon, device, files, prof, pol):
    """Learn each employee's approved context from their first N days (an SME would set this by hand)."""
    first = logon.groupby("user")["day"].min().rename("first_day")
    prov_end = (first + pd.Timedelta(days=pol["provisioning_days"])).rename("prov_end")
    lg = logon.join(prov_end, on="user")
    in_prov = lg[lg["day"] < lg["prov_end"]]
    assigned = in_prov.groupby("user")["pc"].agg(lambda s: s.mode().iat[0])
    assigned = assigned.combine_first(logon.groupby("user")["pc"].agg(lambda s: s.mode().iat[0]))
    dv = device.join(prov_end, on="user")
    usb_ok = dv[dv["day"] < dv["prov_end"]].groupby("user").size().gt(0)
    fl = files.join(prov_end, on="user")
    known_ext = fl[fl["day"] < fl["prov_end"]].groupby("user")["ext"].agg(lambda s: sorted(set(s)))
    ctx = pd.DataFrame({"first_day": first, "prov_end": prov_end, "assigned_pc": assigned})
    ctx["usb_approved"] = usb_ok.reindex(ctx.index).fillna(False).astype(bool)
    pcs = in_prov[in_prov["activity"] == "Logon"].groupby("user")["pc"].agg(lambda s: sorted(set(s)))
    ctx["approved_pcs"] = pcs.reindex(ctx.index)
    ctx["approved_pcs"] = [v if isinstance(v, list) else [a] for v, a in zip(ctx["approved_pcs"], ctx["assigned_pc"])]
    ah = in_prov[(in_prov["activity"] == "Logon") & after_hours(in_prov["ts"], pol)].groupby("user").size().gt(0)
    ctx["after_hours_approved"] = ah.reindex(ctx.index).fillna(False).astype(bool)
    ctx["known_ext"] = known_ext.reindex(ctx.index)
    ctx["known_ext"] = ctx["known_ext"].apply(lambda v: v if isinstance(v, list) else [])
    ctx = ctx.join(prof, how="left")
    ctx["role"] = ctx["role"].fillna("Unknown")
    ctx["department"] = ctx["department"].fillna("Unknown")
    return ctx


def annotate(df, kind, ctx, pol):
    """Attach authorisation verdict + violated rules to every event."""
    d = df.join(ctx[["assigned_pc", "approved_pcs", "usb_approved", "after_hours_approved", "prov_end", "role",
                     "known_ext"]], on="user")
    rules = pd.DataFrame(index=d.index)
    multi = d["role"].isin(pol["multi_pc_roles"])
    post = d["day"] >= d["prov_end"]
    approved_pc = pd.Series([p in a for p, a in zip(d["pc"], d["approved_pcs"])], index=d.index)
    rules["FOREIGN_PC"] = ~approved_pc & ~multi & post
    rules["AFTER_HOURS"] = after_hours(d["ts"], pol) & ~d["after_hours_approved"] & post
    if kind in ("device", "file"):
        rules["USB_NOT_PROVISIONED"] = ~d["usb_approved"] & (d["day"] >= d["prov_end"])
    if kind == "file":
        known = pd.Series([e in k for e, k in zip(d["ext"], d["known_ext"])], index=d.index)
        exe = d["ext"].isin(pol["executable_extensions"])
        rules["EXECUTABLE_TRANSFER"] = exe & ~known & ~d["role"].isin(pol["executable_allowed_roles"]) & post
        rules["NEW_FILE_TYPE"] = ~known & ~exe & post
    sev = pd.Series({k: v["severity"] for k, v in pol["rules"].items()})
    m = rules.values
    d["rules"] = ["|".join(rules.columns[row]) for row in m]
    d["severity"] = (m * sev[rules.columns].values).sum(axis=1)
    maxsev = (m * sev[rules.columns].values).max(axis=1) if m.shape[1] else 0
    d["verdict"] = np.where(maxsev >= 3, "VIOLATION", np.where(maxsev > 0, "REVIEW", "AUTHORISED"))
    for c in rules.columns:
        d["r_" + c] = rules[c].values
    d["is_after_hours"] = after_hours(d["ts"], pol).values  # raw clock fact, used for behaviour features
    return d.drop(columns=["known_ext", "assigned_pc", "approved_pcs", "usb_approved", "after_hours_approved", "prov_end"])


# ---------------------------------------------------------------- daily features
def daily_features(lg, dv, fl, ctx):
    g = ["user", "day"]
    lon = lg[lg["activity"] == "Logon"]
    con = dv[dv["activity"] == "Connect"]
    parts = [
        lon.groupby(g).size().rename("logons"),
        lon.groupby(g)["pc"].nunique().rename("distinct_pcs"),
        lon[lon["is_after_hours"]].groupby(g).size().rename("after_hours_logons"),
        con.groupby(g).size().rename("usb_connects"),
        con[con["is_after_hours"]].groupby(g).size().rename("usb_after_hours"),
        fl.groupby(g).size().rename("file_copies"),
        lon[lon["r_FOREIGN_PC"]].groupby(g).size().rename("foreign_pc_logons"),
        fl[fl["r_EXECUTABLE_TRANSFER"]].groupby(g).size().rename("exe_copies"),
        fl.groupby(g)["ext"].nunique().rename("distinct_file_types"),
        fl[fl["is_after_hours"]].groupby(g).size().rename("files_after_hours"),
    ]
    day = pd.concat(parts, axis=1).fillna(0).reset_index().sort_values(g).reset_index(drop=True)
    day = day.join(ctx[["prov_end", "role", "department"]], on="user")
    post = day["day"] >= day["prov_end"]
    for src, name in [("usb_connects", "first_usb"), ("after_hours_logons", "first_after_hours"),
                      ("foreign_pc_logons", "first_foreign_pc")]:
        seen_before = day.groupby("user")[src].transform(lambda s: s.gt(0).cumsum().shift(1).fillna(0)) > 0
        day[name] = ((day[src] > 0) & ~seen_before & post).astype(int)
    return day


def add_baselines(day, feats):
    g = day.groupby("user")
    for f in feats:
        # L0 (v1): full-period mean/std — uses the future, kept only to reproduce v1
        mu, sd = g[f].transform("mean"), g[f].transform("std").fillna(0)
        day[f + "_zfull"] = (day[f] - mu) / sd.where(sd > 1e-9, 1.0)
        # L1: causal — only days strictly before today
        past = g[f].shift(1)
        cm = past.groupby(day["user"]).transform(lambda s: s.expanding(5).mean())
        cs = past.groupby(day["user"]).transform(lambda s: s.expanding(5).std())
        day[f + "_zself"] = ((day[f] - cm) / cs.clip(lower=1.0)).fillna(0.0)
        # L2: peers — same job role, same day
        pg = day.groupby(["role", "day"])[f]
        pm, ps = pg.transform("mean"), pg.transform("std").fillna(0)
        day[f + "_zpeer"] = (day[f] - pm) / ps.clip(lower=1.0)
    return day


def add_chains(day, lg, dv, fl):
    g = ["user", "day"]
    ah_logon = lg[(lg["activity"] == "Logon") & lg["r_AFTER_HOURS"]].groupby(g)["ts"].min().rename("t1")
    con = dv[(dv["activity"] == "Connect") & dv["r_AFTER_HOURS"]][g + ["ts"]].join(ah_logon, on=g, how="inner")
    t2 = con[con["ts"] >= con["t1"]].groupby(g)["ts"].min().rename("t2")
    f2 = fl[g + ["ts"]].join(t2, on=g, how="inner")
    c1 = f2[f2["ts"] >= f2["t2"]].groupby(g).size().gt(0).rename("CHAIN_AFTER_HOURS_EXFIL")

    flog = lg[(lg["activity"] == "Logon") & lg["r_FOREIGN_PC"]].groupby(g + ["pc"])["ts"].min().rename("tl")
    ff = fl[g + ["pc", "ts"]].join(flog, on=g + ["pc"], how="inner")
    c2 = ff[ff["ts"] >= ff["tl"]].groupby(g).size().gt(0).rename("CHAIN_FOREIGN_PC_TRANSFER")

    day = day.join(c1, on=g).join(c2, on=g)
    day["CHAIN_FIRST_MEDIA_BURST"] = (day["first_usb"] > 0) & (day["file_copies"] > 0)
    for c in CHAINS:
        day[c] = day[c].fillna(False).astype(bool)
    day["chain_score"] = day[list(CHAINS)].sum(axis=1).astype(float)
    return day


def add_policy_score(day, lg, dv, fl, pol):
    sev = {k: v["severity"] for k, v in pol["rules"].items()}
    ev = pd.concat([lg[lg["activity"] == "Logon"], dv[dv["activity"] == "Connect"], fl], ignore_index=True)
    cnt = {}
    for r in sev:
        c = "r_" + r
        if c in ev.columns:
            cnt[r] = ev[ev[c].fillna(False).astype(bool)].groupby(["user", "day"]).size()
    cnt = pd.DataFrame(cnt).fillna(0)
    # each rule contributes severity * log(1 + count): 50 copies ≠ 50x the risk of 1
    score = sum(sev[r] * np.log1p(cnt[r]) for r in cnt.columns).rename("policy_raw")
    day = day.join(score, on=["user", "day"])
    day["policy_raw"] = day["policy_raw"].fillna(0.0)
    for r in cnt.columns:
        day["n_" + r] = day.join(cnt[r].rename("x"), on=["user", "day"])["x"].fillna(0).astype(int).values
    return day


# ---------------------------------------------------------------- detector + risk
def isolation(day, cols, seed=42):
    X = day[cols].astype(float).values
    m = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(X)
    s = -m.score_samples(X)
    thr, top = np.quantile(s, 0.95), np.quantile(s, 0.999)
    excess = np.clip((s - thr) / max(top - thr, 1e-9), 0, None)
    return m, s, excess, thr, top


def accumulate(day, evidence, decay):
    risk = np.zeros(len(day))
    users, days = day["user"].values, day["day"].values
    r, prev_u, prev_d = 0.0, None, None
    for i in range(len(day)):
        if users[i] != prev_u:
            r = 0.0
        else:
            gap = (days[i] - prev_d) / np.timedelta64(1, "D")
            r *= decay ** gap  # decay by calendar days, not by active days
        r += evidence[i]
        risk[i] = r
        prev_u, prev_d = users[i], days[i]
    return risk


# ---------------------------------------------------------------- evaluation
def evaluate(day, evidence, risk, insiders, budget):
    thr = np.quantile(risk, 1 - budget)
    alert = risk >= thr
    d = day[["user", "day", "label"]].copy()
    d["e"], d["risk"], d["alert"] = evidence, risk, alert
    users = d.groupby("user").agg(peak=("risk", "max"), any_alert=("alert", "any"))
    users["insider"] = users.index.isin(insiders).astype(int)
    out = {}
    out["day_auc"] = roc_auc_score(d["label"], d["e"]) if d["label"].nunique() > 1 else np.nan
    if "obs_label" in day:
        out["day_auc_observable"] = roc_auc_score(day["obs_label"], d["e"]) if day["obs_label"].nunique() > 1 else np.nan
    out["day_ap"] = average_precision_score(d["label"], d["e"]) if d["label"].nunique() > 1 else np.nan
    out["user_auc"] = roc_auc_score(users["insider"], users["peak"])
    out["user_ap"] = average_precision_score(users["insider"], users["peak"])
    rank = users.sort_values("peak", ascending=False)
    for k in (10, 20, 50):
        out[f"p@{k}"] = rank.head(k)["insider"].mean()
    mal = d[d["label"] == 1].groupby("user")["day"].agg(["min", "max"])
    delays, hit = [], 0
    for u, (s, e) in mal.iterrows():
        a = d[(d["user"] == u) & d["alert"] & (d["day"] >= s) & (d["day"] <= e + pd.Timedelta(days=7))]
        if len(a):
            hit += 1
            delays.append((a["day"].min() - s).days)
    out["insiders_detected"] = f"{hit}/{len(mal)}"
    out["detection_rate"] = hit / max(len(mal), 1)
    out["median_delay_days"] = float(np.median(delays)) if delays else np.nan
    out["false_alert_users"] = int((users["any_alert"] & (users["insider"] == 0)).sum())
    out["alert_threshold"] = float(thr)
    return out, alert


def compact(df):
    """float32 + categories so the API fits on small hosts (Render free tier: 512 MB)."""
    for c in df.columns:
        if df[c].dtype == "float64":
            df[c] = df[c].astype("float32")
        elif df[c].dtype == "int64":
            df[c] = pd.to_numeric(df[c], downcast="integer")
        elif c in ("user", "pc", "verdict", "rules", "ext", "event", "activity"):
            df[c] = df[c].astype("category")
    return df


def reasons_for(row, pol):
    out = []
    if row["anomaly_excess"] > 0:
        out.append(f"Behaviour anomaly score {row['anomaly_score']:.3f} (top 5% of all user-days)")
    for r, meta in pol["rules"].items():
        n = row.get("n_" + r, 0)
        if n:
            out.append(f"Policy · {meta['text']} ({int(n)} event{'s' if n > 1 else ''})")
    for c, txt in CHAINS.items():
        if row[c]:
            out.append(f"Chain · {txt}")
    return out


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="results_v2")
    ap.add_argument("--policy", default=None)
    a = ap.parse_args()
    pol = dict(DEFAULT_POLICY)
    if a.policy:
        pol.update(json.load(open(a.policy)))
    os.makedirs(a.out, exist_ok=True)
    root = os.path.join(a.data, "r4.2")

    print("loading logs …")
    logon = read_events(f"{root}/logon.csv", ["id", "date", "user", "pc", "activity"])
    device = read_events(f"{root}/device.csv", ["id", "date", "user", "pc", "activity"])
    files = read_events(f"{root}/file.csv", ["id", "date", "user", "pc", "filename"])
    files["ext"] = files["filename"].str.extract(r"(\.[A-Za-z0-9]+)$")[0].str.lower().fillna("")
    prof = load_ldap(f"{root}/LDAP")
    labels, scen = load_labels(os.path.join(a.data, "answers"))
    insiders = set(scen)

    print("policy layer …")
    ctx = provision(logon, device, files, prof, pol)
    lg, dv, fl = (annotate(logon, "logon", ctx, pol), annotate(device, "device", ctx, pol),
                  annotate(files, "file", ctx, pol))

    print("features + baselines …")
    day = daily_features(lg, dv, fl, ctx)
    day = add_baselines(day, ALL_FEATS)
    day = add_chains(day, lg, dv, fl)
    day = add_policy_score(day, lg, dv, fl, pol)
    lab = labels.drop_duplicates(["user", "day"]).assign(label=1)[["user", "day", "label"]]
    day = day.merge(lab, on=["user", "day"], how="left")
    day["label"] = day["label"].fillna(0).astype(int)
    obs = (labels[labels["source"].isin(["logon", "device", "file"])].drop_duplicates(["user", "day"])
           .assign(obs_label=1)[["user", "day", "obs_label"]])
    day = day.merge(obs, on=["user", "day"], how="left")
    day["obs_label"] = day["obs_label"].fillna(0).astype(int)
    day = day.sort_values(["user", "day"]).reset_index(drop=True)
    p99 = max(np.quantile(day.loc[day["policy_raw"] > 0, "policy_raw"], 0.99), 1e-9) if (day["policy_raw"] > 0).any() else 1.0
    day["policy_norm"] = (day["policy_raw"] / p99).clip(upper=3.0)

    print("ablation study …")
    z = lambda fs, k: [f + "_" + k for f in fs]
    w = pol["fusion_weights"]
    variants = {
        "L0 · TERPE v1 replica": (V1_FEATS + z(V1_FEATS, "zfull"), False, False),
        "L1 · + causal self-baseline": (V1_FEATS + z(V1_FEATS, "zself"), False, False),
        "L2 · + peer baseline": (V1_FEATS + z(V1_FEATS, "zself") + z(V1_FEATS, "zpeer"), False, False),
        "L3 · + context features": (ALL_FEATS + z(ALL_FEATS, "zself") + z(ALL_FEATS, "zpeer"), False, False),
        "L4 · + policy fusion": (ALL_FEATS + z(ALL_FEATS, "zself") + z(ALL_FEATS, "zpeer"), True, False),
        "L5 · + exfiltration chains (TERPE v2)": (ALL_FEATS + z(ALL_FEATS, "zself") + z(ALL_FEATS, "zpeer"), True, True),
        "R · rules only (no ML)": (None, True, True),
    }
    rows, final = [], None
    for name, (cols, use_pol, use_chain) in variants.items():
        if cols is not None:
            m, s, ex, thr, top = isolation(day, cols)
        else:
            m, s, ex, thr, top = None, np.zeros(len(day)), np.zeros(len(day)), 0.0, 1.0
        e = w["anomaly"] * ex
        if use_pol:
            e = e + w["policy"] * day["policy_norm"].values
        if use_chain:
            e = e + w["chain"] * day["chain_score"].values
        risk = accumulate(day, e, pol["decay"])
        res, alert = evaluate(day, e, risk, insiders, pol["alert_budget"])
        res["layer"] = name
        rows.append(res)
        print(f"  {name:42s} userAUC={res['user_auc']:.3f} P@20={res['p@20']:.2f} detected={res['insiders_detected']}")
        if name.startswith("L5"):
            final = dict(model=m, cols=cols, thr=thr, top=top, s=s, ex=ex, e=e, risk=risk, alert=alert,
                         alert_at=res["alert_threshold"])
    abl = pd.DataFrame(rows).set_index("layer")
    abl.to_csv(os.path.join(a.out, "ablation.csv"))

    # ------------------------------------------------ persist final TERPE v2 outputs
    day["anomaly_score"], day["anomaly_excess"] = final["s"], final["ex"]
    day["evidence"], day["risk"], day["alert"] = final["e"], final["risk"], final["alert"]
    day["reasons"] = [json.dumps(reasons_for(r, pol)) for _, r in day.iterrows()]
    keep = (["user", "day", "label", "obs_label", "anomaly_score", "anomaly_excess", "policy_raw", "policy_norm",
             "chain_score", "evidence", "risk", "alert", "reasons"] + ALL_FEATS + list(CHAINS)
            + z(ALL_FEATS, "zself") + z(ALL_FEATS, "zpeer") + [c for c in day.columns if c.startswith("n_")])
    # small row groups (data is sorted by user) so the API can read one employee without loading everything
    compact(day[keep].copy()).to_parquet(os.path.join(a.out, "daily.parquet"), index=False, row_group_size=4000)

    ev_cols = ["user", "ts", "pc", "verdict", "rules", "severity"]
    compact(fl[ev_cols + ["filename", "ext"]].assign(event="File copied to removable media")).to_parquet(
        os.path.join(a.out, "file_events.parquet"), index=False)
    # only logon / USB events that are NOT authorised (authorised ones are the normal pattern)
    compact(pd.concat([lg[lg["verdict"] != "AUTHORISED"][ev_cols + ["activity"]].assign(event="Logon/Logoff"),
                       dv[dv["verdict"] != "AUTHORISED"][ev_cols + ["activity"]].assign(event="Removable media")],
                      ignore_index=True)).to_parquet(os.path.join(a.out, "access_events.parquet"), index=False)

    users = day.groupby("user").agg(peak_risk=("risk", "max"), peak_score=("anomaly_score", "max"),
                                    alert_days=("alert", "sum"), anomaly_days=("anomaly_excess", lambda s: int((s > 0).sum())),
                                    violations=("policy_raw", lambda s: int((s > 0).sum())),
                                    chain_days=("chain_score", lambda s: int((s > 0).sum())))
    users = users.join(ctx[["name", "role", "department", "assigned_pc", "usb_approved", "after_hours_approved", "first_day"]])
    users["ground_truth_insider"] = users.index.isin(insiders).astype(int)
    users["scenario"] = users.index.map(scen).fillna(0).astype(int)
    users = users.sort_values("peak_risk", ascending=False).reset_index()
    users.to_parquet(os.path.join(a.out, "users.parquet"), index=False)

    # baselines for live scoring
    base = day.groupby("user")[ALL_FEATS].agg(["mean", "std"])
    base.columns = [f"{f}_{s}" for f, s in base.columns]
    peer = day.groupby("role")[ALL_FEATS].agg(["mean", "std"])
    peer.columns = [f"{f}_{s}" for f, s in peer.columns]
    last = day.groupby("user").tail(1).set_index("user")[["day", "risk"]]
    joblib.dump(dict(model=final["model"], cols=final["cols"], thr=final["thr"], top=final["top"],
                     alert_at=final["alert_at"], policy=pol, feats=ALL_FEATS, p99=p99,
                     self_base=base, peer_base=peer, last=last,
                     ctx=ctx[["role", "department", "assigned_pc", "usb_approved", "after_hours_approved"]]),
                os.path.join(a.out, "model_v2.joblib"))
    # numpy-only copy of the model for the API (scikit-learn is not needed at serving time)
    lite = joblib.load(os.path.join(a.out, "model_v2.joblib"))
    lite["lite"] = iforest_lite.export(lite.pop("model"))
    joblib.dump(lite, os.path.join(a.out, "model_lite.joblib"))
    json.dump(pol, open(os.path.join(a.out, "policy.json"), "w"), indent=2)
    print(abl.round(3).to_string())
    print("saved to", a.out)


if __name__ == "__main__":
    main()
