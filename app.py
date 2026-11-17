"""TERPE dashboard — streamlit run app.py   (needs API_URL in .streamlit/secrets.toml or env)."""
import json
import os

import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio
import requests
import streamlit as st

st.set_page_config(page_title="TERPE · Insider Threat Monitor", page_icon=":material/security:", layout="wide")


def cfg(name, default=""):
    try:
        return str(st.secrets[name])
    except Exception:
        return os.environ.get(name, default)


pio.templates.default = "plotly_dark"
API_URL = cfg("API_URL", "http://127.0.0.1:8000").rstrip("/")
VERDICT_COLOR = {"VIOLATION": "#ef4444", "REVIEW": "#f59e0b", "AUTHORISED": "#22c55e",
                 "Violation": "#ef4444", "Needs review": "#f59e0b", "Allowed": "#22c55e"}
LABELS = {
    "logons": "Logons", "distinct_pcs": "Different PCs used", "after_hours_logons": "After-hours logons",
    "usb_connects": "USB connections", "usb_after_hours": "After-hours USB connections",
    "file_copies": "Files copied to USB", "foreign_pc_logons": "Logons on someone else's PC",
    "exe_copies": "Executables copied", "distinct_file_types": "Different file types",
    "files_after_hours": "Files copied after hours", "first_usb": "First-ever USB use",
    "first_after_hours": "First-ever after-hours logon", "first_foreign_pc": "First-ever foreign-PC logon",
}
RULE_TEXT = {
    "FOREIGN_PC": "Computer not approved for this person", "USB_NOT_PROVISIONED": "USB not approved for this person",
    "EXECUTABLE_TRANSFER": "New program file copied by a non-IT employee",
    "AFTER_HOURS": "After-hours work by someone who never works late",
    "NEW_FILE_TYPE": "File type this person never used before",
}

VERDICT_TEXT = {"VIOLATION": "Violation", "REVIEW": "Needs review", "AUTHORISED": "Allowed"}
CHAIN_TEXT = {"CHAIN_AFTER_HOURS_EXFIL": "logged on after hours, plugged in a USB drive, then copied files",
              "CHAIN_FOREIGN_PC_TRANSFER": "logged on to a computer that is not theirs, then copied files there",
              "CHAIN_FIRST_MEDIA_BURST": "used a USB drive for the first time and copied files the same day"}
SCENARIO_NAMES = {1: "After-hours data theft", 2: "Data theft before leaving", 3: "Disgruntled IT administrator"}


PIPELINE_TEXT = {  # wording stored by pipeline.py -> wording shown in the app
    "Used a PC this employee is not approved to use": "Computer not approved for this person",
    "Removable media used, but employee is not approved for USB": "USB not approved for this person",
    "New executable moved via removable media by a non-IT role": "New program file copied by a non-IT employee",
    "After-hours activity by an employee not approved for after-hours work": "After-hours work by someone who never works late",
    "File type never handled by this employee before": "File type this person never used before",
    "After-hours logon → USB connected → files copied (in that order)": "logged on after hours, plugged in a USB drive, then copied files",
    "Logged on to someone else's PC → copied files on that PC": "logged on to a computer that is not theirs, then copied files there",
    "First-ever removable-media use with files copied the same day": "used a USB drive for the first time and copied files the same day",
}


def plain_reason(r):
    if r.startswith("Behaviour anomaly score"):
        return "Unusual behaviour: this day is among the 5% most unusual days in the company"
    for prefix, label in (("Policy · ", "Rule broken: "), ("Chain · ", "Attack sequence: ")):
        if r.startswith(prefix):
            body = r[len(prefix):]
            for old_t, new_t in PIPELINE_TEXT.items():
                body = body.replace(old_t, new_t)
            return label + body.replace(" events)", " times)").replace(" event)", " time)")
    return r


st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: #080B12; color: #F8FAFC; }
.pill {display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;margin:2px 4px 2px 0}
.card {background:#111827;border:1px solid #1f2937;border-radius:12px;padding:10px 14px}
.card .k {color:#94a3b8;font-size:12px} .card .v {color:#f8fafc;font-size:18px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.reason {padding:8px 12px;border-left:3px solid #38bdf8;background:rgba(56,189,248,.06);margin:6px 0;border-radius:6px}
.reason.policy {border-color:#f59e0b;background:rgba(245,158,11,.07)}
.reason.chain {border-color:#ef4444;background:rgba(239,68,68,.08)}
</style>""", unsafe_allow_html=True)


# ================================================================== API helpers
def api(method, path, **kw):
    headers = {}
    if st.session_state.get("token"):
        headers["Authorization"] = "Bearer " + st.session_state["token"]
    try:
        r = requests.request(method, API_URL + path, headers=headers, timeout=60, **kw)
    except requests.RequestException:
        return None, "Cannot reach the TERPE API. Check that the backend is running."
    if r.status_code == 401 and st.session_state.get("token"):
        st.session_state.clear()
        st.warning("Your session has ended. Please sign in again.")
        st.rerun()
    if r.status_code >= 400:
        try:
            det = r.json().get("detail", "")
            if isinstance(det, list):
                det = "; ".join(f"{'.'.join(map(str, d.get('loc', [])[1:]))}: {d.get('msg')}" for d in det)
        except ValueError:
            det = r.text[:200]
        return None, det or f"Error {r.status_code}"
    return r.json(), None


def get(path, **params):
    data, err = api("GET", path, params=params or None)
    if err:
        st.error(err)
        st.stop()
    return data


@st.cache_data(ttl=300, show_spinner=False)
def cached(path, token, **params):
    return get(path, **params)


def cget(path, **params):
    return cached(path, st.session_state.get("token"), **params)


def pills(rules):
    if not rules:
        return ""
    return "".join(f'<span class="pill" style="background:#334155">{RULE_TEXT.get(r, r)}</span>'
                   for r in rules.split("|") if r)


def verdict_table(df, extra_cols=()):
    if df.empty:
        st.info("No events.")
        return
    d = df.copy()
    d["verdict"] = d["verdict"].astype(str).map(lambda v: VERDICT_TEXT.get(v, v))
    d["Why"] = d["rules"].fillna("").apply(lambda s: " · ".join(RULE_TEXT.get(r, r) for r in s.split("|") if r) or "Within the person's permissions")
    cols = [c for c in ["ts", "event", "activity", "filename", "ext", "pc", "verdict", "Why", *extra_cols] if c in d.columns]
    if "event" in d.columns:
        d["event"] = d["event"].astype(str).replace({"File copied to removable media": "Copied to USB",
                                                     "Logon/Logoff": "Logon", "Removable media": "USB device"})
    d = d[cols].rename(columns={"ts": "Time", "event": "Event", "activity": "Action", "filename": "File",
                                "ext": "Type", "pc": "Computer", "verdict": "Result", "Why": "Reason"})
    st.dataframe(d.style.map(lambda v: f"color:{VERDICT_COLOR.get(v, '')};font-weight:700", subset=["Result"]),
                 hide_index=True, width="stretch")


# ================================================================== LOGIN / SIGN-UP
def auth_screen():
    st.markdown("""
    <style>
    .stApp {background: radial-gradient(circle at 8% 20%, rgba(67,56,202,.20), transparent 30%),
            radial-gradient(circle at 90% 80%, rgba(14,165,233,.12), transparent 30%), #030712;}
    .block-container {max-width:1180px;padding-top:3rem}
    .terpe-title {font-size:62px;font-weight:800;letter-spacing:8px;line-height:1;color:#fff;margin-bottom:12px}
    .terpe-subtitle {font-size:19px;color:#b9c7dc;margin-bottom:10px}
    .terpe-description {max-width:500px;font-size:14px;line-height:1.75;color:#8290a8}
    .feature {padding:7px 0;color:#b7c3d7;font-size:13px}
    .feature span {color:#38bdf8;margin-right:9px;font-weight:700}
    div[data-testid="stVerticalBlockBorderWrapper"] {background:linear-gradient(145deg,rgba(19,30,55,.96),rgba(7,13,28,.98));
        border:1px solid rgba(148,163,184,.18)!important;border-radius:22px!important;padding:26px!important;
        box-shadow:0 30px 75px rgba(0,0,0,.5)}
    div.stButton > button, div.stFormSubmitButton > button {width:100%;height:46px;border-radius:11px;border:none;
        background:linear-gradient(100deg,#2563eb,#4f46e5);color:#fff;font-weight:700}
    </style>""", unsafe_allow_html=True)
    left, right = st.columns([1.1, 0.9], gap="large")
    with left:
        st.markdown('<div class="terpe-title">TERPE</div><div class="terpe-subtitle">Threat Exposure & Risk Profiling Engine</div>'
                    '<div class="terpe-description"><b style="color:#cbd5e1">Insider-threat detection for small and medium businesses</b><br><br>'
                    'Combines machine learning with clear access rules to flag employees whose activity looks like data theft, '
                    'and shows the exact files, computers and rules behind every alert.</div><br>', unsafe_allow_html=True)
        for f in ["Shows exactly which files were copied, and whether that was allowed",
                  "Compares each person with their own past and with colleagues",
                  "Spots known data-theft sequences",
                  "Each user sees only what their role allows, and every action is logged"]:
            st.markdown(f'<div class="feature"><span>◆</span>{f}</div>', unsafe_allow_html=True)
    with right:
        with st.container(border=True):
            t_in, t_up = st.tabs(["Sign in", "Request access"])
            with t_in:
                with st.form("login"):
                    u = st.text_input("Username")
                    p = st.text_input("Password", type="password")
                    ok = st.form_submit_button("Sign in to TERPE")
                if ok:
                    data, err = api("POST", "/auth/login", json={"username": u.strip(), "password": p})
                    if err:
                        st.error(err)
                    else:
                        st.session_state.update(token=data["token"], user=data["user"])
                        st.rerun()
            with t_up:
                st.caption("New accounts are reviewed by an administrator, who assigns your role.")
                with st.form("signup", clear_on_submit=False):
                    c1, c2 = st.columns(2)
                    full = c1.text_input("Full name")
                    uname = c2.text_input("Username", help="3–40 letters, numbers, . or _")
                    email = st.text_input("Work email")
                    org = st.text_input("Organisation / team")
                    reason = st.text_area("Why do you need access?", height=70)
                    p1 = st.text_input("Password", type="password",
                                       help="10+ characters with upper & lower case, a number and a symbol")
                    p2 = st.text_input("Confirm password", type="password")
                    go_ = st.form_submit_button("Request access")
                if go_:
                    if p1 != p2:
                        st.error("Passwords do not match.")
                    else:
                        data, err = api("POST", "/auth/signup", json=dict(username=uname.strip(), email=email.strip(),
                                        full_name=full.strip(), organisation=org, reason=reason, password=p1))
                        st.error(err) if err else st.success(data["message"])
            st.markdown('<div style="text-align:center;color:#59677d;font-size:11px;margin-top:12px">'
                        '🔒 Every sign-in and investigation is recorded in the audit log</div>', unsafe_allow_html=True)


def force_password_change():
    st.title("Set a new password")
    st.info("You signed in with a temporary password. Choose your own password to continue.")
    with st.form("chg"):
        old = st.text_input("Temporary password", type="password")
        n1 = st.text_input("New password", type="password")
        n2 = st.text_input("Confirm new password", type="password")
        ok = st.form_submit_button("Save password")
    if ok:
        if n1 != n2:
            st.error("Passwords do not match.")
        else:
            _, err = api("POST", "/auth/change-password", json={"old_password": old, "new_password": n1})
            if err:
                st.error(err)
            else:
                st.session_state["user"]["must_change_password"] = False
                st.success("Password updated.")
                st.rerun()


if not st.session_state.get("token"):
    auth_screen()
    st.stop()
USER = st.session_state["user"]
if USER.get("must_change_password"):
    force_password_change()
    st.stop()
ROLE = USER["role"]
RANK = {"viewer": 1, "analyst": 2, "admin": 3}[ROLE]
GRANTABLE = ["viewer", "analyst", "admin"] if USER.get("is_owner") else ["viewer", "analyst"]


# ================================================================== OVERVIEW
def page_overview():
    st.title("Overview")
    st.caption("Who is most at risk across the company, and how many actions broke the access rules.")
    ov = cget("/overview")
    top = pd.DataFrame(cget("/users/top", n=1000))
    c = st.columns(4)
    c[0].metric("Employees monitored", ov["employees"])
    c[1].metric("Employees with alerts", ov["alerting_employees"])
    c[2].metric("File copies that broke a rule", f"{ov['file_verdicts'].get('VIOLATION', 0):,}")
    c[3].metric("Known insiders (answer key)" if show_gt else "File copies needing review",
                int(top["ground_truth_insider"].sum()) if show_gt else f"{ov['file_verdicts'].get('REVIEW', 0):,}")
    st.caption("**Employees with alerts:** their risk score crossed the alert line at least once. "
               "**Broke a rule:** a file copy that went against the person's access permissions. "
               "**Needing review:** allowed, but unusual for that person.")
    st.divider()
    l, r = st.columns([1.5, 1])
    with l:
        st.subheader("Highest-risk employees")
        n = st.slider("Employees shown", 5, 50, 20)
        d = top.head(n).sort_values("peak_risk")
        colors = ["#ef4444" if (show_gt and g) else "#3b82f6" for g in d["ground_truth_insider"]]
        fig = go.Figure(go.Bar(x=d["peak_risk"], y=d["user"], orientation="h", marker_color=colors))
        fig.update_layout(height=max(380, n * 18), margin=dict(l=10, r=10, t=10, b=10), xaxis_title="Highest risk score reached")
        st.plotly_chart(fig, width="stretch")
        if show_gt:
            st.caption("Red = a known insider according to the dataset's answer key.")
    with r:
        st.subheader("Result of every file copy")
        fv = ov["file_verdicts"]
        fig = go.Figure(go.Pie(labels=[VERDICT_TEXT.get(k, k) for k in fv], values=list(fv.values()), hole=.5,
                               marker_colors=[VERDICT_COLOR.get(k) for k in fv]))
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
        st.subheader("Which rules were broken most")
        rh = pd.Series(ov["rule_hits"]).sort_values()
        fig = go.Figure(go.Bar(x=rh.values, y=[RULE_TEXT.get(k, k) for k in rh.index], orientation="h", marker_color="#f59e0b"))
        fig.update_layout(height=230, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
    st.subheader("Alerts and rule breaks per week")
    w = pd.DataFrame(ov["weekly"])
    fig = go.Figure([go.Scatter(x=w["week"], y=w["alerts"], name="Employee-days with an alert", line_color="#ef4444"),
                     go.Scatter(x=w["week"], y=w["violations"], name="Employee-days with a rule break", line_color="#f59e0b")])
    fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, width="stretch")
    st.subheader("All employees by risk")
    top = top.assign(ground_truth_insider=top["ground_truth_insider"].map({1: "Yes", 0: ""}),
                     scenario=top["scenario"].map(SCENARIO_NAMES).fillna(""))
    view = top.rename(columns={"user": "Employee", "role": "Role", "department": "Department", "peak_risk": "Highest risk score",
                               "alert_days": "Days with an alert", "violations": "Days with a rule break",
                               "chain_days": "Days with an attack sequence", "anomaly_days": "Days with unusual behaviour",
                               "ground_truth_insider": "Known insider", "scenario": "Insider type"})
    view = view.drop(columns=["peak_score"] + ([] if show_gt else ["Known insider", "Insider type"]))
    st.dataframe(view, hide_index=True, width="stretch")

# ================================================================== INVESTIGATE
def page_employees():
    st.title("Employees")
    st.caption("Pick an employee to see their risk over time, and exactly which files and computers caused it.")
    top = pd.DataFrame(cget("/users/top", n=1000))
    uid = st.selectbox("Employee (sorted by risk)", top["user"],
                       format_func=lambda u: f"{u} · {top.set_index('user').loc[u, 'role']}")
    prof = cget(f"/users/{uid}/profile")
    tl = pd.DataFrame(cget(f"/users/{uid}/timeline"))
    tl["day"] = pd.to_datetime(tl["day"])
    c = st.columns(6)
    for col, (k, v) in zip(c, [("Role", prof["role"]), ("Department", prof["department"]),
                               ("Main computer", prof["assigned_pc"]), ("USB / late work allowed", f"{'Yes' if prof['usb_approved'] else 'No'} / {'Yes' if prof.get('after_hours_approved') else 'No'}"),
                               ("Highest risk score", f"{prof['peak_risk']:.2f}"), ("Days with an alert", prof["alert_days"])]):
        col.markdown(f'<div class="card" title="{v}"><div class="k">{k}</div><div class="v">{v}</div></div>', unsafe_allow_html=True)
    st.write("")
    if show_gt and prof["ground_truth_insider"]:
        st.error(f"Answer key: this employee is a known insider ({SCENARIO_NAMES.get(prof['scenario'], 'unknown type')}).")

    with st.expander("How to read this page"):
        st.markdown("""
- **Grey bars (day score):** how suspicious that single day was. It adds up three things: unusual behaviour, rule breaks and attack sequences.
- **Blue line (risk score):** a running total. It drops by 20% for each quiet day, so one odd day fades away, while several suspicious days in a row build up.
- **Red dots (alerts):** days when the risk score crossed the alert line. The line is set so that only 1% of all employee-days raise an alert.
- **Result of each file, logon or USB event:** *Allowed* = fits the person's normal setup; *Needs review* = unusual but not forbidden
  (for example a new file type); *Violation* = breaks an access rule (for example using USB without permission).
""")
    t1, t2 = st.tabs(["Risk over time", "All file copies"])
    with t1:
        fig = go.Figure()
        fig.add_bar(x=tl["day"], y=tl["evidence"], name="Day score", marker_color="#64748b", opacity=.6)
        fig.add_scatter(x=tl["day"], y=tl["risk"], name="Risk score", line_color="#38bdf8")
        al = tl[tl["alert"]]
        fig.add_scatter(x=al["day"], y=al["risk"], mode="markers", name="Alert", marker=dict(color="#ef4444", size=8))
        if show_gt:
            m = tl[tl["label"] == 1]
            fig.add_scatter(x=m["day"], y=m["risk"], mode="markers", name="Malicious day (answer key)",
                            marker=dict(symbol="x", color="#fbbf24", size=9))
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h"))
        st.plotly_chart(fig, width="stretch")

        st.subheader("Why was this employee flagged?")
        cand = tl.sort_values("evidence", ascending=False)
        cand = cand[cand["evidence"] > 0].head(30)
        if cand.empty:
            st.info("Nothing suspicious was found for this employee.")
        else:
            day = st.selectbox("Pick a day (most suspicious first)", cand["day"].dt.strftime("%Y-%m-%d"),
                               format_func=lambda d: f"{d}  ·  day score {cand.set_index(cand['day'].dt.strftime('%Y-%m-%d')).loc[d, 'evidence']:.2f}")
            dd = cget(f"/users/{uid}/day/{day}")
            s = dd["scores"]
            k = st.columns(5)
            k[0].metric("Unusual behaviour", f"{s['anomaly_excess']:.2f}")
            k[1].metric("Rule breaks", f"{s['policy_norm']:.2f}")
            k[2].metric("Attack sequences", f"{s.get('chain_evidence', s['chain_score']):.2f}")
            k[3].metric("Day score", f"{s['evidence']:.2f}")
            k[4].metric("Risk score after this day", f"{s['risk']:.2f}", "ALERT" if dd["alert"] else None, delta_color="inverse")
            for rsn in dd["reasons"]:
                cls = "chain" if rsn.startswith("Chain") else "policy" if rsn.startswith("Policy") else ""
                st.markdown(f'<div class="reason {cls}">{plain_reason(rsn)}</div>', unsafe_allow_html=True)
            st.markdown("##### Files copied to USB that day")
            verdict_table(pd.DataFrame(dd["files"]))
            st.markdown("##### Logons and USB connections that were not allowed")
            verdict_table(pd.DataFrame(dd["access"]))
            st.markdown("##### How this day compares")
            dv = pd.DataFrame(dd["deviations"])
            dv["feature"] = dv["feature"].map(LABELS)
            st.dataframe(dv.rename(columns={"feature": "Activity", "value": "Count that day", "z_self": "Compared with own past",
                                            "z_peer": "Compared with same-role colleagues"}), hide_index=True, width="stretch")
            st.caption("The comparison numbers are in standard deviations: 0 means a normal day, 2 or more is clearly unusual, "
                       "and a negative number means less activity than usual.")
    with t2:
        v = st.radio("Show", ["All", "VIOLATION", "REVIEW", "AUTHORISED"], horizontal=True,
                     format_func=lambda x: VERDICT_TEXT.get(x, x))
        fl = pd.DataFrame(cget(f"/users/{uid}/files", **({} if v == "All" else {"verdict": v})))
        if not fl.empty:
            k = st.columns(3)
            for i, vv in enumerate(["VIOLATION", "REVIEW", "AUTHORISED"]):
                k[i].metric(VERDICT_TEXT[vv], int((fl["verdict"] == vv).sum()))
        verdict_table(fl)
        st.caption("The dataset records files copied to USB drives. Each copy is checked against the person's permissions: "
                   "their computers, USB approval, working hours and usual file types (see How it works).")

# ================================================================== FILE ACCESS MONITOR
def page_files():
    st.title("File activity")
    st.caption("Every file copied to a USB drive across the company that broke a rule or needs review, newest first.")
    v = st.radio("Show", ["VIOLATION", "REVIEW"], horizontal=True, format_func=lambda x: VERDICT_TEXT.get(x, x))
    lim = st.select_slider("How many of the most recent", [100, 500, 1000, 5000], value=500)
    fl = pd.DataFrame(cget("/files/feed", verdict=v, limit=lim))
    if fl.empty:
        st.info("Nothing to show.")
    else:
        rules = sorted({r for s in fl["rules"] for r in s.split("|") if r})
        pick = st.multiselect("Only show these rules", rules, format_func=lambda r: RULE_TEXT.get(r, r))
        if pick:
            fl = fl[fl["rules"].apply(lambda s: any(r in s.split("|") for r in pick))]
        c = st.columns(3)
        c[0].metric("File copies", len(fl))
        c[1].metric("Employees involved", fl["user"].nunique())
        c[2].metric("Computers involved", fl["pc"].nunique())
        verdict_table(fl.rename(columns={"user": "Employee"}), extra_cols=("Employee",))

# ================================================================== LIVE SCORING
def page_risk_check():
    st.title("Risk check")
    st.caption("Type in one day of activity for an employee to see how TERPE would score it. "
               "Useful for trying out \"what if\" situations, for example copying 15 files to USB at night.")
    top = pd.DataFrame(cget("/users/top", n=1000))
    uid = st.selectbox("Employee", top["user"])
    defaults = dict(logons=2, distinct_pcs=1, after_hours_logons=0, usb_connects=0, usb_after_hours=0, file_copies=0,
                    foreign_pc_logons=0, exe_copies=0, distinct_file_types=0, files_after_hours=0)
    vals, cols = {}, st.columns(3)
    for i, (f, dv_) in enumerate(defaults.items()):
        vals[f] = cols[i % 3].number_input(LABELS[f], 0, 100000, dv_, 1)
    if st.button("Check this day", width="stretch", type="primary"):
        res, err = api("POST", "/score", json={"user_id": uid, "features": {k: float(v) for k, v in vals.items()}})
        if err:
            st.error(err)
        else:
            c = st.columns(5)
            c[0].metric("Unusual behaviour", f"{res['anomaly_component']:.2f}")
            c[1].metric("Rule breaks", f"{res['policy_component']:.2f}")
            c[2].metric("Attack sequences", f"{res.get('chain_evidence', res['chain_component']):.2f}")
            c[3].metric("Day score", f"{res['evidence']:.2f}")
            c[4].metric("Risk score", f"{res['risk']:.2f}")
            c[4].caption(f"Alert line: {res['alert_threshold']:.2f}")
            if res["alert"]:
                st.error("ALERT: the risk score is above the alert line. This employee would be flagged for review.")
            elif res["evidence"] > 0:
                st.warning("Something unusual was found, but the risk score is still below the alert line.")
            else:
                st.success("This day looks normal for this employee and breaks no rules.")
            ctx = res["context"]
            st.caption(f"About this employee: {ctx['role']} in {ctx['department']} · main computer {ctx['assigned_pc']} · "
                       f"USB allowed: {'yes' if ctx['usb_approved'] else 'no'} · "
                       f"late work allowed: {'yes' if ctx.get('after_hours_approved') else 'no'}")
            for k_, n_ in res["policy_hits"].items():
                st.markdown(f'<div class="reason policy">Rule broken: {RULE_TEXT.get(k_, k_)} ({int(n_)} times)</div>', unsafe_allow_html=True)
            for ch in res["chains"]:
                st.markdown(f'<div class="reason chain">Attack sequence: {CHAIN_TEXT.get(ch, ch)}</div>', unsafe_allow_html=True)
            st.caption("**Unusual behaviour** is the machine-learning score (0 = normal). **Rule breaks** grows with how many "
                       "rules were broken and how often. **Day score** is the sum of the three. The **risk score** also carries "
                       "over part of this employee's earlier risk.")

# ================================================================== ADMIN
def page_admin():
    st.title("User management")
    if USER.get("is_owner"):
        st.caption("You are the **owner**: only you can give someone the admin role, and nobody else can change your account.")
    t1, t2, t3, t4 = st.tabs(["Access requests", "All accounts", "Create account", "Audit log"])
    accts = pd.DataFrame(get("/admin/users"))
    with t1:
        pend = accts[accts["status"] == "pending"] if not accts.empty else accts
        if pend.empty:
            st.success("No pending requests.")
        for _, a in pend.iterrows():
            with st.container(border=True):
                st.markdown(f"**{a['full_name']}** · `{a['username']}` · {a['email']}  \n"
                            f"{a['organisation'] or '—'} · requested {a['created_at']}  \n_{a['reason'] or 'No reason given'}_")
                c1, c2, c3 = st.columns([1, 1, 1])
                role = c1.selectbox("Role", GRANTABLE, key=f"r{a['id']}")
                if c2.button("Approve", key=f"a{a['id']}", width="stretch", type="primary"):
                    _, err = api("PATCH", f"/admin/users/{a['id']}", json={"status": "active", "role": role})
                    st.error(err) if err else st.rerun()
                if c3.button("Reject", key=f"x{a['id']}", width="stretch"):
                    _, err = api("PATCH", f"/admin/users/{a['id']}", json={"status": "rejected"})
                    st.error(err) if err else st.rerun()
    with t2:
        st.dataframe(accts[["username", "full_name", "email", "role", "status", "last_login", "approved_by", "created_at"]],
                     hide_index=True, width="stretch")
        who = st.selectbox("Manage account", accts["username"])
        a = accts.set_index("username").loc[who]
        c1, c2, c3 = st.columns(3)
        opts = GRANTABLE if a["role"] in GRANTABLE else GRANTABLE + [a["role"]]
        nr = c1.selectbox("Role", opts, index=opts.index(a["role"]))
        ns = c2.selectbox("Status", ["active", "disabled", "pending", "rejected"],
                          index=["active", "disabled", "pending", "rejected"].index(a["status"]))
        if c3.button("Save changes", width="stretch"):
            r, err = api("PATCH", f"/admin/users/{int(a['id'])}", json={"role": nr, "status": ns})
            st.error(err) if err else st.success("Saved: " + (", ".join(r["changes"]) or "no changes"))
        if st.button(f"Reset password for {who}"):
            r, err = api("POST", f"/admin/users/{int(a['id'])}/reset-password")
            if err:
                st.error(err)
            else:
                st.warning(f"Temporary password: `{r['temporary_password']}` — share it privately. "
                           "They must change it at next sign-in.")
    with t3:
        with st.form("create"):
            c1, c2 = st.columns(2)
            un, fn = c1.text_input("Username"), c2.text_input("Full name")
            em = c1.text_input("Email")
            rl = c2.selectbox("Role", [r for r in ["analyst", "viewer", "admin"] if r in GRANTABLE])
            ok = st.form_submit_button("Create account")
        if ok:
            r, err = api("POST", "/admin/users", json={"username": un, "email": em, "full_name": fn, "role": rl})
            st.error(err) if err else st.warning(f"Created. Temporary password: `{r['temporary_password']}`")
    with t4:
        lg = pd.DataFrame(get("/admin/audit", limit=1000))
        if not lg.empty:
            acts = st.multiselect("Action", sorted(lg["action"].unique()))
            if acts:
                lg = lg[lg["action"].isin(acts)]
        st.dataframe(lg, hide_index=True, width="stretch")
        st.caption("Investigations of individual employees are logged too, so the monitoring tool cannot itself be misused unnoticed.")

# ================================================================== ACCOUNT
def page_account():
    st.title("My account")
    me = get("/auth/me")
    st.write(f"**{me['full_name']}** · `{me['username']}` · {me['email']} · role **{me['role']}** · last sign-in {me['last_login']}")
    with st.form("pw"):
        old = st.text_input("Current password", type="password")
        n1 = st.text_input("New password", type="password", help="10+ characters, upper & lower case, number, symbol")
        n2 = st.text_input("Confirm new password", type="password")
        ok = st.form_submit_button("Change password")
    if ok:
        if n1 != n2:
            st.error("Passwords do not match.")
        else:
            _, err = api("POST", "/auth/change-password", json={"old_password": old, "new_password": n1})
            st.error(err) if err else st.success("Password changed.")

# ================================================================== HOW IT WORKS
def page_how():
    st.title("How it works")
    st.markdown("""
TERPE checks three things for every employee, every day, and adds them up into one **risk score**.
When the risk score crosses the alert line, the employee is flagged for a security analyst to review.

Think of it like penalty points on a driving licence. One small offence fades after a while.
Several offences close together add up, and the licence gets reviewed.
""")
    st.subheader("What data it uses")
    st.markdown("""
- **Logon records:** who signed in to which computer, and when.
- **USB records:** when a USB drive or other removable device was plugged in.
- **File-copy records:** which file was copied to a USB drive, from which computer, and when.
- **Employee directory:** each person's job role and department.

TERPE never reads what is inside a file. It only uses the record of the action: file name, type, time and computer.
""")
    st.caption("In this project the data comes from the CERT Insider Threat dataset (version r4.2), "
               "a simulated company of 1,000 employees published by Carnegie Mellon University for research. "
               "70 of these employees were scripted to behave as insiders.")

    st.subheader("Step 1: Learn what is normal for each person")
    st.markdown("""
During each employee's first 30 days, TERPE records their normal setup:

- which computers they use,
- whether they use USB drives at all,
- whether they ever work after hours (before 7 am, after 7 pm, or on weekends),
- which file types they normally handle (.doc, .pdf, .exe and so on).

A real company would set these permissions in its IT policy. The dataset has no such policy, so TERPE learns them from the first month.
""")

    st.subheader("Step 2: Check every action against the rules")
    st.markdown("After the first 30 days, every logon, USB connection and file copy gets one of three results:")
    st.dataframe(pd.DataFrame([
        {"Rule": "Computer not approved for this person", "Example": "Logs on to a colleague's PC", "Result": "Violation"},
        {"Rule": "USB not approved for this person", "Example": "Plugs in a USB drive for the first time", "Result": "Violation"},
        {"Rule": "New program file copied by a non-IT employee", "Example": "Copies an .exe file to USB", "Result": "Violation"},
        {"Rule": "After-hours work by someone who never works late", "Example": "Logs on at 11 pm", "Result": "Needs review"},
        {"Rule": "File type this person never used before", "Example": "First time copying a .zip file", "Result": "Needs review"},
    ]), hide_index=True, width="stretch")
    st.caption("**Allowed** means the action fits the person's normal setup. **Needs review** means it is unusual but not forbidden. "
               "**Violation** means it breaks an access rule. Every file and logon on the Employees page shows its result and the reason.")
    st.markdown("""
**How much each broken rule counts is learned from the data, not chosen by hand.** A rule that is almost never broken
in the company counts more than one that is broken often. For example, using a USB drive without approval happens on
only about 4 in every 10,000 employee-days, so it gets the highest weight.
""")
    st.caption("Technically, each weight is the rule's *surprisal*: −log₂ of the share of employee-days on which the rule is broken. "
               "It comes from information theory, needs no answer key, and is recalculated whenever the data changes. "
               "The same idea weights the attack sequences in Step 4.")

    st.subheader("Step 3: Compare behaviour with the past and with colleagues")
    st.markdown("""
For each day, TERPE counts 13 things, such as logons, USB connections, files copied and files copied after hours.
Each count is compared two ways:

- **with the person's own past days:** is today unusual *for them*?
- **with colleagues in the same job role on the same day:** is today unusual *for this kind of job*?

A machine-learning model called an **Isolation Forest** then gives each day an *unusualness score*.
""")
    st.caption("What is an Isolation Forest? It is a standard machine-learning method for finding unusual records without being told "
               "which ones are bad. It splits the data at random again and again; a normal day needs many splits to be separated "
               "from the rest, while an unusual day gets separated after only a few. Fewer splits means a higher unusualness score.")

    st.subheader("Step 4: Look for known attack sequences")
    st.markdown("""
Some actions are only suspicious when they happen **in a particular order on the same day**. TERPE looks for three:

1. Logs on after hours → plugs in a USB drive → copies files.
2. Logs on to a computer that is not theirs → copies files on that computer.
3. Uses a USB drive for the first time ever → copies files the same day.
""")

    st.subheader("Step 5: Add it up and keep a running total")
    st.markdown("""
- **Day score** = unusualness score + rule-break score + number of attack sequences found.
- **Risk score** = yesterday's risk score, reduced by 20% for each day that has passed, plus today's day score.
- **Alert** when the risk score crosses the alert line. The line is set so that only the top 1% of all employee-days raise an alert,
  which keeps the number of alerts manageable for a small security team.
""")
    st.caption("Because the risk score carries over, a single odd day fades away within a week or so, "
               "but several suspicious days in a row build up and raise an alert.")

    st.subheader("What changed from the previous model")
    st.markdown("""
The previous model used only the unusualness score (Step 3), with 6 counts per day. It also compared each day with the
employee's **whole** history, including days that had not happened yet, which a live system cannot do.
The current model fixes that, adds the rule checks (Steps 1 and 2) and the attack sequences (Step 4), learns how much
each one should count from the data, and shows exactly which files, computers and rules caused each alert.
""")
    st.info("See **Results** for how much each of these changes improves detection.")


# ================================================================== RESULTS
LAYER_NAMES = {
    "L0": "Previous model (unusualness score only)",
    "L1": "+ compare only with past days",
    "L2": "+ compare with same-role colleagues",
    "L3": "+ 7 extra behaviour counts",
    "L4": "+ access-rule checks",
    "L5": "+ attack sequences",
    "L6": "Current model (+ weights learned from data)",
    "R": "Access rules only, no machine learning",
}


def page_results():
    st.title("Results")
    ev = cget("/evaluation")
    ab = pd.DataFrame(ev["ablation"])
    ab["key"] = ab["layer"].str.split(" · ").str[0]
    ab["Model"] = ab["key"].map(LAYER_NAMES)
    old = ab[ab["key"] == "L0"].iloc[0]
    new = ab[ab["key"] == "L6"].iloc[0]
    rules = ab[ab["key"] == "R"].iloc[0]
    caught = lambda r: int(str(r["insiders_detected"]).split("/")[0])
    total = int(str(new["insiders_detected"]).split("/")[1])

    st.markdown(f"""
The system was tested on the CERT dataset: **1,000 simulated employees, {total} of whom are known insiders**.
The dataset comes with an answer key that says who the insiders are, so we can check how many TERPE finds.
The answer key is used only for this check, never to build or tune the model.
""")
    c = st.columns(3)
    for col, label, now_v, before in [
            (c[0], "Real insiders among the 10 highest-risk employees", f"{int(round(new['p@10'] * 10))} of 10", f"{int(round(old['p@10'] * 10))} of 10"),
            (c[1], "Insiders flagged while their attack was happening", f"{caught(new)} of {total}", f"{caught(old)} of {total}"),
            (c[2], "Normal employees wrongly flagged", f"{int(new['false_alert_users'])} of {1000 - total}", f"{int(old['false_alert_users'])} of {1000 - total}")]:
        col.metric(label, now_v)
        col.caption(f"Previous model: {before}")
    st.caption("A security analyst usually only has time to check the top of the list, so the first number matters most. "
               "\"Flagged while the attack was happening\" means an alert between the insider's first malicious action "
               "and one week after their last.")

    st.subheader("What each part of the method adds")
    st.markdown("""
To show which part makes the difference, we started from the previous model and added one part at a time,
measuring after each step. Researchers call this an **ablation study**. Every row uses the same data and the same alert line,
so the rows can be compared fairly.
""")
    tbl = pd.DataFrame({
        "Model": ab["Model"],
        "Top 10": (ab["p@10"] * 10).round().astype(int),
        "Top 20": (ab["p@20"] * 20).round().astype(int),
        "Top 50": (ab["p@50"] * 50).round().astype(int),
        "Caught": ab["insiders_detected"],
        "Wrongly flagged": ab["false_alert_users"].astype(int),
        "AUC": ab["user_auc"].round(2),
        "Avg. precision": ab["user_ap"].round(2),
    })
    st.dataframe(tbl, hide_index=True, width="stretch",
                 column_config={"Model": st.column_config.TextColumn(width="large")})
    st.caption("""
**Top 10 / 20 / 50:** how many real insiders are among the 10, 20 or 50 employees with the highest risk scores.
**Caught:** insiders flagged while their attack was happening (out of 70). **Wrongly flagged:** normal employees who got at least one alert (out of 930).
**AUC:** the chance that a randomly picked insider gets a higher risk score than a randomly picked normal employee
(0.5 = guessing, 1.0 = perfect). **Avg. precision (average precision):** how tightly the insiders are packed at the very top of the list
(0 to 1, higher is better); it is the stricter measure when, as here, only 7% of employees are insiders.
""")

    st.subheader("What the results show")
    st.markdown(f"""
- **The access-rule checks make the biggest difference.** Adding them raises the insiders flagged during their attack
  from {caught(ab[ab['key'] == 'L3'].iloc[0])} to {caught(ab[ab['key'] == 'L4'].iloc[0])}. Adding the attack sequences raises it again to {caught(ab[ab['key'] == 'L5'].iloc[0])}.
- **Letting the data set the weights removes the guesswork and cuts false alarms.** Instead of hand-picked weights
  (3 for a violation, 1 for review), each rule is weighted by how rare it is in the company. Detection stays at
  {caught(new)} of {total}, and wrongly flagged employees drop from {int(ab[ab['key'] == 'L5'].iloc[0]['false_alert_users'])} to {int(new['false_alert_users'])}.
- **Machine learning on its own does not improve on the previous model.** The second row is slightly worse because it no
  longer looks at future days. That was an unfair advantage the previous model had, which a real system cannot have.
- **Rules alone find insiders well but raise too many false alarms.** They wrongly flag {int(rules['false_alert_users'])} normal employees.
  The current model flags almost as many insiders while wrongly flagging only {int(new['false_alert_users'])}, about
  {(1 - new['false_alert_users'] / rules['false_alert_users']) * 100:.0f}% fewer. That is why the final design combines both.
""")

    st.subheader("Which kinds of insider it catches")
    st.dataframe(pd.DataFrame([
        {"Insider type (from the dataset)": "Starts working late and copying data to USB, then leaves", "Insiders": 30, "Flagged": 29},
        {"Insider type (from the dataset)": "Disgruntled IT administrator plants a keylogger", "Insiders": 10, "Flagged": 10},
        {"Insider type (from the dataset)": "Job-hunts, then copies data before leaving", "Insiders": 30, "Flagged": 3},
    ]), hide_index=True, width="stretch")
    st.caption("The job-hunting insiders were already approved to use USB drives, and their main warning sign is visiting job "
               "websites. Web browsing records are not used yet, so this is the clearest area for future work.")

    st.subheader("Limits")
    st.markdown("""
- The company in the dataset is simulated, with far more insiders than a real company would have.
- The dataset has no real access policy, so each person's permissions are learned from their first 30 days.
- The dataset records only files copied to USB drives, not every file that is opened.
- A high risk score is a reason to look closer, not proof that someone is guilty.
""")

    st.subheader("Access rules in use")
    pol = ev["policy"]
    lw = pol.get("learned_weights", {})
    st.dataframe(pd.DataFrame([{"Rule": RULE_TEXT.get(k, k), "Result": "Violation" if v["severity"] >= 3 else "Needs review",
                                "Weight learned from data": round(lw.get(k, v["severity"]), 1)} for k, v in pol["rules"].items()]),
                 hide_index=True, width="stretch")
    st.caption(f"Working hours: {pol['work_hours']['start']}:00 to {pol['work_hours']['end']}:00 on weekdays. "
               f"Roles allowed to use several computers and copy program files: {', '.join(pol['multi_pc_roles'])}. "
               "The weight is how much each broken rule adds to the day score. It is learned from the data: "
               "the rarer a rule break is across the company, the higher its weight.")

# ================================================================== NAVIGATION

sections = {"Monitor": [st.Page(page_overview, title="Overview", icon=":material/dashboard:", default=True)]}
if RANK >= 2:
    sections["Monitor"] += [
        st.Page(page_employees, title="Employees", icon=":material/person_search:", url_path="employees"),
        st.Page(page_files, title="File activity", icon=":material/folder_open:", url_path="files"),
        st.Page(page_risk_check, title="Risk check", icon=":material/speed:", url_path="risk-check"),
    ]
sections["About the system"] = [
    st.Page(page_how, title="How it works", icon=":material/schema:", url_path="how-it-works"),
    st.Page(page_results, title="Results", icon=":material/insights:", url_path="results"),
]
sections["Account"] = ([st.Page(page_admin, title="User management", icon=":material/admin_panel_settings:", url_path="users")]
                       if RANK >= 3 else []) + [
    st.Page(page_account, title="My account", icon=":material/account_circle:", url_path="account")]
pg = st.navigation(sections)

st.sidebar.markdown("<div style='font-size:20px;font-weight:800;letter-spacing:4px'>TERPE</div>"
                    "<div style='color:#94a3b8;font-size:12px;margin-bottom:10px'>Insider Threat Monitor</div>", unsafe_allow_html=True)
show_gt = st.sidebar.toggle("Evaluation mode", value=False,
                            help="Shows which employees the dataset's answer key marks as real insiders, so you can check "
                                 "the alerts against the truth. A real company would not have an answer key.")
if show_gt:
    st.sidebar.caption("Showing the dataset's answer key: known insiders are marked in red.")
st.sidebar.caption(f"Signed in as **{USER['full_name']}**  \n`{USER['username']}` · {ROLE.title()}")
if st.sidebar.button("Log out", width="stretch"):
    st.session_state.clear()
    st.cache_data.clear()
    st.rerun()

pg.run()
