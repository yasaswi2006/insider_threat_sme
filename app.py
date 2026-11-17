"""TERPE v2 dashboard — streamlit run app.py   (needs API_URL in .streamlit/secrets.toml or env)."""
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
VERDICT_COLOR = {"VIOLATION": "#ef4444", "REVIEW": "#f59e0b", "AUTHORISED": "#22c55e"}
LABELS = {
    "logons": "Logons", "distinct_pcs": "Different PCs used", "after_hours_logons": "After-hours logons",
    "usb_connects": "USB connections", "usb_after_hours": "After-hours USB connections",
    "file_copies": "Files copied to USB", "foreign_pc_logons": "Logons on someone else's PC",
    "exe_copies": "Executables copied", "distinct_file_types": "Different file types",
    "files_after_hours": "Files copied after hours", "first_usb": "First-ever USB use",
    "first_after_hours": "First-ever after-hours logon", "first_foreign_pc": "First-ever foreign-PC logon",
}
RULE_TEXT = {
    "FOREIGN_PC": "PC this employee is not approved to use", "USB_NOT_PROVISIONED": "Employee not approved for USB",
    "EXECUTABLE_TRANSFER": "New executable moved by non-IT role", "AFTER_HOURS": "After hours, not approved for after-hours work",
    "NEW_FILE_TYPE": "File type never handled before",
}

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
    d["Why"] = d["rules"].fillna("").apply(lambda s: " · ".join(RULE_TEXT.get(r, r) for r in s.split("|") if r) or "Within policy")
    cols = [c for c in ["ts", "event", "activity", "filename", "ext", "pc", "verdict", "Why", *extra_cols] if c in d.columns]
    d = d[cols].rename(columns={"ts": "Time", "event": "Event", "activity": "Activity", "filename": "File",
                                "ext": "Type", "pc": "PC", "verdict": "Verdict"})
    st.dataframe(d.style.map(lambda v: f"color:{VERDICT_COLOR.get(v, '')};font-weight:700", subset=["Verdict"]),
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
                    '<div class="terpe-description"><b style="color:#cbd5e1">Policy-grounded insider-threat intelligence for SMEs</b><br><br>'
                    'Fuses behavioural anomaly detection with access-policy verdicts and exfiltration-chain detection, '
                    'so every alert comes with the exact files, PCs and rules behind it.</div><br>', unsafe_allow_html=True)
        for f in ["File-level access authorisation", "Self + peer behavioural baselines",
                  "Exfiltration-chain detection", "Role-based access with full audit trail"]:
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

# ================================================================== SIDEBAR
st.sidebar.markdown(f"""<div style="text-align:center"><div style="font-size:34px;font-weight:800;letter-spacing:5px">TERPE</div>
<div style="color:#94a3b8;font-size:13px">Insider Threat Monitor · v2</div></div>""", unsafe_allow_html=True)
st.sidebar.divider()
pages = ["Overview"]
if RANK >= 2:
    pages += ["Investigate Employee", "File Access Monitor", "Live Scoring"]
pages += ["Methodology & Evaluation"]
if RANK >= 3:
    pages += ["Admin Console"]
pages += ["My Account"]
page = st.sidebar.radio("Navigation", pages)
st.sidebar.divider()
show_gt = st.sidebar.toggle("Evaluation mode (show CERT ground truth)", value=False)
st.sidebar.caption(f"Signed in as **{USER['full_name']}**  \n`{USER['username']}` · {ROLE.title()}")
if st.sidebar.button("Log out", width="stretch"):
    st.session_state.clear()
    st.cache_data.clear()
    st.rerun()


# ================================================================== OVERVIEW
if page == "Overview":
    st.title("Insider Threat Monitor")
    st.caption("Organisation-wide view of behavioural risk, access-policy violations and alerts.")
    ov = cget("/overview")
    top = pd.DataFrame(cget("/users/top", n=1000))
    c = st.columns(4)
    c[0].metric("Employees monitored", ov["employees"])
    c[1].metric("Employees with alerts", ov["alerting_employees"])
    c[2].metric("File transfers in violation", f"{ov['file_verdicts'].get('VIOLATION', 0):,}")
    c[3].metric("Ground-truth insiders" if show_gt else "Files needing review",
                int(top["ground_truth_insider"].sum()) if show_gt else f"{ov['file_verdicts'].get('REVIEW', 0):,}")
    st.caption("**Employees with alerts**: accumulated risk crossed the alert line at least once. "
               "**Violation**: a file transfer that broke the access policy. **Review**: allowed but unusual for that employee.")
    st.divider()
    l, r = st.columns([1.5, 1])
    with l:
        st.subheader("Highest-risk employees")
        n = st.slider("Employees shown", 5, 50, 20)
        d = top.head(n).sort_values("peak_risk")
        colors = ["#ef4444" if (show_gt and g) else "#3b82f6" for g in d["ground_truth_insider"]]
        fig = go.Figure(go.Bar(x=d["peak_risk"], y=d["user"], orientation="h", marker_color=colors))
        fig.update_layout(height=max(380, n * 18), margin=dict(l=10, r=10, t=10, b=10), xaxis_title="Peak accumulated risk")
        st.plotly_chart(fig, width="stretch")
        if show_gt:
            st.caption("Red = labelled insider in CERT r4.2.")
    with r:
        st.subheader("File transfers by verdict")
        fv = ov["file_verdicts"]
        fig = go.Figure(go.Pie(labels=list(fv), values=list(fv.values()), hole=.5,
                               marker_colors=[VERDICT_COLOR.get(k) for k in fv]))
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
        st.subheader("Policy rule hits")
        rh = pd.Series(ov["rule_hits"]).sort_values()
        fig = go.Figure(go.Bar(x=rh.values, y=[RULE_TEXT.get(k, k) for k in rh.index], orientation="h", marker_color="#f59e0b"))
        fig.update_layout(height=230, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
    st.subheader("Alerts and policy violations per week")
    w = pd.DataFrame(ov["weekly"])
    fig = go.Figure([go.Scatter(x=w["week"], y=w["alerts"], name="Alert user-days", line_color="#ef4444"),
                     go.Scatter(x=w["week"], y=w["violations"], name="User-days with violations", line_color="#f59e0b")])
    fig.update_layout(height=300, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig, width="stretch")
    st.subheader("Risk leaderboard")
    view = top.rename(columns={"user": "Employee", "role": "Role", "department": "Department", "peak_risk": "Peak risk",
                               "alert_days": "Alert days", "violations": "Days with violations",
                               "chain_days": "Days with exfil. chains", "anomaly_days": "Anomalous days",
                               "ground_truth_insider": "Ground-truth insider", "scenario": "CERT scenario"})
    view = view.drop(columns=["peak_score"] + ([] if show_gt else ["Ground-truth insider", "CERT scenario"]))
    st.dataframe(view, hide_index=True, width="stretch")


# ================================================================== INVESTIGATE
elif page == "Investigate Employee":
    st.title("Investigate an Employee")
    top = pd.DataFrame(cget("/users/top", n=1000))
    uid = st.selectbox("Employee (sorted by risk)", top["user"],
                       format_func=lambda u: f"{u} · {top.set_index('user').loc[u, 'role']}")
    prof = cget(f"/users/{uid}/profile")
    tl = pd.DataFrame(cget(f"/users/{uid}/timeline"))
    tl["day"] = pd.to_datetime(tl["day"])
    c = st.columns(6)
    for col, (k, v) in zip(c, [("Role", prof["role"]), ("Department", prof["department"]),
                               ("Assigned PC", prof["assigned_pc"]), ("USB / after-hours", f"{'Yes' if prof['usb_approved'] else 'No'} / {'Yes' if prof.get('after_hours_approved') else 'No'}"),
                               ("Peak risk", f"{prof['peak_risk']:.2f}"), ("Alert days", prof["alert_days"])]):
        col.markdown(f'<div class="card" title="{v}"><div class="k">{k}</div><div class="v">{v}</div></div>', unsafe_allow_html=True)
    st.write("")
    if show_gt and prof["ground_truth_insider"]:
        st.error(f"Evaluation mode: CERT labels this employee as an insider (scenario {prof['scenario']}).")

    with st.expander("How to read this page"):
        st.markdown("""
- **Grey bars (daily evidence)**: how suspicious each single day was = ML anomaly + policy violations + attack chains.
- **Blue line (accumulated risk)**: evidence adds up over days and fades by 20% per day when nothing happens, so one odd day fades away while repeated suspicious days build up.
- **Red dots (alerts)**: days when the accumulated risk crossed the alert line (set so only the top 1% of all employee-days alert).
- **Verdicts on each file / logon / USB event**: *Authorised* = within the employee's approved context; *Review* = unusual but allowed
  (e.g. new file type); *Violation* = breaks the access policy (e.g. USB used by someone not approved for USB).
""")
    t1, t2 = st.tabs(["Risk timeline & daily evidence", "All file transfers"])
    with t1:
        fig = go.Figure()
        fig.add_bar(x=tl["day"], y=tl["evidence"], name="Daily evidence", marker_color="#64748b", opacity=.6)
        fig.add_scatter(x=tl["day"], y=tl["risk"], name="Accumulated risk", line_color="#38bdf8")
        al = tl[tl["alert"]]
        fig.add_scatter(x=al["day"], y=al["risk"], mode="markers", name="Alert", marker=dict(color="#ef4444", size=8))
        if show_gt:
            m = tl[tl["label"] == 1]
            fig.add_scatter(x=m["day"], y=m["risk"], mode="markers", name="Malicious (ground truth)",
                            marker=dict(symbol="x", color="#fbbf24", size=9))
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h"))
        st.plotly_chart(fig, width="stretch")

        st.subheader("Why was this employee flagged on a given day?")
        cand = tl.sort_values("evidence", ascending=False)
        cand = cand[cand["evidence"] > 0].head(30)
        if cand.empty:
            st.info("No day with risk evidence for this employee.")
        else:
            day = st.selectbox("Day (strongest evidence first)", cand["day"].dt.strftime("%Y-%m-%d"),
                               format_func=lambda d: f"{d}  ·  evidence {cand.set_index(cand['day'].dt.strftime('%Y-%m-%d')).loc[d, 'evidence']:.2f}")
            dd = cget(f"/users/{uid}/day/{day}")
            s = dd["scores"]
            k = st.columns(5)
            k[0].metric("Anomaly (ML)", f"{s['anomaly_excess']:.2f}")
            k[1].metric("Policy", f"{s['policy_norm']:.2f}")
            k[2].metric("Chains", int(s["chain_score"]))
            k[3].metric("Day evidence", f"{s['evidence']:.2f}")
            k[4].metric("Risk after day", f"{s['risk']:.2f}", "ALERT" if dd["alert"] else None, delta_color="inverse")
            for rsn in dd["reasons"]:
                cls = "chain" if rsn.startswith("Chain") else "policy" if rsn.startswith("Policy") else ""
                st.markdown(f'<div class="reason {cls}">{rsn}</div>', unsafe_allow_html=True)
            st.markdown("##### Files copied to removable media that day")
            verdict_table(pd.DataFrame(dd["files"]))
            st.markdown("##### Logons and USB events outside the normal pattern")
            verdict_table(pd.DataFrame(dd["access"]))
            st.markdown("##### Behavioural deviations")
            dv = pd.DataFrame(dd["deviations"])
            dv["feature"] = dv["feature"].map(LABELS)
            st.dataframe(dv.rename(columns={"feature": "Behaviour", "value": "Value", "z_self": "vs own history (σ)",
                                            "z_peer": "vs same-role peers (σ)"}), hide_index=True, width="stretch")
    with t2:
        v = st.radio("Show", ["All", "VIOLATION", "REVIEW", "AUTHORISED"], horizontal=True)
        fl = pd.DataFrame(cget(f"/users/{uid}/files", **({} if v == "All" else {"verdict": v})))
        if not fl.empty:
            k = st.columns(3)
            for i, vv in enumerate(["VIOLATION", "REVIEW", "AUTHORISED"]):
                k[i].metric(vv.title(), int((fl["verdict"] == vv).sum()))
        verdict_table(fl)
        st.caption("CERT r4.2 records files copied to removable media. Each transfer is checked against the access policy "
                   "(see Methodology): assigned PC, USB approval, working hours, executable rules and the employee's usual file types.")


# ================================================================== FILE ACCESS MONITOR
elif page == "File Access Monitor":
    st.title("File Access Monitor")
    st.caption("Every file transfer checked against the access policy, across the whole organisation.")
    v = st.radio("Verdict", ["VIOLATION", "REVIEW"], horizontal=True)
    lim = st.select_slider("Most recent", [100, 500, 1000, 5000], value=500)
    fl = pd.DataFrame(cget("/files/feed", verdict=v, limit=lim))
    if fl.empty:
        st.info("Nothing to show.")
    else:
        rules = sorted({r for s in fl["rules"] for r in s.split("|") if r})
        pick = st.multiselect("Filter by rule", rules, format_func=lambda r: RULE_TEXT.get(r, r))
        if pick:
            fl = fl[fl["rules"].apply(lambda s: any(r in s.split("|") for r in pick))]
        c = st.columns(3)
        c[0].metric("Transfers", len(fl))
        c[1].metric("Employees", fl["user"].nunique())
        c[2].metric("PCs", fl["pc"].nunique())
        verdict_table(fl.rename(columns={"user": "Employee"}), extra_cols=("Employee",))


# ================================================================== LIVE SCORING
elif page == "Live Scoring":
    st.title("Live Threat Assessment")
    st.caption("Enter one employee's activity for a day. TERPE scores it with the ML model, the access policy and the chain detector.")
    top = pd.DataFrame(cget("/users/top", n=1000))
    uid = st.selectbox("Employee", top["user"])
    defaults = dict(logons=2, distinct_pcs=1, after_hours_logons=0, usb_connects=0, usb_after_hours=0, file_copies=0,
                    foreign_pc_logons=0, exe_copies=0, distinct_file_types=0, files_after_hours=0)
    vals, cols = {}, st.columns(3)
    for i, (f, dv_) in enumerate(defaults.items()):
        vals[f] = cols[i % 3].number_input(LABELS[f], 0, 100000, dv_, 1)
    if st.button("Analyse activity", width="stretch", type="primary"):
        res, err = api("POST", "/score", json={"user_id": uid, "features": {k: float(v) for k, v in vals.items()}})
        if err:
            st.error(err)
        else:
            c = st.columns(5)
            c[0].metric("Anomaly score", f"{res['anomaly_score']:.3f}")
            c[1].metric("ML component", f"{res['anomaly_component']:.2f}")
            c[2].metric("Policy component", f"{res['policy_component']:.2f}")
            c[3].metric("Chains", res["chain_component"])
            c[4].metric("Accumulated risk", f"{res['risk']:.2f}", f"threshold {res['alert_threshold']:.2f}", delta_color="off")
            if res["alert"]:
                st.error("ALERT — accumulated risk is above the alert threshold.")
            elif res["evidence"] > 0:
                st.warning("Risk evidence recorded, but accumulated risk is below the alert threshold.")
            else:
                st.success("Activity is within this employee's normal pattern and the access policy.")
            ctx = res["context"]
            st.caption(f"Context · {ctx['role']} in {ctx['department']} · assigned PC {ctx['assigned_pc']} · "
                       f"USB approved: {'yes' if ctx['usb_approved'] else 'no'}")
            for k_, n_ in res["policy_hits"].items():
                st.markdown(f'<div class="reason policy">Policy · {RULE_TEXT.get(k_, k_)} ({int(n_)} events)</div>', unsafe_allow_html=True)
            for ch in res["chains"]:
                st.markdown(f'<div class="reason chain">Chain · {ch.replace("CHAIN_", "").replace("_", " ").title()}</div>', unsafe_allow_html=True)


# ================================================================== METHODOLOGY
elif page == "Methodology & Evaluation":
    st.title("Methodology & Evaluation")
    ev = cget("/evaluation")
    st.markdown("""
**TERPE v2 = behaviour anomaly (ML) + access-policy verdicts (rules) + exfiltration chains (sequences), fused into one accumulated risk.**

| Layer | What it adds | Why it matters |
|---|---|---|
| **Causal baselines** | Each day is compared only with the employee's *past* days | v1 compared each day with the full period, including the future: impossible in a live system and optimistic in evaluation |
| **Peer baseline** | Same-day deviation from employees in the same job role | Catches insiders who behave abnormally from day one, so their own history looks "normal" |
| **Context features** | Foreign-PC logons, executable transfers, first-ever USB / after-hours / foreign-PC behaviour | The CERT insider scenarios are about *new* behaviour, which raw counts miss |
| **Context-provisioned policy** | Every logon, USB and file event gets an *Authorised / Review / Violation* verdict against the employee's own approved context: approved PCs, USB approval, after-hours approval, usual file types | Gives analysts concrete, auditable evidence ("copied 14 files on a PC that isn't theirs") instead of a bare score |
| **Exfiltration chains** | Ordered sequences such as after-hours logon → USB → file copy | Single events are ambiguous; the ordered combination is the attack pattern |
| **Risk fusion** | `risk_t = 0.8^(days since last activity) · risk_(t-1) + anomaly + policy + chains` | Repeated weak evidence accumulates; the alert threshold is set by an analyst *alert budget* (top 1% of user-days), not by labels |
""")
    ab = pd.DataFrame(ev["ablation"])
    v1 = ab[ab["layer"].str.startswith("L0")].iloc[0]
    v2 = ab[ab["layer"].str.startswith("L5")].iloc[0]
    ro = ab[ab["layer"].str.startswith("R")].iloc[0]
    st.subheader("What the results say")
    st.markdown(f"""
The dataset has **1,000 employees, {int(v2['insiders_detected'].split('/')[1])} of whom are real insiders** (known only because CERT publishes the answer key).
An analyst cannot read everyone's logs, so the question is: *if the analyst only looks at the employees TERPE ranks highest, how many real insiders do they find?*

- **Top 10 employees:** TERPE v1 had **{int(v1['p@10']*10)}** real insiders in its top 10; TERPE v2 has **{int(v2['p@10']*10)}**.
  Top 20: **{int(v1['p@20']*20)} → {int(v2['p@20']*20)}**. In simple terms, almost every person v2 puts at the top of the list really is an insider.
- **Caught while the attack was happening:** v1 raised an alert during the malicious period for **{v1['insiders_detected']}** insiders; v2 does it for **{v2['insiders_detected']}**,
  usually on the very first malicious day (median delay **{v2['median_delay_days']:.0f} days**).
- **Cost of that:** v2 also alerts on **{int(v2['false_alert_users'])}** normal employees (out of ~930), v1 on {int(v1['false_alert_users'])}.
  The analyst reviews more people, but finds four times as many insiders.
- **Why combine rules and ML instead of rules alone?** The access rules on their own rank insiders just as well, but they alert on
  **{int(ro['false_alert_users'])}** normal employees. Fusing them with the ML score and accumulating risk over days keeps the same insiders while cutting false alerts by about
  **{(1 - v2['false_alert_users']/ro['false_alert_users'])*100:.0f}%**.
- **The ML layers alone (L1–L3) do not improve on v1.** The causal baseline removes v1's look-ahead into future days (an unfair advantage), so its numbers drop slightly. This is
  reported honestly: the improvement comes from *combining* behaviour, policy and attack-chain evidence, not from any single model.
- **By insider type:** after-hours data theft (scenario 1) and the disgruntled IT admin (scenario 3) are caught almost completely. The job-hunting insider (scenario 2) is mostly missed,
  because those employees were already approved USB users and their main warning sign is web browsing, which this version does not use yet (future work).
""")
    with st.expander("What do the column names mean?"):
        st.markdown("""
- **User AUC**: probability that a randomly chosen insider is ranked above a randomly chosen normal employee (0.5 = random, 1 = perfect).
- **User AP (average precision)**: how concentrated the insiders are at the top of the ranking; more sensitive than AUC when insiders are rare (7%).
- **Precision@k**: share of real insiders among the top *k* employees: what an analyst who reviews *k* people actually finds.
- **Insiders detected**: insiders with an alert between their first malicious day and one week after their last.
- **Median detection delay**: days between the first malicious action and the first alert (0 = same day).
- **False-alert employees**: normal employees who received at least one alert.
- **Day-level AUC**: how well single days are separated; many malicious CERT days are web/email-only and invisible to these logs, which keeps this number low for every layer.
""")
    st.subheader("Ablation study: what each layer contributes")
    show = ab[["layer", "user_auc", "user_ap", "p@10", "p@20", "p@50", "insiders_detected", "median_delay_days",
               "false_alert_users", "day_auc"]].rename(columns={
        "layer": "Layer", "user_auc": "User AUC", "user_ap": "User AP", "p@10": "Precision@10", "p@20": "Precision@20",
        "p@50": "Precision@50", "insiders_detected": "Insiders detected", "median_delay_days": "Median detection delay (days)",
        "false_alert_users": "False-alert employees", "day_auc": "Day-level AUC"})
    st.dataframe(show.style.format(precision=3), hide_index=True, width="stretch")
    short = ab["layer"].str.split(" · ").str[0].replace({"L0": "L0 v1", "L5": "L5 v2", "R": "Rules only"})
    fig = go.Figure([go.Bar(x=short, y=ab["user_ap"], name="User-level AP"),
                     go.Bar(x=short, y=ab["p@20"], name="Precision@20")])
    fig.update_layout(barmode="group", height=360, margin=dict(l=10, r=10, t=10, b=10), legend=dict(orientation="h"))
    st.plotly_chart(fig, width="stretch")
    st.caption("All layers use the same unsupervised detector and the same alert budget, so the rows compare like with like. "
               "Ground-truth labels are used only to score each row, never to train or tune.")
    st.subheader("Access policy in force")
    pol = ev["policy"]
    st.dataframe(pd.DataFrame([{"Rule": k, "Meaning": v["text"], "Severity": v["severity"],
                                "Verdict": "Violation" if v["severity"] >= 3 else "Review"} for k, v in pol["rules"].items()]),
                 hide_index=True, width="stretch")
    st.caption(f"Working hours {pol['work_hours']['start']}:00–{pol['work_hours']['end']}:00 on weekdays · "
               f"multi-PC roles: {', '.join(pol['multi_pc_roles'])} · executable transfers allowed for: "
               f"{', '.join(pol['executable_allowed_roles'])} · approved PCs, USB use, after-hours work and usual file types are learned from each "
               f"employee's first {pol['provisioning_days']} days (an SME would set these in its IT policy).")


# ================================================================== ADMIN
elif page == "Admin Console":
    st.title("Admin Console")
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
elif page == "My Account":
    st.title("My Account")
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
