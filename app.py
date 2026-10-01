import hmac
import os

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(page_title="Insider Threat Monitor", layout="wide")


# ---------- settings (from Streamlit secrets, or environment variables) ----------
def cfg(name, default=""):
    try:
        return str(st.secrets[name])
    except Exception:
        return os.environ.get(name, default)


API_URL = cfg("API_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = cfg("API_KEY")
APP_PASSWORD = cfg("APP_PASSWORD")

FEATURES = ["logons", "distinct_pcs", "after_hours_logons",
            "usb_connects", "usb_after_hours", "file_copies"]
LABELS = {
    "logons": "Logons",
    "distinct_pcs": "Different PCs used",
    "after_hours_logons": "After-hours logons",
    "usb_connects": "USB connections",
    "usb_after_hours": "After-hours USB connections",
    "file_copies": "Files copied to USB",
}


# ---------- login ----------
def login():
    if st.session_state.get("authed"):
        return True
    st.title("Insider Threat Monitor")
    if not APP_PASSWORD:
        st.error("APP_PASSWORD is not configured. The app stays locked.")
        return False
    if st.session_state.get("attempts", 0) >= 5:
        st.error("Too many failed attempts. Close this tab and try again later.")
        return False
    pw = st.text_input("Password", type="password")
    if st.button("Log in"):
        if hmac.compare_digest(pw.encode(), APP_PASSWORD.encode()):
            st.session_state["authed"] = True
            st.rerun()
        else:
            st.session_state["attempts"] = st.session_state.get("attempts", 0) + 1
            st.error("Incorrect password")
    return False


if not login():
    st.stop()


# ---------- talking to the API ----------
def call(method, path, **kwargs):
    try:
        r = requests.request(method, API_URL + path, headers={"X-API-Key": API_KEY},
                             timeout=60, **kwargs)
    except requests.RequestException:
        return None, "Cannot reach the API. Is it running, and is API_URL correct?"
    if r.status_code != 200:
        try:
            detail = r.json().get("detail", "")
        except ValueError:
            detail = ""
        return None, f"API error {r.status_code}: {detail}"
    return r.json(), None


def fetch(path, params=None):
    data, err = call("GET", path, params=params)
    if err:
        raise RuntimeError(err)
    return data


@st.cache_data(ttl=300, show_spinner=False)
def get_top(n):
    return fetch("/users/top", {"n": n})


@st.cache_data(ttl=300, show_spinner=False)
def get_timeline(user_id):
    return fetch(f"/users/{user_id}/timeline")


@st.cache_data(ttl=300, show_spinner=False)
def get_explain(user_id, day):
    return fetch(f"/users/{user_id}/explain", {"day": day})


def safe(fn, *args):
    try:
        return fn(*args)
    except Exception as e:
        st.error(str(e))
        st.stop()


# ---------- sidebar ----------
st.sidebar.title("Insider Threat Monitor")
page = st.sidebar.radio("Page", ["Overview", "Investigate a user", "Live scoring"])
show_gt = st.sidebar.checkbox("Evaluation mode (show ground truth)", value=True)
st.sidebar.caption("Ground truth exists only because this demo uses the CERT r4.2 "
                   "research dataset. A real company would not have it.")
if st.sidebar.button("Log out"):
    st.session_state.clear()
    st.rerun()


# ---------- page 1: overview ----------
if page == "Overview":
    st.title("Insider Threat Monitor for SMEs")
    st.write("Users ranked by accumulated risk. Risk grows when a user's daily behaviour "
             "is unusual and fades on normal days.")
    n = st.slider("How many top-risk users to show", 5, 50, 20)
    top = pd.DataFrame(safe(get_top, n))

    c1, c2, c3 = st.columns(3)
    c1.metric("Users shown", len(top))
    c2.metric("Highest peak risk", f"{top['peak_risk'].max():.3f}")
    if show_gt:
        c3.metric("Real insiders in this list",
                  f"{int(top['ground_truth_insider'].sum())} / {len(top)}")

    view = top.rename(columns={"user": "User", "peak_score": "Peak anomaly score",
                               "anomaly_days": "Anomalous days", "peak_risk": "Peak risk",
                               "ground_truth_insider": "Real insider (ground truth)"})
    if not show_gt:
        view = view.drop(columns=["Real insider (ground truth)"])
    st.dataframe(view, hide_index=True)
    st.bar_chart(top.set_index("user")["peak_risk"])


# ---------- page 2: investigate ----------
elif page == "Investigate a user":
    st.title("Investigate a user")
    users = safe(get_top, 100)
    ids = [u["user"] for u in users]
    uid = st.selectbox("Select a user", ids)

    tl = pd.DataFrame(safe(get_timeline, uid))
    tl["day"] = pd.to_datetime(tl["day"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Days monitored", len(tl))
    c2.metric("Alert days", int(tl["alert"].sum()))
    c3.metric("Peak risk", f"{tl['risk'].max():.3f}")

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=tl["day"], y=tl["anomaly_score"], mode="lines", name="Anomaly score"))
    a = tl[tl["alert"]]
    fig.add_trace(go.Scatter(x=a["day"], y=a["anomaly_score"], mode="markers",
                             name="Alert day", marker=dict(size=7, color="red")))
    if show_gt:
        m = tl[tl["label"] == 1]
        fig.add_trace(go.Scatter(x=m["day"], y=m["anomaly_score"], mode="markers",
                                 name="Malicious day (ground truth)",
                                 marker=dict(size=11, symbol="diamond-open", color="black")))
    fig.update_layout(title=f"Daily anomaly score: {uid}", height=380, margin=dict(t=50, b=10))
    st.plotly_chart(fig)

    fig2 = go.Figure(go.Scatter(x=tl["day"], y=tl["risk"], mode="lines", name="Risk"))
    fig2.update_layout(title=f"Accumulated risk: {uid}", height=300, margin=dict(t=50, b=10))
    st.plotly_chart(fig2)

    st.subheader("Why was a day flagged?")
    top_days = tl.nlargest(10, "anomaly_score")["day"].dt.strftime("%Y-%m-%d").tolist()
    day = st.selectbox("This user's 10 most unusual days", top_days)
    ex = safe(get_explain, uid, day)
    st.write("Largest deviations from this user's own normal behaviour on that day:")
    for r in ex["reasons"]:
        st.write(f"- **{LABELS.get(r['feature'], r['feature'])}**: {r['value']:.0f} on this day, "
                 f"{r['z_score']:+.1f} standard deviations from this user's usual level")
    st.caption("The model also looks at raw counts, so this is an approximate explanation, "
               "not the model's exact reasoning.")


# ---------- page 3: live scoring ----------
else:
    st.title("Live scoring")
    st.write("Enter one user's activity for a day. The app sends it to the API, which compares "
             "it with that user's own baseline and updates their running risk.")
    users = safe(get_top, 100)
    uid = st.selectbox("User", [u["user"] for u in users])

    defaults = {"logons": 3, "distinct_pcs": 3, "after_hours_logons": 0,
                "usb_connects": 0, "usb_after_hours": 0, "file_copies": 0}
    cols = st.columns(3)
    vals = {}
    for i, f in enumerate(FEATURES):
        vals[f] = cols[i % 3].number_input(LABELS[f], min_value=0, max_value=100000,
                                           value=defaults[f], step=1)

    if st.button("Score this day"):
        res, err = call("POST", "/score",
                        json={"user_id": uid, "features": {k: float(v) for k, v in vals.items()}})
        if err:
            st.error(err)
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Anomaly score", f"{res['anomaly_score']:.3f}")
            c2.metric("Running risk", f"{res['risk']:.3f}")
            c3.metric("Unusual day?", "Yes" if res["anomalous_day"] else "No")
            if res["alert"]:
                st.error("ALERT: this user's accumulated risk is above the alert level.")
            else:
                st.success("No alert for this user.")
            st.write("Largest deviations from this user's normal:")
            for r in res["reasons"]:
                st.write(f"- **{LABELS.get(r['feature'], r['feature'])}**: {r['value']:.0f}, "
                         f"{r['z_score']:+.1f} standard deviations from usual")