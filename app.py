
import hmac
import os

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Insider Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CONFIGURATION
# =========================================================

def cfg(name, default=""):
    try:
        return str(st.secrets[name])
    except Exception:
        return os.environ.get(name, default)


API_URL = cfg("API_URL", "http://127.0.0.1:8000").rstrip("/")
API_KEY = cfg("API_KEY")
APP_PASSWORD = cfg("APP_PASSWORD")


FEATURES = [
    "logons",
    "distinct_pcs",
    "after_hours_logons",
    "usb_connects",
    "usb_after_hours",
    "file_copies"
]


LABELS = {
    "logons": "Logons",
    "distinct_pcs": "Different PCs used",
    "after_hours_logons": "After-hours logons",
    "usb_connects": "USB connections",
    "usb_after_hours": "After-hours USB connections",
    "file_copies": "Files copied to USB",
}


# =========================================================
# LOGIN
# =========================================================

def login():

    if st.session_state.get("authed"):
        return True

    st.markdown(
        """
        <div style="text-align:center; padding-top:70px;">
            <div style="font-size:55px;">🛡️</div>
            <h1>Insider Threat Monitor</h1>
            <p style="font-size:18px;">
                Behavioral security analytics for SMEs
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    if not APP_PASSWORD:
        st.error("APP_PASSWORD is not configured.")
        return False

    if st.session_state.get("attempts", 0) >= 5:
        st.error("Too many failed attempts. Refresh the page to try again.")
        return False

    pw = st.text_input(
        "Dashboard password",
        type="password"
    )

    if st.button("Log in", use_container_width=True):

        if hmac.compare_digest(
            pw.encode(),
            APP_PASSWORD.encode()
        ):
            st.session_state["authed"] = True
            st.rerun()

        else:
            st.session_state["attempts"] = (
                st.session_state.get("attempts", 0) + 1
            )
            st.error("Incorrect password.")

    return False


if not login():
    st.stop()


# =========================================================
# API FUNCTIONS
# =========================================================

def call(method, path, **kwargs):

    try:

        response = requests.request(
            method,
            API_URL + path,
            headers={"X-API-Key": API_KEY},
            timeout=60,
            **kwargs
        )

    except requests.RequestException:

        return None, (
            "Cannot reach the API. "
            "Make sure FastAPI is running on port 8000."
        )

    if response.status_code != 200:

        try:
            detail = response.json().get("detail", "")
        except ValueError:
            detail = ""

        return None, f"API error {response.status_code}: {detail}"

    return response.json(), None


def fetch(path, params=None):

    data, error = call(
        "GET",
        path,
        params=params
    )

    if error:
        raise RuntimeError(error)

    return data


@st.cache_data(ttl=300, show_spinner=False)
def get_top(n):

    return fetch(
        "/users/top",
        {"n": n}
    )


@st.cache_data(ttl=300, show_spinner=False)
def get_timeline(user_id):

    return fetch(
        f"/users/{user_id}/timeline"
    )


@st.cache_data(ttl=300, show_spinner=False)
def get_explain(user_id, day):

    return fetch(
        f"/users/{user_id}/explain",
        {"day": day}
    )


def safe(function, *args):

    try:
        return function(*args)

    except Exception as e:

        st.error(str(e))
        st.stop()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.markdown(
    """
    <div style="text-align:center;">
        <div style="font-size:42px;">🛡️</div>
        <h2>Insider Threat Monitor</h2>
        <p>SME Security Analytics</p>
    </div>
    """,
    unsafe_allow_html=True
)

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "🔍 Investigate User",
        "⚡ Live Scoring"
    ]
)

st.sidebar.divider()

show_gt = st.sidebar.checkbox(
    "Evaluation mode",
    value=True
)

if show_gt:

    st.sidebar.info(
        "Ground truth is available because this "
        "demonstration uses the CERT r4.2 research dataset."
    )

else:

    st.sidebar.caption(
        "Evaluation mode is disabled. "
        "This view represents a real deployment."
    )

if st.sidebar.button(
    "Log out",
    use_container_width=True
):

    st.session_state.clear()
    st.rerun()


# =========================================================
# OVERVIEW
# =========================================================

if page == "📊 Overview":

    st.title("🛡️ Insider Threat Monitor")

    st.caption(
        "Behavioral anomaly detection and accumulated risk monitoring "
        "for SME environments."
    )

    st.divider()

    n = st.slider(
        "Number of users to display",
        5,
        50,
        20
    )

    top = pd.DataFrame(
        safe(get_top, n)
    )

    # -----------------------------------------------------
    # KPI CALCULATIONS
    # -----------------------------------------------------

    total_users = len(top)

    high_risk = int(
        (top["peak_risk"] >= 0.15524637949938055).sum()
    )

    alert_days = int(
        top["anomaly_days"].sum()
    )

    if "ground_truth_insider" in top.columns:

        insiders = int(
            top["ground_truth_insider"].sum()
        )

    else:

        insiders = 0


    # -----------------------------------------------------
    # KPI CARDS
    # -----------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Users displayed",
        total_users
    )

    c2.metric(
        "High-risk users",
        high_risk
    )

    c3.metric(
        "Anomalous days",
        alert_days
    )

    if show_gt:

        c4.metric(
            "Ground-truth insiders",
            insiders
        )

    else:

        c4.metric(
            "Monitoring status",
            "Active"
        )


    st.divider()


    # -----------------------------------------------------
    # RISK CHART
    # -----------------------------------------------------

    left, right = st.columns(
        [1.5, 1]
    )


    with left:

        st.subheader("Top-risk users")

        chart_data = top.sort_values(
            "peak_risk",
            ascending=True
        )

        fig = go.Figure()

        fig.add_trace(
            go.Bar(
                x=chart_data["peak_risk"],
                y=chart_data["user"],
                orientation="h",
                name="Peak risk"
            )
        )

        fig.update_layout(
            height=480,
            margin=dict(
                l=10,
                r=10,
                t=20,
                b=20
            ),
            xaxis_title="Peak risk",
            yaxis_title="User",
            showlegend=False
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )


    with right:

        st.subheader("Risk distribution")

        low = int(
            (top["peak_risk"] < 0.05).sum()
        )

        medium = int(
            (
                (top["peak_risk"] >= 0.05)
                &
                (top["peak_risk"] < 0.15524637949938055)
            ).sum()
        )

        high = int(
            (
                top["peak_risk"] >= 0.15524637949938055
            ).sum()
        )

        distribution = pd.DataFrame(
            {
                "Level": [
                    "Low",
                    "Medium",
                    "High"
                ],
                "Users": [
                    low,
                    medium,
                    high
                ]
            }
        )

        fig2 = go.Figure(
            data=[
                go.Pie(
                    labels=distribution["Level"],
                    values=distribution["Users"],
                    hole=0.45
                )
            ]
        )

        fig2.update_layout(
            height=480,
            margin=dict(
                l=10,
                r=10,
                t=20,
                b=20
            )
        )

        st.plotly_chart(
            fig2,
            use_container_width=True
        )


    # -----------------------------------------------------
    # TABLE
    # -----------------------------------------------------

    st.subheader("Risk leaderboard")

    view = top.rename(
        columns={
            "user": "User",
            "peak_score": "Peak anomaly score",
            "anomaly_days": "Anomalous user-days",
            "peak_risk": "Peak risk",
            "ground_truth_insider":
                "Ground-truth insider"
        }
    )

    if not show_gt and "Ground-truth insider" in view.columns:

        view = view.drop(
            columns=["Ground-truth insider"]
        )

    st.dataframe(
        view,
        hide_index=True,
        use_container_width=True
    )


# =========================================================
# INVESTIGATE USER
# =========================================================

elif page == "🔍 Investigate User":

    st.title("🔍 Investigate a User")

    st.caption(
        "Review an employee's behavioral history, anomaly scores, "
        "accumulated risk and the main factors associated with unusual activity."
    )

    users = safe(
        get_top,
        100
    )

    ids = [
        u["user"]
        for u in users
    ]

    uid = st.selectbox(
        "Select employee",
        ids
    )

    tl = pd.DataFrame(
        safe(
            get_timeline,
            uid
        )
    )

    tl["day"] = pd.to_datetime(
        tl["day"]
    )

    # -----------------------------------------------------
    # USER METRICS
    # -----------------------------------------------------

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Days monitored",
        len(tl)
    )

    c2.metric(
        "Alert days",
        int(tl["alert"].sum())
    )

    c3.metric(
        "Peak risk",
        f"{tl['risk'].max():.3f}"
    )

    st.divider()


    # -----------------------------------------------------
    # ANOMALY TIMELINE
    # -----------------------------------------------------

    st.subheader(
        "Behavioral anomaly timeline"
    )

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=tl["day"],
            y=tl["anomaly_score"],
            mode="lines",
            name="Anomaly score"
        )
    )

    alerts = tl[
        tl["alert"]
    ]

    fig.add_trace(
        go.Scatter(
            x=alerts["day"],
            y=alerts["anomaly_score"],
            mode="markers",
            name="Alert"
        )
    )

    if show_gt:

        malicious = tl[
            tl["label"] == 1
        ]

        fig.add_trace(
            go.Scatter(
                x=malicious["day"],
                y=malicious["anomaly_score"],
                mode="markers",
                name="Ground truth"
            )
        )

    fig.update_layout(
        height=400,
        xaxis_title="Date",
        yaxis_title="Anomaly score",
        margin=dict(
            t=20,
            b=20
        )
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


    # -----------------------------------------------------
    # RISK TIMELINE
    # -----------------------------------------------------

    st.subheader(
        "Accumulated risk"
    )

    fig2 = go.Figure()

    fig2.add_trace(
        go.Scatter(
            x=tl["day"],
            y=tl["risk"],
            mode="lines",
            name="Risk"
        )
    )

    fig2.update_layout(
        height=320,
        xaxis_title="Date",
        yaxis_title="Risk score",
        margin=dict(
            t=20,
            b=20
        )
    )

    st.plotly_chart(
        fig2,
        use_container_width=True
    )


    # -----------------------------------------------------
    # EXPLANATION
    # -----------------------------------------------------

    st.divider()

    st.subheader(
        "Why was this user flagged?"
    )

    top_days = (
        tl.nlargest(
            10,
            "anomaly_score"
        )["day"]
        .dt.strftime("%Y-%m-%d")
        .tolist()
    )

    day = st.selectbox(
        "Select one of the user's most unusual days",
        top_days
    )

    explanation = safe(
        get_explain,
        uid,
        day
    )

    st.write(
        f"Behavioral deviations for **{uid}** on **{day}**:"
    )

    for reason in explanation["reasons"]:

        feature = LABELS.get(
            reason["feature"],
            reason["feature"]
        )

        z = reason["z_score"]

        if z >= 2:

            icon = "🔴"

        elif z >= 1:

            icon = "🟠"

        else:

            icon = "🟡"

        st.markdown(
            f"""
            {icon} **{feature}**

            Value: **{reason['value']:.0f}**  
            Deviation from personal baseline: **{z:+.1f}σ**
            """
        )

        st.divider()

    st.caption(
        "These explanations show the largest deviations from the "
        "user's personal baseline. They are an approximation of the "
        "model's reasoning, not a complete explanation of the model."
    )


# =========================================================
# LIVE SCORING
# =========================================================

else:

    st.title("⚡ Live Threat Assessment")

    st.caption(
        "Enter one employee's activity for a day and evaluate "
        "whether the behavior is unusual."
    )

    users = safe(
        get_top,
        100
    )

    ids = [
        u["user"]
        for u in users
    ]

    uid = st.selectbox(
        "Employee",
        ids
    )

    st.divider()

    st.subheader(
        "Daily activity"
    )

    defaults = {
        "logons": 3,
        "distinct_pcs": 3,
        "after_hours_logons": 0,
        "usb_connects": 0,
        "usb_after_hours": 0,
        "file_copies": 0
    }

    vals = {}

    col1, col2, col3 = st.columns(3)

    columns = [
        col1,
        col2,
        col3
    ]

    for i, feature in enumerate(FEATURES):

        with columns[i % 3]:

            vals[feature] = st.number_input(
                LABELS[feature],
                min_value=0,
                max_value=100000,
                value=defaults[feature],
                step=1
            )


    st.divider()

    if st.button(
        "🔎 Analyze Activity",
        use_container_width=True
    ):

        result, error = call(
            "POST",
            "/score",
            json={
                "user_id": uid,
                "features": {
                    k: float(v)
                    for k, v in vals.items()
                }
            }
        )

        if error:

            st.error(error)

        else:

            st.subheader(
                "Assessment"
            )

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "Anomaly score",
                f"{result['anomaly_score']:.3f}"
            )

            c2.metric(
                "Running risk",
                f"{result['risk']:.3f}"
            )

            c3.metric(
                "Unusual activity",
                "YES"
                if result["anomalous_day"]
                else "NO"
            )


            if result["alert"]:

                st.error(
                    "🚨 ALERT — accumulated risk is above the alert threshold."
                )

            elif result["anomalous_day"]:

                st.warning(
                    "⚠️ Unusual activity detected, but accumulated risk "
                    "has not reached the alert level."
                )

            else:

                st.success(
                    "✅ Activity is within the expected behavioral range."
                )


            st.divider()

            st.subheader(
                "Main behavioral deviations"
            )

            for reason in result["reasons"]:

                feature = LABELS.get(
                    reason["feature"],
                    reason["feature"]
                )

                st.write(
                    f"**{feature}** — "
                    f"{reason['value']:.0f} "
                    f"({reason['z_score']:+.1f}σ from baseline)"
                )
