
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
    page_icon=":material/security:",
    layout="wide"
)



# =========================================================
# TERPE DESIGN SYSTEM
# =========================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #080B12;
    color: #F8FAFC;
}
</style>
""", unsafe_allow_html=True)

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

    # =========================================================
    # TERPE LOGIN PAGE — PREMIUM + FUNCTIONAL
    # =========================================================

    st.markdown("""
    <style>

    /* ================= PAGE ================= */

    .stApp {
        background:
            radial-gradient(
                circle at 8% 20%,
                rgba(67, 56, 202, 0.20),
                transparent 30%
            ),
            radial-gradient(
                circle at 90% 80%,
                rgba(14, 165, 233, 0.12),
                transparent 30%
            ),
            #030712;
    }

    .block-container {
        max-width: 1180px;
        padding-top: 3.2rem;
        padding-bottom: 2rem;
    }


    /* ================= LEFT BRAND ================= */

    .terpe-title {
        font-size: 62px;
        font-weight: 800;
        letter-spacing: 8px;
        line-height: 1;
        color: #ffffff;
        margin-bottom: 12px;
    }

    .terpe-subtitle {
        font-size: 19px;
        color: #b9c7dc;
        margin-bottom: 10px;
    }

    .terpe-description {
        max-width: 500px;
        font-size: 14px;
        line-height: 1.75;
        color: #8290a8;
    }


    /* ================= SECURITY CORE ================= */

    .shield-wrapper {
        height: 275px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 5px 0;
    }

    .shield {
        width: 205px;
        height: 205px;

        display: flex;
        align-items: center;
        justify-content: center;

        border-radius: 50%;

        font-size: 88px;

        background:
            radial-gradient(
                circle,
                rgba(59,130,246,0.30),
                rgba(79,70,229,0.12) 48%,
                rgba(3,7,18,0.15) 72%,
                transparent 74%
            );

        border: 1px solid rgba(96,165,250,0.35);

        box-shadow:
            0 0 28px rgba(59,130,246,0.30),
            0 0 65px rgba(79,70,229,0.16),
            inset 0 0 40px rgba(59,130,246,0.12);

        position: relative;
    }

    .shield::before {
        content: "";
        position: absolute;
        width: 238px;
        height: 238px;
        border-radius: 50%;
        border: 1px solid rgba(56,189,248,0.10);
    }

    .shield::after {
        content: "";
        position: absolute;
        width: 275px;
        height: 275px;
        border-radius: 50%;
        border: 1px solid rgba(99,102,241,0.06);
    }


    /* ================= FEATURES ================= */

    .feature {
        padding: 7px 0;
        color: #b7c3d7;
        font-size: 13px;
    }

    .feature span {
        color: #38bdf8;
        margin-right: 9px;
        font-weight: 700;
    }


    /* ================= REAL STREAMLIT LOGIN CARD ================= */

    /* Streamlit's REAL bordered container */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background:
            linear-gradient(
                145deg,
                rgba(19,30,55,0.96),
                rgba(7,13,28,0.98)
            );

        border: 1px solid rgba(148,163,184,0.18) !important;

        border-radius: 26px !important;

        padding: 34px 34px 30px 34px !important;

        box-shadow:
            0 30px 75px rgba(0,0,0,0.50),
            0 0 45px rgba(59,130,246,0.08);
    }


    /* ================= ACCESS TEXT ================= */

    .access-title {
        font-size: 29px;
        font-weight: 750;
        color: #ffffff;
        margin-bottom: 6px;
    }

    .access-subtitle {
        color: #8998af;
        font-size: 14px;
        line-height: 1.6;
        margin-bottom: 24px;
    }


    /* ================= PASSWORD ================= */

    div[data-testid="stTextInput"] label {
        color: #cbd5e1 !important;
        font-size: 13px !important;
    }

    div[data-testid="stTextInput"] input {
        background: rgba(2,6,23,0.90) !important;
        color: #ffffff !important;

        border: 1px solid #334155 !important;
        border-radius: 11px !important;

        height: 50px !important;

        font-size: 14px !important;
    }

    div[data-testid="stTextInput"] input:focus {
        border-color: #38bdf8 !important;

        box-shadow:
            0 0 0 1px #38bdf8,
            0 0 18px rgba(56,189,248,0.12) !important;
    }


    /* ================= LOGIN BUTTON ================= */

    div.stButton > button {
        width: 100%;
        height: 50px;

        margin-top: 10px;

        border-radius: 11px;

        background:
            linear-gradient(
                100deg,
                #2563eb,
                #4f46e5
            );

        color: #ffffff;

        border: none;

        font-size: 14px;
        font-weight: 700;

        box-shadow:
            0 10px 28px rgba(37,99,235,0.22);

        transition: 0.2s ease;
    }

    div.stButton > button:hover {
        transform: translateY(-2px);

        box-shadow:
            0 14px 32px rgba(59,130,246,0.30);
    }


    /* ================= SECURITY FOOTER ================= */

    .security-note {
        text-align: center;
        color: #59677d;
        font-size: 11px;
        margin-top: 18px;
    }

    </style>
    """, unsafe_allow_html=True)


    # =========================================================
    # SECURITY CHECKS
    # =========================================================

    if not APP_PASSWORD:
        st.error("APP_PASSWORD is not configured.")
        return False

    if st.session_state.get("attempts", 0) >= 5:
        st.error(
            "Too many failed attempts. Refresh the page to try again."
        )
        return False


    # =========================================================
    # TWO-COLUMN LOGIN LAYOUT
    # =========================================================

    left, right = st.columns(
        [1.15, 0.85],
        gap="large"
    )


    # =========================================================
    # LEFT SIDE
    # =========================================================

    with left:

        st.markdown(
            '<div class="terpe-title">TERPE</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="terpe-subtitle">'
            'Threat Exposure & Risk Profiling Engine'
            '</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '<div class="terpe-description">'
            '<b style="color:#cbd5e1;">'
            'Behavioral Security Intelligence for SMEs'
            '</b>'
            '<br><br>'
            'Monitor anomalous employee behavior, track accumulated '
            'risk over time, and investigate potential insider-threat '
            'signals through explainable security analytics.'
            '</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            '''
            <div class="shield-wrapper">
                <div class="shield">🛡</div>
            </div>
            ''',
            unsafe_allow_html=True
        )

        st.markdown(
            '''
            <div class="feature">
                <span>◆</span>
                Behavioral anomaly detection
            </div>

            <div class="feature">
                <span>◆</span>
                Stateful risk profiling
            </div>

            <div class="feature">
                <span>◆</span>
                Explainable security intelligence
            </div>

            <div class="feature">
                <span>◆</span>
                SME-focused threat monitoring
            </div>
            ''',
            unsafe_allow_html=True
        )


    # =========================================================
    # RIGHT SIDE — REAL FUNCTIONAL LOGIN CARD
    # =========================================================

    with right:

        with st.container(border=True):

            st.markdown(
                '<div class="access-title">Secure Access</div>',
                unsafe_allow_html=True
            )

            st.markdown(
                '<div class="access-subtitle">'
                'Sign in to your TERPE security dashboard.'
                '</div>',
                unsafe_allow_html=True
            )

            pw = st.text_input(
                "Dashboard password",
                type="password",
                placeholder="Enter your password"
            )

            if st.button(
                "Log in to TERPE",
                use_container_width=True
            ):

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

            st.markdown(
                '<div class="security-note">'
                '🔒 Protected TERPE security environment'
                '</div>',
                unsafe_allow_html=True
            )


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
        <div style="font-size:42px;">TERPE</div>
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
        "Overview",
        "Investigate User",
        "Live Scoring"
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

if page == "Overview":

    st.title("Insider Threat Monitor")

    st.caption(
        "Behavioral anomaly detection and accumulated risk monitoring "
        "for SME environments."
    )

    st.divider()

    # -----------------------------------------------------
    # USER DISPLAY CONTROL
    # -----------------------------------------------------

    n = st.slider(
        "Number of users to display",
        min_value=5,
        max_value=1000,
        value=100,
        step=5
    )

    top = pd.DataFrame(
        safe(get_top, n)
    )

    # All Overview metrics and charts use the same selected
    # population. Selecting 1000 represents all backend users.
    risk_population = top.copy()

    # -----------------------------------------------------
    # KPI CALCULATIONS
    # -----------------------------------------------------

    total_users = len(risk_population)

    high_risk = int(
        (
            risk_population["peak_risk"]
            >= 0.15524637949938055
        ).sum()
    )

    alert_days = int(
        risk_population["anomaly_days"].sum()
    )

    if "ground_truth_insider" in risk_population.columns:

        insiders = int(
            risk_population["ground_truth_insider"].sum()
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
    # RISK CHARTS
    # -----------------------------------------------------

    left, right = st.columns(
        [1.5, 1]
    )

    with left:

        st.subheader("Top-risk users")

        chart_data = risk_population.sort_values(
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
            (
                risk_population["peak_risk"]
                < 0.05
            ).sum()
        )

        medium = int(
            (
                (risk_population["peak_risk"] >= 0.05)
                &
                (
                    risk_population["peak_risk"]
                    < 0.15524637949938055
                )
            ).sum()
        )

        high = int(
            (
                risk_population["peak_risk"]
                >= 0.15524637949938055
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

    # =====================================================
    # TERPE EVALUATION & RISK PROFILING
    # =====================================================

    st.divider()

    st.subheader(
        "TERPE Evaluation & Risk Profiling"
    )

    st.write(
        "TERPE extends basic anomaly detection by combining "
        "Isolation Forest anomaly scores with stateful risk "
        "profiling. Instead of treating every unusual day as "
        "an independent alert, the system tracks accumulated "
        "risk over time."
    )

    # -----------------------------------------------------
    # TERPE MODEL PIPELINE
    # -----------------------------------------------------

    st.markdown(
        "### From anomaly detection to risk profiling"
    )

    evaluation_data = pd.DataFrame(
        {
            "TERPE layer": [
                "Isolation Forest",
                "Stateful Risk Engine",
                "Behavioral Explanation"
            ],
            "What it does": [
                "Identifies unusual daily employee behaviour",
                "Accumulates and decays risk across time",
                "Highlights behaviours that deviate from the user's baseline"
            ]
        }
    )

    st.dataframe(
        evaluation_data,
        hide_index=True,
        use_container_width=True
    )

    # -----------------------------------------------------
    # RISK LEADERBOARD
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

elif page == "Investigate User":

    st.title("Investigate a User")

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

    st.title("Live Threat Assessment")

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
        "Analyze Activity",
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
                    "ALERT — accumulated risk is above the alert threshold."
                )

            elif result["anomalous_day"]:

                st.warning(
                    "Unusual activity detected, but accumulated risk "
                    "has not reached the alert level."
                )

            else:

                st.success(
                    "Activity is within the expected behavioral range."
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
