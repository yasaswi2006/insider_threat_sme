
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