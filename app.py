"""
Aegis-Twin · AI-Driven Digital Twin Dashboard
==============================================
Enterprise Fleet Manager Edition.

Run with: streamlit run app.py
"""

import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from auth import create_user, has_users, init_db
from auth_page import render_login_page
from dashboard import render_device_dashboard
from model import LSTMAutoencoder
from registry import IOT_REGISTRY, SESSION_DEFAULTS
from ui import NEON_GREEN, NEON_RED, inject_css

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Aegis-Twin Fleet Manager",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
load_dotenv()
init_db()

if not has_users():
    admin_email    = os.environ.get("AEGIS_ADMIN_EMAIL")
    admin_password = os.environ.get("AEGIS_ADMIN_PASSWORD")
    if admin_email and admin_password:
        try:
            create_user(admin_email, admin_password)
        except Exception:
            pass

inject_css()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
for k, v in SESSION_DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------------------------------------------------------------------------
# Auth guard
# ---------------------------------------------------------------------------
if not st.session_state.authenticated:
    render_login_page()

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
@st.cache_resource
def load_aegis_engine():
    model = LSTMAutoencoder()
    model.eval()
    return model

autoencoder = load_aegis_engine()

# ---------------------------------------------------------------------------
# PAGE 1 — Fleet overview
# ---------------------------------------------------------------------------
def render_fleet_page():
    st.markdown("<h1 style='text-align:center;color:white;'>🌐 Enterprise Fleet Manager</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#aaa;'>Select a registered IoT device to enter its continuous monitoring Digital Twin dashboard.</p>", unsafe_allow_html=True)
    st.divider()

    cols = st.columns(4)
    for idx, (dev_id, info) in enumerate(IOT_REGISTRY.items()):
        with cols[idx % 4]:
            health  = st.session_state.device_health.get(dev_id, "Healthy")
            h_color = NEON_GREEN if health == "Healthy" else NEON_RED
            h_text  = "● ONLINE" if health == "Healthy" else "● CRITICAL"
            h_anim  = "none" if health == "Healthy" else "blinker 1s linear infinite"

            st.markdown(f"""
            <div class="fleet-card">
                <div style="font-size:3rem;">{info['icon']}</div>
                <h3 style="color:white;margin-bottom:5px;">{info['name']}</h3>
                <p style="color:#00cfff;font-size:0.9em;margin-bottom:5px;">ID: {dev_id}</p>
                <p style="color:#aaa;font-size:0.8em;margin-bottom:15px;">Sector: {info['sector']} | Type: {info['type']}</p>
                <div style="color:{h_color};font-weight:bold;margin-bottom:10px;animation:{h_anim};">{h_text}</div>
            </div>""", unsafe_allow_html=True)

            if st.button("View Digital Twin", key=f"btn_{dev_id}", width="stretch"):
                st.session_state.active_device  = dev_id
                st.session_state.page           = "dashboard"
                st.session_state.packet_history = pd.DataFrame(columns=["Time","Pkt Size","IAT","Entropy","Symmetry","Status"])
                st.session_state.threat_log     = []
                st.rerun()

    st.divider()

    if st.session_state.remediation_log:
        st.markdown("### 🛠️ Remediation History")
        st.dataframe(pd.DataFrame(st.session_state.remediation_log), width="stretch", hide_index=True)

    if st.session_state.audit_logs:
        st.markdown("### 🧾 Audit Trail")
        st.dataframe(pd.DataFrame(st.session_state.audit_logs), width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
if st.session_state.page == "fleet":
    render_fleet_page()
elif st.session_state.page == "dashboard":
    render_device_dashboard(autoencoder)