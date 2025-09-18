"""
BOUNTY HUNTERS DASHBOARD
Streamlit app for Proactive Security Patch Automation Framework.
Accepts any CSV upload (no schema restrictions).
Supports multi-row patching + theme toggle + multiple chart options.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import random
from datetime import datetime

# ---------------- CONFIG ----------------
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
np.random.seed(42)
random.seed(42)

# ---------------- HELPERS ----------------
def apply_patch(df, indices):
    for idx in indices:
        df.loc[idx, ["status", "severity", "cve_id", "cvss"]] = ["Safe", "None", "None", None]
        df.loc[idx, "applied_patch_version"] = "latest"
    return df

# ---------------- THEME HANDLING ----------------
if "theme" not in st.session_state:
    st.session_state.theme = "light"  # default

def set_theme(theme):
    st.session_state.theme = theme

# Background styling
if st.session_state.theme == "light":
    bg_color = "#e0f2fe"  # light blue
else:
    bg_color = "#1e3a8a"  # dark blue

st.markdown(
    f"""
    <style>
    body {{
        background-color: {bg_color};
    }}
    .big-title {{
        font-size: 50px;
        font-weight: 900;
        text-align: center;
        color: white;
        margin-bottom: 20px;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------- TOP NAV BAR ----------------
col1, col2 = st.columns([10, 1])
with col1:
    st.markdown(
        '<div class="big-title"> 🛡⚔ BOUNTY HUNTERS DASHBOARD ⚔🛡</div>',
        unsafe_allow_html=True,
    )
with col2:
    if st.button("🌙" if st.session_state.theme == "light" else "☀"):
        set_theme("dark" if st.session_state.theme == "light" else "light")
        st.experimental_rerun()

# ---------------- APP BODY ----------------
uploaded = st.file_uploader("📂 Upload any CSV file", type=["csv"])

if uploaded:
    df = pd.read_csv(uploaded)

    # Ensure unique identifier
    if "id" not in df.columns:
        df.insert(0, "id", range(1, len(df) + 1))

    # ---- SIMULATE VULNERABILITY DATA ----
    df["cve_id"] = [f"CVE-{random.randint(1000,9999)}" for _ in range(len(df))]
    df["cvss"] = np.round(np.random.uniform(2, 9, size=len(df)), 1)
    df["severity"] = df["cvss"].apply(lambda x: SEVERITY_LEVELS[int(x//3)])
    df["patch_recommendation"] = "Update to latest"
    df["status"] = "Vulnerable"
    df["applied_patch_version"] = None
    df["timestamp"] = datetime.utcnow().isoformat() + "Z"

    # ---- DISPLAY TABLE ----
    st.subheader("📋 Detected Vulnerabilities")
    st.dataframe(df, use_container_width=True)

    # ---- CHART OPTIONS ----
    st.subheader("📊 Visualize Vulnerabilities")
    chart_type = st.selectbox("Choose chart type", ["Bar", "Pie", "Scatter", "Line", "Heatmap"])

    if chart_type == "Bar":
        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.bar(counts, x="Severity", y="Count", color="Severity", title="Severity Distribution")
        st.plotly_chart(fig, use_container_width=True)

    elif chart_type == "Pie":
        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.pie(counts, values="Count", names="Severity", title="Severity Breakdown")
        st.plotly_chart(fig, use_container_width=True)

    elif chart_type == "Scatter":
        fig = px.scatter(df, x="id", y="cvss", color="severity",
                         hover_data=["cve_id", "status"],
                         title="CVSS Scores by ID")
        st.plotly_chart(fig, use_container_width=True)

    elif chart_type == "Line":
        fig = px.line(df, x="id", y="cvss", color="severity",
                      markers=True, title="CVSS Trend by ID")
        st.plotly_chart(fig, use_container_width=True)

    elif chart_type == "Heatmap":
        pivot = pd.crosstab(df["severity"], df["status"])
        fig = px.imshow(pivot, text_auto=True, color_continuous_scale="Blues",
                        title="Severity vs Status Heatmap")
        st.plotly_chart(fig, use_container_width=True)

    # ---- SUMMARY ----
    st.subheader("📌 Vulnerability Summary")
    summary = df["severity"].value_counts().to_dict()
    for sev, count in summary.items():
        st.write(f"{sev}: {count}")

    # ---- PATCH SIMULATION ----
    st.subheader("🛠 Simulate Patch")
    vuln_indices = df[df["status"] == "Vulnerable"].index.tolist()
    if vuln_indices:
        selected = st.multiselect("Select rows to patch", vuln_indices)
        if st.button("Apply Patch"):
            df = apply_patch(df, selected)
            st.success(f"✅ Patched {len(selected)} row(s)")
            st.dataframe(df, use_container_width=True)
else:
    st.info("📥 Please upload a CSV file to continue.")
