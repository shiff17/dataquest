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

# ---------------- NAVBAR & THEME ----------------
st.markdown(
    """
    <style>
    /* Navbar */
    .top-bar {
        background-color: #2563eb; /* blue */
        color: white;
        padding: 10px 20px;
        font-size: 20px;
        font-weight: 600;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-radius: 8px;
        margin-bottom: 15px;
    }
    .dark-mode .top-bar {
        background-color: #1e3a8a; /* darker blue */
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Toggle for dark/light
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = False

col1, col2 = st.columns([10, 1])
with col1:
    st.markdown('<div class="top-bar">🛡 Proactive Security Patch Automation Dashboard</div>', unsafe_allow_html=True)
with col2:
    if st.button("🌙" if not st.session_state.dark_mode else "☀"):
        st.session_state.dark_mode = not st.session_state.dark_mode
        mode = "dark-mode" if st.session_state.dark_mode else ""
        st.markdown(f"<body class='{mode}'>", unsafe_allow_html=True)

# ---------------- STREAMLIT APP ----------------
uploaded = st.file_uploader("Upload any CSV file", type=["csv"])

if uploaded:
    df = pd.read_csv(uploaded)

    # Ensure unique identifier column exists
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
    st.subheader("Detected Vulnerabilities")
    st.dataframe(df, use_container_width=True)

    # ---- CHART ----
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["Severity", "Count"]
    fig = px.bar(counts, x="Severity", y="Count", color="Severity")
    st.plotly_chart(fig, use_container_width=True)

    # ---- SUMMARY ----
    st.subheader("Vulnerability Summary")
    for _, row in counts.iterrows():
        st.write(f"{row['Severity']}: {row['Count']}")

    # ---- PATCH SIMULATION ----
    st.subheader("Simulate Patch")
    vuln_indices = df[df["status"] == "Vulnerable"].index.tolist()
    if vuln_indices:
        selected = st.multiselect("Select rows to patch", vuln_indices)
        if st.button("Apply Patch"):
            df = apply_patch(df, selected)
            st.success(f"Patched {len(selected)} row(s)")
            st.dataframe(df, use_container_width=True)
else:
    st.info("Please upload a CSV file to continue.")
