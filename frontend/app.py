import streamlit as st
import pandas as pd
import plotly.express as px

st.title("🛡 Proactive Security Patch Automation Dashboard")

# Allow both JSON and CSV uploads
uploaded = st.file_uploader("Upload scan results (JSON or CSV)", type=["json", "csv"])

if uploaded:
    # Detect file type
    if uploaded.name.endswith(".json"):
        df = pd.read_json(uploaded)
    elif uploaded.name.endswith(".csv"):
        df = pd.read_csv(uploaded)
    else:
        st.error("Unsupported file format")
        st.stop()

    st.subheader("Vulnerabilities")
    st.dataframe(df, use_container_width=True)

    # Severity counts
    if "severity" in df.columns:
        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.bar(counts, x="Severity", y="Count", color="Severity")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No 'severity' column found in file.")

    # Simulate patch
    if "status" in df.columns and "software" in df.columns:
        vuln = df[df["status"] == "Vulnerable"]["software"].tolist()
        if vuln:
            choice = st.selectbox("Select software to patch", vuln)
            if st.button("Apply Patch"):
                df.loc[df["software"] == choice, ["status", "severity", "cve_id"]] = ["Safe", "None", "None"]
                st.success(f"Patched {choice}")
                st.dataframe(df, use_container_width=True)
    else:
        st.warning("Missing required columns: 'status' and/or 'software'")
