
import streamlit as st
import pandas as pd
import plotly.express as px

# Load JSON
st.title("🛡 Proactive Security Patch Automation Dashboard")
uploaded = st.file_uploader("Upload scan_results.json from backend", type=["json"])

if uploaded:
    df = pd.read_json(uploaded)
    st.subheader("Vulnerabilities")
    st.dataframe(df, use_container_width=True)

    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["Severity", "Count"]
    fig = px.bar(counts, x="Severity", y="Count", color="Severity")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Simulate Patch")
    vuln = df[df["status"] == "Vulnerable"]["software"].tolist()
    if vuln:
        choice = st.selectbox("Select software to patch", vuln)
        if st.button("Apply Patch"):
            df.loc[df["software"] == choice, ["status","severity","cve_id"]] = ["Safe","None","None"]
            st.success(f"Patched {choice}")
            st.dataframe(df, use_container_width=True)
