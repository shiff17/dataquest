import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.cluster import KMeans
import numpy as np

# -------------------- NAVIGATION --------------------
st.sidebar.title("🛡 Proactive Patch Automation")
page = st.sidebar.radio(
    "Navigate",
    ["Homepage", "Analytics", "Visualization"]
)

# -------------------- HOMEPAGE --------------------
if page == "Homepage":
    st.title("🛡 Proactive Self-Healing Patch Dashboard")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)

        st.subheader("📌 Raw Data (Before Cleaning)")
        st.dataframe(df, use_container_width=True)

        # Save before data snapshot
        before_snapshot = df.copy()

        # Clean null values
        df = df.dropna()

        # Clustering example (assume severity numeric mapping)
        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)

            # Simple clustering
            km = KMeans(n_clusters=2, random_state=42, n_init=10)
            df["cluster"] = km.fit_predict(df[["severity_num"]])

        # Simulate patching — mark vulnerable as safe
        if "status" in df.columns:
            df["status"] = df["status"].replace("Vulnerable", "Safe")

        st.subheader("✨ Processed Data (After Cleaning & Self-Healing)")
        st.dataframe(df, use_container_width=True)

        # Compare before vs after
        st.subheader("🔍 Before vs After")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Before**")
            st.dataframe(before_snapshot, use_container_width=True)
        with col2:
            st.write("**After**")
            st.dataframe(df, use_container_width=True)

# -------------------- ANALYTICS --------------------
elif page == "Analytics":
    st.title("📊 Dataset Analytics & Recommendations")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded).dropna()

        st.subheader("Summary Statistics")
        st.write(df.describe(include="all"))

        if "severity" in df.columns:
            counts = df["severity"].value_counts()
            st.write("### Vulnerability Severity Distribution")
            st.bar_chart(counts)

        if "status" in df.columns:
            vuln_rate = (df["status"] == "Vulnerable").mean() * 100
            st.write(f"⚠️ Vulnerable Systems: {vuln_rate:.2f}%")

        st.subheader("Recommendations")
        if "severity" in df.columns and "status" in df.columns:
            if vuln_rate > 20:
                st.error("High vulnerability detected! Immediate patching recommended.")
            else:
                st.success("System health looks stable. Continue monitoring weekly.")
        else:
            st.info("Upload CSV with 'severity' and 'status' columns for full analytics.")

# -------------------- VISUALIZATION --------------------
elif page == "Visualization":
    st.title("📈 Before & After Visualization")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded).dropna()
        before_df = df.copy()

        # Map severity to numbers
        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)

        # After patch: mark all safe
        if "status" in df.columns:
            df["status"] = df["status"].replace("Vulnerable", "Safe")

        vis_type = st.selectbox(
            "Choose visualization",
            ["Bar Chart", "Scatter Plot", "Pie Chart"]
        )

        if vis_type == "Bar Chart" and "severity" in before_df.columns:
            before_counts = before_df["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]

            fig_before = px.bar(before_counts, x="Severity", y="Count", title="Before Patching")
            fig_after = px.bar(after_counts, x="Severity", y="Count", title="After Patching")

            st.plotly_chart(fig_before, use_container_width=True)
            st.plotly_chart(fig_after, use_container_width=True)

        elif vis_type == "Scatter Plot" and "severity_num" in df.columns:
            fig = px.scatter(df, x=np.arange(len(df)), y="severity_num", color="status",
                             title="Scatter of Vulnerabilities Before/After")
            st.plotly_chart(fig, use_container_width=True)

        elif vis_type == "Pie Chart" and "status" in df.columns:
            before_status = before_df["status"].value_counts().reset_index()
            before_status.columns = ["Status", "Count"]
            after_status = df["status"].value_counts().reset_index()
            after_status.columns = ["Status", "Count"]

            fig1 = px.pie(before_status, values="Count", names="Status", title="Before Patching")
            fig2 = px.pie(after_status, values="Count", names="Status", title="After Patching")

            st.plotly_chart(fig1, use_container_width=True)
            st.plotly_chart(fig2, use_container_width=True)
