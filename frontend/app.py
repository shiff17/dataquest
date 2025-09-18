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

        # Save before snapshot
        before_snapshot = df.copy()
        before_len = len(df)

        # Cleaning: drop null values
        df = df.dropna()
        after_len = len(df)

        # Accuracy improvement % = retained rows vs original
        if before_len > 0:
            improvement = (after_len / before_len) * 100
            st.info(f"✅ Data cleaned successfully. Approx. **{improvement:.2f}%** data retained → improved accuracy of analysis.")

        # Clustering example (assume severity numeric mapping)
        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)

            km = KMeans(n_clusters=2, random_state=42, n_init=10)
            df["cluster"] = km.fit_predict(df[["severity_num"]])

        # Simulate patching
        if "status" in df.columns:
            df["status"] = df["status"].replace("Vulnerable", "Safe")

        st.subheader("✨ Processed Data (After Cleaning & Self-Healing)")
        st.dataframe(df, use_container_width=True)

        # Download button
        st.download_button(
            label="📥 Download Processed Data",
            data=df.to_csv(index=False),
            file_name="processed_results.csv",
            mime="text/csv"
        )

        # Before vs After Comparison
        st.subheader("🔍 Before vs After (Graphical Comparison)")
        if "severity" in before_snapshot.columns:
            before_counts = before_snapshot["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]
            before_counts["Type"] = "Before"

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]
            after_counts["Type"] = "After"

            combined = pd.concat([before_counts, after_counts])

            fig = px.line(combined, x="Severity", y="Count", color="Type", markers=True,
                          title="Before vs After - Severity Distribution")
            st.plotly_chart(fig, use_container_width=True)

# -------------------- ANALYTICS --------------------
elif page == "Analytics":
    st.title("📊 Dataset Analytics & Recommendations")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        before_len = len(df)
        df = df.dropna()
        after_len = len(df)

        st.subheader("Summary Statistics")
        st.write(df.describe(include="all"))

        # Explanation of dataset & cleaning
        st.info(
            f"""
            ℹ️ **Dataset Overview**  
            - Original rows: {before_len} | After cleaning: {after_len}  
            - Cleaning criteria: removed null values in key columns (e.g., severity, status).  
            - Factors considered: *severity levels, vulnerability status, clustering on severity*.  
            - Goal: Provide a cleaned dataset suitable for patch simulation and analysis.  
            """
        )

        if "severity" in df.columns:
            counts = df["severity"].value_counts()
            st.write("### Vulnerability Severity Distribution")
            st.bar_chart(counts)

        vuln_rate = None
        if "status" in df.columns:
            vuln_rate = (df["status"] == "Vulnerable").mean() * 100
            st.write(f"⚠️ Vulnerable Systems: {vuln_rate:.2f}%")

        # Recommendations
        st.subheader("Recommendations")
        recs = []
        if vuln_rate is not None:
            if vuln_rate > 30:
                recs.append("⚠️ Immediate patching required: High percentage of vulnerable systems.")
            elif vuln_rate > 10:
                recs.append("🔄 Regular patch cycles should be enforced bi-weekly.")
            else:
                recs.append("✅ Vulnerability levels are low. Maintain current monitoring schedule.")

        if "severity" in df.columns:
            if "Critical" in df["severity"].values:
                recs.append("🔥 Prioritize patching of Critical vulnerabilities first.")
            if "High" in df["severity"].values:
                recs.append("🚨 Ensure High severity issues are patched within 72 hours.")

        recs.append("📊 Establish continuous monitoring to detect new threats early.")

        for r in recs[:5]:
            st.write("-", r)

# -------------------- VISUALIZATION --------------------
elif page == "Visualization":
    st.title("📈 Before & After Visualization")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded).dropna()
        before_df = df.copy()

        # Severity mapping
        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)

        # After patch
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

            fig_before = px.bar(before_counts, x="Severity", y="Count", title="Before Patching",
                                text="Count")
            fig_after = px.bar(after_counts, x="Severity", y="Count", title="After Patching",
                               text="Count")

            st.plotly_chart(fig_before, use_container_width=True)
            st.plotly_chart(fig_after, use_container_width=True)

        elif vis_type == "Scatter Plot" and "severity_num" in df.columns:
            fig = px.scatter(df, x=np.arange(len(df)), y="severity_num", color="status",
                             title="Scatter of Vulnerabilities Before/After",
                             labels={"severity_num": "Severity Level"})
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

            # Show major values explicitly
            st.write("📊 **Before Patching:**", before_status.to_dict("records"))
            st.write("📊 **After Patching:**", after_status.to_dict("records"))
