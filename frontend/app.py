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
            st.info(f"✅ Data cleaned successfully. Approx. {improvement:.2f}% data retained → improved accuracy of analysis.")

            # Data volume graph
            acc_df = pd.DataFrame({
                "Stage": ["Before", "After"],
                "Rows": [before_len, after_len]
            })
            fig_acc = px.bar(acc_df, x="Stage", y="Rows", text="Rows",
                             title="📊 Data Volume Before vs After Cleaning",
                             color="Stage")
            st.plotly_chart(fig_acc, use_container_width=True)

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

        # -------------------- HOMEPAGE COMPARISON --------------------
        st.subheader("🔍 Before vs After (Graphical Comparison)")
        if "severity" in before_snapshot.columns:
            before_counts = before_snapshot["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]

            col1, col2 = st.columns(2)
            with col1:
                fig_before = px.bar(before_counts, x="Severity", y="Count", text="Count",
                                    color="Severity", title="Before Cleaning & Patching",
                                    color_discrete_sequence=["#e63946", "#f77f00", "#ffba08", "#d62828"])
                st.plotly_chart(fig_before, use_container_width=True)

            with col2:
                fig_after = px.bar(after_counts, x="Severity", y="Count", text="Count",
                                   color="Severity", title="After Cleaning & Patching",
                                   color_discrete_sequence=["#2a9d8f", "#43aa8b", "#90be6d", "#577590"])
                st.plotly_chart(fig_after, use_container_width=True)

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

        st.info(
            f"""
            ℹ Dataset Overview  
            - Original rows: {before_len} | After cleaning: {after_len}  
            - Cleaning criteria: removed null values in key columns (e.g., severity, status).  
            - Factors considered: severity levels, vulnerability status, clustering on severity.  
            - Goal: Provide a cleaned dataset suitable for patch simulation and analysis.  
            """
        )

        # Severity bar chart
        if "severity" in df.columns:
            counts = df["severity"].value_counts().reset_index()
            counts.columns = ["Severity", "Count"]
            fig = px.bar(counts, x="Severity", y="Count", text="Count",
                         title="Vulnerability Severity Distribution")
            st.plotly_chart(fig, use_container_width=True)

        vuln_rate = None
        if "status" in df.columns:
            vuln_rate = (df["status"] == "Vulnerable").mean() * 100
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["Status", "Count"]
            fig2 = px.pie(status_counts, values="Count", names="Status",
                          title="Vulnerability Status Distribution")
            st.plotly_chart(fig2, use_container_width=True)
            st.write(f"⚠ Vulnerable Systems: {vuln_rate:.2f}%")

        # Recommendations
        st.subheader("Recommendations")
        recs = []
        if vuln_rate is not None:
            if vuln_rate > 30:
                recs.append("⚠ Immediate patching required: High percentage of vulnerable systems.")
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

        # Pie chart for cleaned data
        if "severity" in df.columns:
            st.write("### Vulnerability Severity Distribution (Cleaned Data)")
            fig = px.pie(df, names="severity", title="Severity Breakdown",
                         color="severity", color_discrete_map={
                             "Critical": "#e63946",
                             "High": "#f77f00",
                             "Medium": "#ffba08",
                             "Low": "#43aa8b"
                         })
            st.plotly_chart(fig, use_container_width=True)

# -------------------- VISUALIZATION --------------------
elif page == "Visualization":
    st.title("📈 Before & After Visualization")
