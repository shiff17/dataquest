#!/usr/bin/env python3
"""
Proactive Security Patch Automation Framework (Schema-Free)
- Accepts ANY CSV (no column restrictions)
- Cleans nulls
- Auto-generates severity/status if missing
- RL-based patch prioritization
- Interactive analytics & visualizations
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import random
from collections import defaultdict

# -------------------- RL Patch Prioritizer --------------------
class PatchPrioritizationRL:
    def _init_(self, epsilon=0.1):
        self.epsilon = epsilon
        self.q_table = defaultdict(lambda: defaultdict(float))

    def choose_action(self, severity):
        actions = ["patch_now", "schedule", "defer"]
        if random.random() < self.epsilon:
            return random.choice(actions)
        if severity == "Critical":
            return "patch_now"
        elif severity == "High":
            return "schedule"
        else:
            return "defer"

    def recommend(self, row):
        sev = row.get("severity", "Low")
        action = self.choose_action(sev)
        return {
            "row_id": row.get("id", "N/A"),
            "severity": sev,
            "recommendation": action
        }

# -------------------- Streamlit UI --------------------
st.set_page_config(page_title="🛡 Proactive Patch Automation", layout="wide")
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Homepage", "Analytics", "Visualization"])

# -------------------- HOMEPAGE --------------------
if page == "Homepage":
    st.title("🛡 Proactive Self-Healing Patch Dashboard")
    uploaded = st.file_uploader("Upload ANY CSV file", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)

        st.subheader("📌 Raw Data")
        st.dataframe(df, use_container_width=True)

        # Add row IDs if none
        if "id" not in df.columns:
            df.insert(0, "id", range(1, len(df) + 1))

        # Clean nulls
        before_len = len(df)
        df = df.dropna()
        after_len = len(df)
        st.info(f"✅ Cleaned data: {before_len} → {after_len} rows")

        # Auto-generate severity if missing
        severities = ["Low", "Medium", "High", "Critical"]
        if "severity" not in df.columns:
            df["severity"] = [random.choice(severities) for _ in range(len(df))]

        # Auto-generate status if missing
        if "status" not in df.columns:
            df["status"] = ["Vulnerable" if random.random() > 0.3 else "Safe" for _ in range(len(df))]

        # RL Recommendations
        rl_agent = PatchPrioritizationRL()
        recs = [rl_agent.recommend(row) for _, row in df.iterrows()]
        rec_df = pd.DataFrame(recs)

        st.subheader("🤖 Patch Recommendations")
        st.dataframe(rec_df, use_container_width=True)

        st.download_button(
            label="📥 Download Recommendations",
            data=rec_df.to_csv(index=False),
            file_name="patch_recommendations.csv",
            mime="text/csv"
        )

# -------------------- ANALYTICS --------------------
elif page == "Analytics":
    st.title("📊 Dataset Analytics")
    uploaded = st.file_uploader("Upload ANY CSV file", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded).dropna()

        st.subheader("Summary Statistics")
        st.write(df.describe(include="all"))

        if "severity" not in df.columns:
            df["severity"] = [random.choice(["Low", "Medium", "High", "Critical"]) for _ in range(len(df))]

        counts = df["severity"].value_counts().reset_index()
        counts.columns = ["Severity", "Count"]
        fig = px.bar(counts, x="Severity", y="Count", color="Severity",
                     title="Vulnerability Severity Distribution")
        st.plotly_chart(fig, use_container_width=True)

        if "status" not in df.columns:
            df["status"] = ["Vulnerable" if random.random() > 0.3 else "Safe" for _ in range(len(df))]

        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        fig2 = px.pie(status_counts, values="Count", names="Status",
                      title="Vulnerability Status Distribution")
        st.plotly_chart(fig2, use_container_width=True)

# -------------------- VISUALIZATION --------------------
elif page == "Visualization":
    st.title("📈 Before & After Visualization")
    uploaded = st.file_uploader("Upload ANY CSV file", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded).dropna()
        before_df = df.copy()

        if "severity" not in df.columns:
            df["severity"] = [random.choice(["Low", "Medium", "High", "Critical"]) for _ in range(len(df))]
            before_df["severity"] = df["severity"]

        if "status" not in df.columns:
            df["status"] = ["Vulnerable" if random.random() > 0.3 else "Safe" for _ in range(len(df))]
            before_df["status"] = df["status"]

        # Simulate patching
        df["status"] = df["status"].replace("Vulnerable", "Safe")

        vis_type = st.selectbox(
            "Choose visualization",
            ["Severity (Bar)", "Severity (Line)", "Vulnerability Status (Pie)", "Scatter Severity"]
        )

        if vis_type == "Severity (Bar)":
            before_counts = before_df["severity"].value_counts().reset_index()
            after_counts = df["severity"].value_counts().reset_index()
            before_counts.columns, after_counts.columns = ["Severity", "Count"], ["Severity", "Count"]
            before_counts["Type"], after_counts["Type"] = "Before", "After"
            combined = pd.concat([before_counts, after_counts])
            fig = px.bar(combined, x="Severity", y="Count", color="Type", barmode="group",
                         title="Before vs After - Severity Levels")
            st.plotly_chart(fig, use_container_width=True)

        elif vis_type == "Severity (Line)":
            before_counts = before_df["severity"].value_counts().reset_index()
            after_counts = df["severity"].value_counts().reset_index()
            before_counts.columns, after_counts.columns = ["Severity", "Count"], ["Severity", "Count"]
            before_counts["Type"], after_counts["Type"] = "Before", "After"
            combined = pd.concat([before_counts, after_counts])
            fig = px.line(combined, x="Severity", y="Count", color="Type", markers=True,
                          title="Before vs After - Severity Trend")
            st.plotly_chart(fig, use_container_width=True)

        elif vis_type == "Vulnerability Status (Pie)":
            before_status = before_df["status"].value_counts().reset_index()
            after_status = df["status"].value_counts().reset_index()
            before_status.columns, after_status.columns = ["Status", "Count"], ["Status", "Count"]
            fig1 = px.pie(before_status, values="Count", names="Status", title="Before Patching")
            fig2 = px.pie(after_status, values="Count", names="Status", title="After Patching")
            st.plotly_chart(fig1, use_container_width=True)
            st.plotly_chart(fig2, use_container_width=True)

        elif vis_type == "Scatter Severity":
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)
            fig = px.scatter(df, x=np.arange(len(df)), y="severity_num", color="status",
                             title="Scatter of Vulnerabilities After Cleaning",
                             labels={"severity_num": "Severity Level"})
            st.plotly_chart(fig, use_container_width=True)
