#!/usr/bin/env python3
"""
Proactive Security Patch Automation Dashboard
- CSV only
- Requires 'software' and 'version' columns
- Auto-fills severity/status if missing
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import random
from datetime import datetime

# ---------------- CONFIG ----------------
SEVERITIES = ["Low", "Medium", "High", "Critical"]
random.seed(42)
np.random.seed(42)

st.set_page_config(page_title="🛡 Proactive Patch Automation", layout="wide")
st.title("🛡 Proactive Security Patch Dashboard")

# ---------------- HELPERS ----------------
def generate_random_vulns(df: pd.DataFrame) -> pd.DataFrame:
    """Fill in severity and status if missing"""
    if "severity" not in df.columns:
        df["severity"] = [random.choice(SEVERITIES) for _ in range(len(df))]
    if "status" not in df.columns:
        df["status"] = ["Vulnerable" if random.random() > 0.3 else "Safe" for _ in range(len(df))]
    df["scan_date"] = datetime.utcnow().isoformat()
    return df

def apply_patch(df: pd.DataFrame, selected: list) -> pd.DataFrame:
    """Mark selected software as patched"""
    df.loc[df["software"].isin(selected), ["status", "severity"]] = ["Safe", "None"]
    return df

def security_score(df: pd.DataFrame) -> int:
    """Calculate a simple security score out of 100"""
    total = len(df)
    if total == 0:
        return 100
    vuln = len(df[df["status"] == "Vulnerable"])
    score = max(0, 100 - int((vuln / total) * 100))
    return score

# ---------------- STREAMLIT APP ----------------
uploaded = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded:
    df = pd.read_csv(uploaded)

    # Normalize column names to lowercase
df.columns = [c.strip().lower() for c in df.columns]

# Auto-map synonyms
rename_map = {}
if "app" in df.columns: 
    rename_map["app"] = "software"
if "program" in df.columns:
    rename_map["program"] = "software"
if "ver" in df.columns:
    rename_map["ver"] = "version"
if "release" in df.columns:
    rename_map["release"] = "version"

df.rename(columns=rename_map, inplace=True)


    # ✅ Show columns for debugging
    st.write("📂 Columns detected:", list(df.columns))

    # ✅ Ensure required columns
    required = {"software", "version"}
    if not required.issubset(df.columns):
        st.error(f"❌ CSV must contain at least these columns: {required}")
        st.stop()

    # Add ID if missing
    if "id" not in df.columns:
        df.insert(0, "id", range(1, len(df) + 1))

    # Fill missing fields
    df = generate_random_vulns(df)

    # Show data
    st.subheader("📊 Uploaded Data")
    st.dataframe(df, use_container_width=True)

    # Show security score
    score = security_score(df)
    st.metric("🔐 Security Score", f"{score}/100")

    # Severity chart
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["Severity", "Count"]
    fig = px.bar(counts, x="Severity", y="Count", color="Severity",
                 title="Vulnerabilities by Severity")
    st.plotly_chart(fig, use_container_width=True)

    # Patch simulation
    st.subheader("🩹 Simulate Patch")
    vuln_rows = df[df["status"] == "Vulnerable"]
    if not vuln_rows.empty:
        selected = st.multiselect("Select software to patch", vuln_rows["software"].tolist())
        if st.button("Apply Patch"):
            df = apply_patch(df, selected)
            st.success(f"✅ Patched {len(selected)} item(s)")
            st.dataframe(df, use_container_width=True)

            # Recalculate score
            score = security_score(df)
            st.metric("🔐 Updated Security Score", f"{score}/100")

            # ✅ Download patched results
            st.download_button(
                "📥 Download Patched CSV",
                df.to_csv(index=False),
                file_name="patched_results.csv",
                mime="text/csv"
            )
    else:
        st.info("🎉 All software is already safe!")

else:
    st.info("Please upload a CSV file to continue.")
