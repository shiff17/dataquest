import io, time, random
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# ------------------- CONFIG -------------------
SEVERITY_WEIGHT = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10, "None": 0}
SEVERITY_COLOR = {
    "Low": "#a7f3d0",
    "Medium": "#fde68a",
    "High": "#fca5a5",
    "Critical": "#f87171",
    "None": "#d1d5db"
}
PATCH_HINTS = {
    "Apache HTTPD": "Update to >= 2.4.51",
    "OpenSSL": "Update to latest 1.1.1+ LTS or 3.x",
    "NGINX": "Update to >= 1.25.x",
}

np.random.seed(42)
random.seed(42)

# ------------------- HELPERS -------------------
def severity_bucket(score):
    if score is None:
        return "Medium"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"

def compute_risk(df):
    return float(df["severity"].map(SEVERITY_WEIGHT).fillna(0).sum())

def security_score(df, init_risk):
    if init_risk == 0:
        return 100
    remaining = compute_risk(df)
    return max(0, 100 - int((remaining / init_risk) * 100))

def style_severity(val):
    color = SEVERITY_COLOR.get(str(val), "#e5e7eb")
    return f"background-color:{color}; color:#111827; font-weight:600;"

def apply_patch(df, sw):
    idx = df[(df["software"] == sw) & (df["status"] == "Vulnerable")].index
    if len(idx) == 0:
        return df, False
    i = idx[0]
    df.loc[i, "status"] = "Safe"
    df.loc[i, "severity"] = "None"
    df.loc[i, "cve_id"] = "None"
    df.loc[i, "cvss"] = None
    reco = df.loc[i, "patch_recommendation"]
    df.loc[i, "applied_patch_version"] = (
        reco.split(">=")[-1].strip() if ">=" in str(reco) else "latest"
    )
    return df, True

def clean_nulls(df):
    return df.fillna({"cvss": 0, "applied_patch_version": "None", "cve_id": "None"})

def kmeans_cluster(df, k=3):
    z = df.copy()
    z["sev_w"] = z["severity"].map(SEVERITY_WEIGHT).fillna(0)
    z["cvss_f"] = z["cvss"].fillna(0)
    z["is_vuln"] = (z["status"] == "Vulnerable").astype(int)
    X = StandardScaler().fit_transform(z[["sev_w", "cvss_f", "is_vuln"]])
    km = KMeans(n_clusters=k, n_init=10, random_state=7)
    labs = km.fit_predict(X)
    z["cluster"] = labs
    low_c = int(z.groupby("cluster")["sev_w"].mean().idxmin())
    return z, low_c

# ------------------- STREAMLIT APP -------------------
st.set_page_config(page_title="Proactive Patch Automation", layout="wide", page_icon="🛡")

st.sidebar.title("🛡 Navigation")
page = st.sidebar.radio("Slides", [
    "Slide 1 — Self-Healing Upload",
    "Slide 2 — Clean • Cluster • Status",
    "Slide 3 — RL Assist",
    "Slide 4 — Before/After Visuals",
])

# ---- Load CSV ----
with st.expander("📥 Upload Inventory (CSV only)", expanded=True):
    uploaded = st.file_uploader("Upload installed software CSV", type=["csv"])
    if uploaded:
        df = pd.read_csv(uploaded)
        # enforce schema
        if not {"software", "version"}.issubset(df.columns):
            st.error("CSV must contain at least 'software' and 'version' columns.")
            st.stop()

        # simulate vulnerability enrichment
        df["cve_id"] = df["software"].apply(lambda s: "CVE-XXXX" if "Apache" in s else "None")
        df["cvss"] = df["software"].apply(lambda s: 7.5 if "Apache" in s else None)
        df["severity"] = df["cvss"].apply(lambda x: severity_bucket(x) if x else "None")
        df["patch_recommendation"] = df["software"].map(PATCH_HINTS).fillna("Update to latest")
        df["status"] = df["cve_id"].apply(lambda x: "Vulnerable" if x != "None" else "Safe")
        df["applied_patch_version"] = None
        df["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if "df" not in st.session_state:
            st.session_state.df_twin = df.copy()
            st.session_state.df = df.copy()
            st.session_state.init_risk = compute_risk(df)
    else:
        st.warning("Please upload a CSV file to continue.")
        st.stop()

# ---- Slide 1 ----
if page.startswith("Slide 1"):
    st.title("Slide 1 — Self-Healing Patch (Digital Twin)")
    left, right = st.columns(2)

    with left:
        st.subheader("Before")
        st.dataframe(st.session_state.df_twin.style.applymap(style_severity, subset=["severity"]))

    with right:
        st.subheader("After (Auto-Heal)")
        auto = st.selectbox("Threshold", ["Off", "High & Critical", "Critical only"])
        run = st.button("Run Auto-Heal")
        df_after = st.session_state.df.copy()

        if run and auto != "Off":
            need = {"High & Critical": {"High", "Critical"}, "Critical only": {"Critical"}}[auto]
            for sw in df_after[df_after["severity"].isin(need)]["software"]:
                df_after, _ = apply_patch(df_after, sw)
            st.session_state.df = df_after
            st.success("Auto-heal applied")

        st.dataframe(st.session_state.df.style.applymap(style_severity, subset=["severity"]))

    st.metric("Initial Risk", f"{compute_risk(st.session_state.df_twin):.0f}")
    st.metric("Current Risk", f"{compute_risk(st.session_state.df):.0f}")
    st.metric("Security Score", f"{security_score(st.session_state.df, st.session_state.init_risk)}/100")

# ---- Slide 2 ----
elif page.startswith("Slide 2"):
    st.title("Slide 2 — Clean Nulls & Cluster")
    df_clean = clean_nulls(st.session_state.df)
    st.subheader("Cleaned Data")
    st.dataframe(df_clean.style.applymap(style_severity, subset=["severity"]))

    k = st.slider("Clusters (k)", 2, 6, 3)
    clustered, low_c = kmeans_cluster(df_clean, k)
    fig = px.scatter(
        clustered, x="cvss", y="sev_w", color="cluster",
        hover_data=["software", "version", "severity"]
    )
    st.plotly_chart(fig, use_container_width=True)
    st.info(f"Low vulnerability cluster = {low_c}")

# ---- Slide 3 ----
elif page.startswith("Slide 3"):
    st.title("Slide 3 — RL Assist")
    df_v = st.session_state.df.copy()
    df_v["sev_w"] = df_v["severity"].map(SEVERITY_WEIGHT).fillna(0)
    vul = df_v[df_v["status"] == "Vulnerable"].copy()

    if vul.empty:
        st.success("🎉 No vulnerabilities to learn from.")
    else:
        vul["exposure"] = np.random.uniform(0.5, 1.5, len(vul))
        vul["risk"] = vul["sev_w"] * vul["exposure"]
        arms = vul.index.tolist()
        q, n = {i: 0 for i in arms}, {i: 0 for i in arms}
        rewards = []

        eps = st.slider("Episodes", 50, 500, 200)
        eps_greedy = st.slider("Exploration (ε)", 0.0, 0.5, 0.1, 0.05)

        if st.button("Train RL"):
            for ep in range(eps):
                a = random.choice(arms) if random.random() < eps_greedy else max(arms, key=lambda x: q[x])
                r = vul.loc[a, "risk"]
                n[a] += 1
                q[a] += (r - q[a]) / n[a]
                rewards.append(r)

            order = sorted(arms, key=lambda x: q[x], reverse=True)
            table = pd.DataFrame([{
                "priority": i + 1,
                "software": vul.loc[idx, "software"],
                "severity": vul.loc[idx, "severity"],
                "learned_val": round(q[idx], 2),
                "risk": round(vul.loc[idx, "risk"], 2)
            } for i, idx in enumerate(order)])
            st.dataframe(table)

            fig = px.line(pd.Series(rewards).rolling(10).mean(), title="Avg Reward")
            st.plotly_chart(fig)

# ---- Slide 4 ----
elif page.startswith("Slide 4"):
    st.title("Slide 4 — Before vs After Visuals")
    col1, col2 = st.columns(2)

    col1.subheader("Before")
    col1.dataframe(st.session_state.df_twin.style.applymap(style_severity, subset=["severity"]))

    col2.subheader("After")
    col2.dataframe(st.session_state.df.style.applymap(style_severity, subset=["severity"]))

    vis = st.selectbox("Visualization", ["Bar", "Pie", "Scatter"])

    if vis == "Bar":
        counts = st.session_state.df["severity"].value_counts().reset_index()
        counts.columns = ["severity", "count"]
        fig = px.bar(counts, x="severity", y="count", color="severity")
    elif vis == "Pie":
        vals = st.session_state.df["status"].value_counts().reset_index()
        vals.columns = ["status", "count"]
        fig = px.pie(vals, values="count", names="status")
    else:
        df2 = st.session_state.df.copy()
        df2["sev_w"] = df2["severity"].map(SEVERITY_WEIGHT).fillna(0)
        fig = px.scatter(df2, x="cvss", y="sev_w", color="status", trendline="ols")

    st.plotly_chart(fig, use_container_width=True)
