# -------------------- VISUALIZATION --------------------
elif page == "Visualization":
    st.title("📈 Before & After Visualization")
    uploaded = st.file_uploader("Upload your vulnerability scan (CSV)", type=["csv"])

    if uploaded:
        df = pd.read_csv(uploaded)
        before_df = df.copy()
        df = df.dropna()

        if "severity" in df.columns:
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            df["severity_num"] = df["severity"].map(sev_map).fillna(0)

        if "status" in df.columns:
            df["status"] = df["status"].replace("Vulnerable", "Safe")

        vis_type = st.selectbox(
            "Choose visualization",
            ["Severity (Bar)", "Severity (Line)", "Vulnerability Status (Pie)",
             "Scatter Severity", "Heatmap", "Histogram", "Box Plot", "All"]
        )

        # --- Bar Chart ---
        if vis_type in ["Severity (Bar)", "All"] and "severity" in before_df.columns:
            before_counts = before_df["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]
            before_counts["Type"] = "Before"

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]
            after_counts["Type"] = "After"

            combined = pd.concat([before_counts, after_counts])
            fig = px.bar(combined, x="Severity", y="Count", color="Type", barmode="group",
                         title="Before vs After - Severity Levels")
            st.plotly_chart(fig, use_container_width=True)

        # --- Line Chart ---
        if vis_type in ["Severity (Line)", "All"] and "severity" in before_df.columns:
            before_counts = before_df["severity"].value_counts().reset_index()
            before_counts.columns = ["Severity", "Count"]
            before_counts["Type"] = "Before"

            after_counts = df["severity"].value_counts().reset_index()
            after_counts.columns = ["Severity", "Count"]
            after_counts["Type"] = "After"

            combined = pd.concat([before_counts, after_counts])
            fig = px.line(combined, x="Severity", y="Count", color="Type", markers=True,
                          title="Before vs After - Severity Trend")
            st.plotly_chart(fig, use_container_width=True)

        # --- Pie Chart ---
        if vis_type in ["Vulnerability Status (Pie)", "All"] and "status" in before_df.columns:
            before_status = before_df["status"].value_counts().reset_index()
            before_status.columns = ["Status", "Count"]
            after_status = df["status"].value_counts().reset_index()
            after_status.columns = ["Status", "Count"]

            fig1 = px.pie(before_status, values="Count", names="Status", title="Before Patching")
            fig2 = px.pie(after_status, values="Count", names="Status", title="After Patching")

            col1, col2 = st.columns(2)
            with col1: st.plotly_chart(fig1, use_container_width=True)
            with col2: st.plotly_chart(fig2, use_container_width=True)

        # --- Scatter Plot ---
        if vis_type in ["Scatter Severity", "All"] and "severity_num" in df.columns:
            fig = px.scatter(df, x=np.arange(len(df)), y="severity_num", color="status",
                             title="Scatter of Vulnerabilities After Cleaning",
                             labels={"severity_num": "Severity Level"})
            st.plotly_chart(fig, use_container_width=True)

        # --- Heatmap ---
        if vis_type in ["Heatmap", "All"] and "severity_num" in df.columns:
            corr = df[["severity_num"]].corr()
            fig = px.imshow(corr, text_auto=True, title="Correlation Heatmap (Severity)")
            st.plotly_chart(fig, use_container_width=True)

        # --- Histogram ---
        if vis_type in ["Histogram", "All"] and "severity" in df.columns:
            fig = px.histogram(df, x="severity", color="status", barmode="group",
                               title="Severity Distribution Histogram")
            st.plotly_chart(fig, use_container_width=True)

        # --- Box Plot ---
        if vis_type in ["Box Plot", "All"] and "severity_num" in df.columns:
            fig = px.box(df, y="severity_num", color="status",
                         title="Severity Level Spread (Box Plot)",
                         labels={"severity_num": "Severity Level"})
            st.plotly_chart(fig, use_container_width=True)
