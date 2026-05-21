import streamlit as st
from risk_engine import analyze_vendors
from report_generator import generate_markdown_report

st.set_page_config(
    page_title="TrustShield GRC",
    page_icon="🛡️",
    layout="wide"
)

df = analyze_vendors()

st.sidebar.title("🛡️ TrustShield GRC")
st.sidebar.markdown("### Vendor Risk & Evidence Engine")
st.sidebar.markdown(
    """
    **Created by América Trujillo**  
    Cybersecurity GRC / AI Governance Portfolio  
    GitHub: `@ammetb18-create`
    """
)

st.sidebar.divider()

st.sidebar.markdown("### Project Purpose")
st.sidebar.write(
    "This tool simulates a real-world GRC workflow for vendor risk review, "
    "missing evidence detection, framework mapping, and audit readiness reporting."
)

st.sidebar.divider()

risk_filter = st.sidebar.multiselect(
    "Filter by Risk Level",
    options=df["Risk_Level"].unique().tolist(),
    default=df["Risk_Level"].unique().tolist()
)

filtered_df = df[df["Risk_Level"].isin(risk_filter)]

st.title("🛡️ TrustShield GRC")
st.subheader("Vendor Risk & Evidence Engine")

st.markdown(
    """
    A Python and Streamlit-based cybersecurity GRC tool that evaluates vendor cybersecurity risk,
    identifies missing compliance evidence, maps control gaps to security frameworks, and generates
    executive-style risk reports.
    """
)

st.caption(
    "Built by América Trujillo as part of a cybersecurity, GRC, risk, compliance, and AI governance portfolio."
)

st.divider()

total_vendors = len(filtered_df)
critical_vendors = len(filtered_df[filtered_df["Risk_Level"] == "Critical"])
high_vendors = len(filtered_df[filtered_df["Risk_Level"] == "High"])
missing_soc2 = filtered_df["Evidence_Gaps"].apply(lambda gaps: "Missing SOC 2" in gaps).sum()
missing_mfa = filtered_df["Evidence_Gaps"].apply(lambda gaps: "Missing MFA" in gaps).sum()

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Vendors Reviewed", total_vendors)
col2.metric("Critical Risk", critical_vendors)
col3.metric("High Risk", high_vendors)
col4.metric("Missing SOC 2", missing_soc2)
col5.metric("Missing MFA", missing_mfa)

st.divider()

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📊 Dashboard",
        "🔎 Vendor Detail",
        "🧾 Report Generator",
        "🧠 Methodology"
    ]
)

with tab1:
    st.header("Prioritized Vendor Risk Table")

    display_df = filtered_df.copy()
    display_df["Evidence_Gaps"] = display_df["Evidence_Gaps"].apply(lambda gaps: ", ".join(gaps))
    display_df["Framework_Mapping"] = display_df["Framework_Mapping"].apply(lambda items: ", ".join(items))
    display_df["Recommendations"] = display_df["Recommendations"].apply(lambda items: " | ".join(items))

    st.dataframe(
        display_df[
            [
                "Vendor",
                "System",
                "Data_Type",
                "Business_Criticality",
                "Risk_Score",
                "Risk_Level",
                "Recommended_Priority",
                "Evidence_Gaps",
                "Framework_Mapping"
            ]
        ],
        use_container_width=True
    )

    st.header("Risk Score Overview")
    chart_data = filtered_df[["Vendor", "Risk_Score"]].set_index("Vendor")
    st.bar_chart(chart_data)

with tab2:
    st.header("Vendor Detail Review")

    selected_vendor = st.selectbox("Select a vendor to review:", filtered_df["Vendor"].tolist())
    vendor_row = filtered_df[filtered_df["Vendor"] == selected_vendor].iloc[0]

    left, right = st.columns(2)

    with left:
        st.markdown("### Vendor Profile")
        st.write(f"**Vendor:** {vendor_row['Vendor']}")
        st.write(f"**System:** {vendor_row['System']}")
        st.write(f"**Data Type:** {vendor_row['Data_Type']}")
        st.write(f"**Business Criticality:** {vendor_row['Business_Criticality']}")
        st.write(f"**Risk Score:** {vendor_row['Risk_Score']}/100")
        st.write(f"**Risk Level:** {vendor_row['Risk_Level']}")
        st.write(f"**Recommended Priority:** {vendor_row['Recommended_Priority']}")

    with right:
        st.markdown("### Evidence Gaps")
        if vendor_row["Evidence_Gaps"]:
            for gap in vendor_row["Evidence_Gaps"]:
                st.warning(gap)
        else:
            st.success("No major evidence gaps identified.")

    st.markdown("### Framework Mapping")
    if vendor_row["Framework_Mapping"]:
        for mapping in vendor_row["Framework_Mapping"]:
            st.info(mapping)
    else:
        st.write("No major framework gaps mapped.")

    st.markdown("### Recommended Actions")
    if vendor_row["Recommendations"]:
        for recommendation in vendor_row["Recommendations"]:
            st.success(recommendation)
    else:
        st.write("Continue routine monitoring.")

with tab3:
    st.header("Executive Risk Report")

    st.write(
        "Generate a Markdown report summarizing vendor risk levels, evidence gaps, "
        "framework mapping, and recommended remediation priorities."
    )

    if st.button("Generate Executive Risk Report"):
        path = generate_markdown_report()
        st.success(f"Report generated successfully: {path}")

        with open(path, "r", encoding="utf-8") as report_file:
            st.download_button(
                label="Download Markdown Report",
                data=report_file.read(),
                file_name="vendor_risk_report.md",
                mime="text/markdown"
            )

with tab4:
    st.header("Methodology")

    st.markdown(
        """
        TrustShield GRC calculates vendor risk by evaluating business criticality, data sensitivity,
        missing security controls, stale risk reviews, and known vulnerability exposure.

        The tool simulates a practical GRC workflow where a cybersecurity risk analyst,
        compliance analyst, vendor risk analyst, or security control analyst reviews third-party vendors
        and determines which risks require priority remediation.
        """
    )

    st.markdown("### Risk Factors")

    st.markdown(
        """
        - **Business Criticality:** Higher-risk systems receive more weight.
        - **Data Sensitivity:** PII, financial data, confidential data, and customer inputs increase risk.
        - **Missing SOC 2 Evidence:** Indicates lack of third-party assurance documentation.
        - **Missing MFA:** Indicates weak identity and access control.
        - **Encryption Gaps:** Indicates potential weakness in data protection.
        - **Missing Incident Response Plan:** Indicates limited readiness for security incidents.
        - **Known Vulnerability Exposure:** Increases remediation priority.
        - **Stale Risk Review:** Indicates outdated vendor risk documentation.
        """
    )

    st.markdown("### Portfolio Relevance")

    st.markdown(
        """
        This project demonstrates the ability to combine cybersecurity governance, risk analysis,
        compliance documentation, control mapping, and Python-based automation.
        """
    )

st.divider()

st.caption(
    "TrustShield GRC — Created by América Trujillo | GitHub: @ammetb18-create | Cybersecurity GRC Portfolio"
)
