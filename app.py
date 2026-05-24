import pandas as pd
import streamlit as st
from datetime import date, timedelta
from risk_engine import (
    analyze_vendors,
    identify_gaps,
    score_vendor,
    classify_risk,
    prioritize_action,
)
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

def load_control_catalog():
    try:
        controls = pd.read_csv("data/control_catalog.csv")
        return controls.set_index("Gap").to_dict("index")
    except Exception:
        return {}

def map_frameworks_and_recommendations(gaps):
    gap_mapping = load_control_catalog()
    mappings = []
    recommendations = []

    for gap in gaps:
        if gap in gap_mapping:
            mappings.append(f"{gap_mapping[gap]['Framework']} - {gap_mapping[gap]['Control']}")
            recommendations.append(gap_mapping[gap]["Recommendation"])

    return mappings, recommendations

def risk_badge(level):
    if level == "Critical":
        return "🔴 Critical"
    if level == "High":
        return "🟠 High"
    if level == "Medium":
        return "🟡 Medium"
    return f"🟢 {level}"


def calculate_score_breakdown(row, gaps):
    """Return an explainable scoring breakdown aligned with the risk_engine logic."""
    criticality_points = {
        "High": 30,
        "Medium": 20,
        "Low": 10,
    }

    data_sensitivity_points = {
        "Financial Data": 25,
        "PII": 25,
        "PHI": 25,
        "Confidential Data": 25,
        "Customer Inputs": 20,
        "Customer Emails": 15,
        "Internal Data": 10,
        "Public Data": 5,
    }

    breakdown = []

    business_criticality = str(row["Business_Criticality"]).strip()
    data_type = str(row["Data_Type"]).strip()

    breakdown.append({
        "Risk Factor": f"Business Criticality: {business_criticality}",
        "Points": criticality_points.get(business_criticality, 10),
        "Reason": "Business-critical vendors create greater operational and compliance exposure."
    })

    breakdown.append({
        "Risk Factor": f"Data Sensitivity: {data_type}",
        "Points": data_sensitivity_points.get(data_type, 10),
        "Reason": "Sensitive data increases privacy, security, and regulatory risk."
    })

    for gap in gaps:
        if gap == "Known Vulnerability":
            points = 25
            reason = "Known vulnerabilities increase the likelihood of exploitation and require urgent review."
        elif gap in ["Missing SOC 2", "Missing MFA", "Missing Encryption", "Missing Incident Response Plan"]:
            points = 15
            reason = "Missing security evidence or control documentation creates audit and compliance gaps."
        elif gap in ["Unknown Encryption", "Stale Risk Review"]:
            points = 10
            reason = "Unknown or outdated evidence reduces confidence in the vendor's security posture."
        else:
            points = 5
            reason = "Additional risk signal identified."

        breakdown.append({
            "Risk Factor": gap,
            "Points": points,
            "Reason": reason
        })

    raw_score = sum(item["Points"] for item in breakdown)
    final_score = min(raw_score, 100)

    breakdown.append({
        "Risk Factor": "Raw Score",
        "Points": raw_score,
        "Reason": "Total before applying the maximum score cap."
    })

    breakdown.append({
        "Risk Factor": "Final Score",
        "Points": final_score,
        "Reason": "Final score is capped at 100 for consistent risk reporting."
    })

    return breakdown


def build_custom_report(row, gaps, mappings, recommendations, score, risk_level, priority):
    gaps_text = "\n".join([f"- {gap}" for gap in gaps]) if gaps else "- No major evidence gaps identified."
    mappings_text = "\n".join([f"- {item}" for item in mappings]) if mappings else "- No framework mappings identified."
    recommendations_text = "\n".join([f"- {item}" for item in recommendations]) if recommendations else "- Continue routine monitoring."

    breakdown = calculate_score_breakdown(row, gaps)
    breakdown_text = "\n".join(
        [f"- **{item['Risk Factor']}**: +{item['Points']} points — {item['Reason']}" for item in breakdown]
    )

    return f"""# TrustShield GRC Vendor Risk Assessment Report

## Executive Summary

TrustShield GRC reviewed **{row['Vendor']}**, a vendor supporting **{row['System']}**, and calculated a cybersecurity vendor risk score of **{score}/100**.

**Risk Level:** {risk_level}  
**Recommended Priority:** {priority}

This assessment supports vendor risk management, cybersecurity governance, compliance documentation, and audit readiness.

---

## Risk Score Breakdown

{breakdown_text}

---

## Vendor Profile

- **Vendor:** {row['Vendor']}
- **System:** {row['System']}
- **Data Type:** {row['Data_Type']}
- **Business Criticality:** {row['Business_Criticality']}
- **Last Risk Review:** {row['Last_Risk_Review']}

---

## Assessment Inputs

- **SOC 2 Evidence Available:** {row['Has_SOC2']}
- **MFA Implemented:** {row['Has_MFA']}
- **Encryption Status:** {row['Encryption']}
- **Incident Response Plan Available:** {row['Incident_Response_Plan']}
- **Known Vulnerability:** {row['Known_Vulnerability']}

---

## Evidence Gaps

{gaps_text}

---

## Framework Mapping

{mappings_text}

---

## Recommended Actions

{recommendations_text}

---

## Portfolio Note

This report was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate risk analysis, compliance documentation, control mapping, audit-readiness thinking, and Python/Streamlit automation.
---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.

"""

SAMPLE_ASSESSMENT = {
    "Vendor": "FinAssist AI",
    "System": "AI-powered loan screening platform",
    "Data_Type": "Financial Data",
    "Business_Criticality": "High",
    "Has_SOC2": "No",
    "Has_MFA": "No",
    "Encryption": "Unknown",
    "Incident_Response_Plan": "No",
    "Known_Vulnerability": "Yes",
    "Last_Risk_Review": date.today() - timedelta(days=240),
}


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

tab0, tab1, tab2, tab3, tab4 = st.tabs(
    [
        "🚀 Interactive Assessment",
        "📊 Dashboard",
        "🔎 Vendor Detail",
        "🧾 Report Generator",
        "🧠 Methodology"
    ]
)


with tab0:
    st.header("Run a Custom Vendor Risk Assessment")

    st.write(
        "Enter fictional vendor security information, run a risk assessment, review evidence gaps, "
        "map findings to security frameworks, and download a custom report. "
        "Do not enter confidential, client, or production data."
    )

    if st.button("🚀 Load Sample AI Vendor Scenario", use_container_width=True):
        st.session_state["loaded_sample"] = True

    sample = SAMPLE_ASSESSMENT if st.session_state.get("loaded_sample", True) else SAMPLE_ASSESSMENT

    with st.form("interactive_vendor_assessment"):
        left, right = st.columns(2)

        with left:
            vendor = st.text_input("Vendor Name", value=sample["Vendor"])
            system = st.text_input("System / Service", value=sample["System"])

            data_options = [
                "Financial Data",
                "PII",
                "PHI",
                "Confidential Data",
                "Customer Inputs",
                "Customer Emails",
                "Internal Data",
                "Public Data",
            ]

            data_type = st.selectbox(
                "Data Type",
                data_options,
                index=data_options.index(sample["Data_Type"])
            )

            business_criticality = st.selectbox(
                "Business Criticality",
                ["High", "Medium", "Low"],
                index=["High", "Medium", "Low"].index(sample["Business_Criticality"])
            )

            last_review = st.date_input(
                "Last Risk Review Date",
                value=sample["Last_Risk_Review"]
            )

        with right:
            has_soc2 = st.selectbox(
                "SOC 2 Evidence Available?",
                ["Yes", "No"],
                index=["Yes", "No"].index(sample["Has_SOC2"])
            )

            has_mfa = st.selectbox(
                "MFA Implemented?",
                ["Yes", "No"],
                index=["Yes", "No"].index(sample["Has_MFA"])
            )

            encryption = st.selectbox(
                "Encryption Status",
                ["Yes", "No", "Unknown"],
                index=["Yes", "No", "Unknown"].index(sample["Encryption"])
            )

            incident_response = st.selectbox(
                "Incident Response Plan Available?",
                ["Yes", "No"],
                index=["Yes", "No"].index(sample["Incident_Response_Plan"])
            )

            known_vulnerability = st.selectbox(
                "Known Vulnerability?",
                ["Yes", "No"],
                index=["Yes", "No"].index(sample["Known_Vulnerability"])
            )

        submitted = st.form_submit_button("Analyze Vendor Risk", use_container_width=True)

    if submitted:
        row = pd.Series({
            "Vendor": vendor,
            "System": system,
            "Data_Type": data_type,
            "Business_Criticality": business_criticality,
            "Has_SOC2": has_soc2,
            "Has_MFA": has_mfa,
            "Encryption": encryption,
            "Incident_Response_Plan": incident_response,
            "Known_Vulnerability": known_vulnerability,
            "Last_Risk_Review": last_review.strftime("%Y-%m-%d"),
        })

        gaps = identify_gaps(row)
        score = score_vendor(row)
        risk_level = classify_risk(score)
        priority = prioritize_action(risk_level)
        mappings, recommendations = map_frameworks_and_recommendations(gaps)

        st.success("Assessment completed.")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Vendor", vendor)
        m2.metric("Risk Score", f"{score}/100")
        m3.metric("Risk Level", risk_badge(risk_level))
        m4.metric("Priority", priority)

        breakdown = calculate_score_breakdown(row, gaps)
        breakdown_df = pd.DataFrame(breakdown)

        with st.expander("Risk Score Breakdown — Why this score was assigned", expanded=True):
            st.write(
                "This section makes the risk score explainable by showing how business criticality, "
                "data sensitivity, and security evidence gaps contributed to the final risk score."
            )
            st.dataframe(
                breakdown_df,
                use_container_width=True,
                hide_index=True
            )
            raw_score = breakdown_df.loc[breakdown_df["Risk Factor"] == "Raw Score", "Points"].iloc[0]
            final_score = breakdown_df.loc[breakdown_df["Risk Factor"] == "Final Score", "Points"].iloc[0]
            st.caption(f"Raw score: {raw_score}. Final score: {final_score}/100. Scores are capped at 100 for consistent reporting.")

        st.markdown("### Assessment Findings")

        f1, f2, f3 = st.columns(3)

        with f1:
            st.markdown("#### Evidence Gaps")
            if gaps:
                for gap in gaps:
                    st.warning(gap)
            else:
                st.success("No major evidence gaps identified.")

        with f2:
            st.markdown("#### Framework Mapping")
            if mappings:
                for mapping in mappings:
                    st.info(mapping)
            else:
                st.write("No framework mapping identified.")

        with f3:
            st.markdown("#### Recommended Actions")
            if recommendations:
                for item in recommendations:
                    st.success(item)
            else:
                st.write("Continue routine monitoring.")

        st.markdown("### Executive Summary")
        st.write(
            f"{vendor} was assessed as **{risk_level} risk** with a score of **{score}/100**. "
            "This output can support vendor risk review, compliance documentation, remediation planning, and audit readiness."
        )

        custom_report = build_custom_report(row, gaps, mappings, recommendations, score, risk_level, priority)

        st.markdown("### Report Deliverable")
        st.info(
            "The downloadable report includes the vendor profile, assessment inputs, risk score breakdown, "
            "evidence gaps, framework mapping, recommended actions, and ownership/prototype usage notice."
        )

        with st.expander("Preview Executive Vendor Risk Report", expanded=False):
            st.markdown(custom_report)

        st.download_button(
            label="📥 Download Executive Vendor Risk Report (.md)",
            data=custom_report,
            file_name=f"{vendor.lower().replace(' ', '_')}_executive_vendor_risk_report.md",
            mime="text/markdown",
            use_container_width=True
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
