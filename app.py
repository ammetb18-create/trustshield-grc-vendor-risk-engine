import json
import pandas as pd
import streamlit as st
from datetime import date, timedelta, datetime
from risk_engine import (
    analyze_vendors,
    identify_gaps,
    score_vendor,
    classify_risk,
    prioritize_action,
)
from report_generator import generate_markdown_report
from demo_data import get_rich_demo_vendor_inventory_df, get_invalid_demo_vendor_inventory_df

st.set_page_config(
    page_title="TrustShield GRC",
    page_icon="🛡️",
    layout="wide"
)

df = analyze_vendors()

if "assessment_history" not in st.session_state:
    st.session_state.assessment_history = []

if "evidence_tracker_state" not in st.session_state:
    st.session_state.evidence_tracker_state = []

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



def generate_remediation_plan(gaps, risk_level):
    """Create a consulting-style remediation plan based on evidence gaps and risk level."""
    remediation_catalog = {
        "Missing SOC 2": {
            "Action Item": "Request and review the vendor's latest SOC 2 Type II report",
            "Control Objective": "Validate third-party security, availability, confidentiality, and processing integrity controls",
            "Required Evidence": "SOC 2 Type II report, bridge letter if applicable, management response to exceptions",
            "Suggested Owner": "Vendor Risk / GRC Analyst",
            "Timeline": "15 business days",
            "Priority": "High",
        },
        "Missing MFA": {
            "Action Item": "Require MFA enforcement for privileged and user access",
            "Control Objective": "Reduce account takeover risk and strengthen identity and access controls",
            "Required Evidence": "MFA policy, identity provider configuration evidence, access control screenshots, user access review evidence",
            "Suggested Owner": "IT Security / IAM Owner",
            "Timeline": "10 business days",
            "Priority": "High",
        },
        "Missing Encryption": {
            "Action Item": "Confirm encryption at rest and in transit for sensitive data",
            "Control Objective": "Protect sensitive information from unauthorized disclosure or interception",
            "Required Evidence": "Encryption policy, architecture diagram, TLS configuration, database/storage encryption evidence",
            "Suggested Owner": "Security Engineering / Vendor Technical Contact",
            "Timeline": "15 business days",
            "Priority": "High",
        },
        "Unknown Encryption": {
            "Action Item": "Obtain clarification and evidence of encryption controls",
            "Control Objective": "Remove uncertainty around data protection posture",
            "Required Evidence": "Encryption attestation, technical documentation, architecture diagram, policy excerpt",
            "Suggested Owner": "Vendor Risk / Security Review Team",
            "Timeline": "10 business days",
            "Priority": "Medium",
        },
        "Missing Incident Response Plan": {
            "Action Item": "Request the vendor's incident response policy and escalation procedures",
            "Control Objective": "Validate readiness to detect, respond to, and communicate security incidents",
            "Required Evidence": "Incident response plan, breach notification procedure, escalation matrix, tabletop exercise summary",
            "Suggested Owner": "Incident Response / GRC Analyst",
            "Timeline": "15 business days",
            "Priority": "High",
        },
        "Known Vulnerability": {
            "Action Item": "Require documented remediation or risk acceptance for known vulnerability exposure",
            "Control Objective": "Ensure timely remediation of exploitable weaknesses",
            "Required Evidence": "Vulnerability scan summary, remediation plan, patch evidence, risk acceptance if unresolved",
            "Suggested Owner": "Security Operations / Vendor Technical Owner",
            "Timeline": "5 business days",
            "Priority": "Critical",
        },
        "Stale Risk Review": {
            "Action Item": "Schedule a refreshed vendor risk review",
            "Control Objective": "Maintain current vendor risk documentation and audit readiness",
            "Required Evidence": "Updated questionnaire, refreshed control evidence, review notes, approval record",
            "Suggested Owner": "Vendor Risk / Compliance Owner",
            "Timeline": "30 business days",
            "Priority": "Medium",
        },
    }

    plan = []

    if risk_level == "Critical":
        plan.append({
            "Action Item": "Escalate vendor for executive-level risk review",
            "Control Objective": "Ensure high-risk vendor exposure is visible to decision-makers",
            "Required Evidence": "Executive summary, risk score, evidence gaps, remediation ownership, target dates",
            "Suggested Owner": "GRC Lead / Security Leadership",
            "Timeline": "Immediate",
            "Priority": "Critical",
        })

    for gap in gaps:
        if gap in remediation_catalog:
            plan.append(remediation_catalog[gap])

    if not plan:
        plan.append({
            "Action Item": "Continue routine vendor monitoring",
            "Control Objective": "Maintain ongoing audit readiness and vendor oversight",
            "Required Evidence": "Periodic review record, updated vendor profile, monitoring notes",
            "Suggested Owner": "Vendor Risk / Compliance Owner",
            "Timeline": "Quarterly",
            "Priority": "Low",
        })

    return plan


def build_custom_report(row, gaps, mappings, recommendations, score, risk_level, priority):
    gaps_text = "\n".join([f"- {gap}" for gap in gaps]) if gaps else "- No major evidence gaps identified."
    mappings_text = "\n".join([f"- {item}" for item in mappings]) if mappings else "- No framework mappings identified."
    recommendations_text = "\n".join([f"- {item}" for item in recommendations]) if recommendations else "- Continue routine monitoring."

    remediation_plan = generate_remediation_plan(gaps, risk_level)
    remediation_text = "\n".join(
        [
            f"- **{item['Priority']} Priority — {item['Action Item']}**\n"
            f"  - Control Objective: {item['Control Objective']}\n"
            f"  - Required Evidence: {item['Required Evidence']}\n"
            f"  - Suggested Owner: {item['Suggested Owner']}\n"
            f"  - Timeline: {item['Timeline']}"
            for item in remediation_plan
        ]
    )

    breakdown = calculate_score_breakdown(row, gaps)
    breakdown_lines = []
    for item in breakdown:
        factor = item["Risk Factor"]
        points = item["Points"]
        reason = item["Reason"]

        if factor == "Final Score":
            breakdown_lines.append(f"- **Final Score:** {points}/100 — {reason}")
        elif factor == "Raw Score":
            breakdown_lines.append(f"- **Raw Score:** {points} points — {reason}")
        else:
            breakdown_lines.append(f"- **{factor}**: +{points} points — {reason}")

    breakdown_text = "\n".join(breakdown_lines)

    return f"""# TrustShield GRC Vendor Risk Assessment Report

## Report Metadata

- **Prepared By:** América Trujillo
- **Tool:** TrustShield GRC
- **Report Type:** Individual Vendor Cybersecurity Risk Assessment
- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Assessment Mode:** Prototype / Portfolio Demonstration
- **Intended Use:** Vendor risk review, evidence gap analysis, remediation planning, and audit-readiness documentation

---

## Assessment Scope

This assessment evaluates the cybersecurity and compliance risk posture of a third-party vendor based on business criticality, data sensitivity, available security evidence, control gaps, known vulnerability exposure, and risk review freshness.

The assessment is designed to support third-party risk management, cybersecurity governance, vendor evidence review, and remediation planning.

---

## Executive Summary

TrustShield GRC reviewed **{row['Vendor']}**, a vendor supporting **{row['System']}**, and calculated a cybersecurity vendor risk score of **{score}/100**.

**Risk Level:** {risk_level}  
**Recommended Priority:** {priority}

This assessment supports vendor risk management, cybersecurity governance, compliance documentation, and audit readiness.

---

## Methodology / Basis of Assessment

TrustShield GRC calculates vendor risk using structured assessment inputs and evidence gap indicators. The score considers:

- Business criticality of the vendor or service
- Sensitivity of data handled by the vendor
- SOC 2 or equivalent assurance evidence availability
- MFA / identity control evidence
- Encryption status
- Incident response readiness
- Known vulnerability exposure
- Freshness of the last vendor risk review

The output is intended to help prioritize vendor follow-up, remediation planning, evidence requests, and risk documentation.

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

## Remediation Action Plan

{remediation_text}

---

## Limitations

This report is based on the assessment inputs entered into TrustShield GRC and does not independently verify vendor claims, technical configurations, contractual obligations, or production security controls.

This prototype does not replace a formal vendor due diligence process, legal review, audit procedure, penetration test, security architecture review, or compliance certification.

---

## Portfolio Note

This report was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate risk analysis, compliance documentation, control mapping, audit-readiness thinking, and Python/Streamlit automation.

---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.

"""


def get_batch_template_df():
    """Return a CSV template for batch vendor assessments."""
    return pd.DataFrame([
        {
            "Vendor": "FinAssist AI",
            "System": "AI-powered loan screening platform",
            "Data_Type": "Financial Data",
            "Business_Criticality": "High",
            "Has_SOC2": "No",
            "Has_MFA": "No",
            "Encryption": "Unknown",
            "Incident_Response_Plan": "No",
            "Known_Vulnerability": "Yes",
            "Last_Risk_Review": "2025-09-26",
        },
        {
            "Vendor": "SecureDocs Cloud",
            "System": "Document management platform",
            "Data_Type": "Confidential Data",
            "Business_Criticality": "Medium",
            "Has_SOC2": "Yes",
            "Has_MFA": "Yes",
            "Encryption": "Yes",
            "Incident_Response_Plan": "Yes",
            "Known_Vulnerability": "No",
            "Last_Risk_Review": "2026-03-15",
        },
    ])



def normalize_batch_value(value):
    """Clean text values imported from CSV."""
    if pd.isna(value):
        return ""
    return str(value).strip()



def get_required_batch_columns():
    """Return the required columns for a valid vendor inventory CSV."""
    return [
        "Vendor",
        "System",
        "Data_Type",
        "Business_Criticality",
        "Has_SOC2",
        "Has_MFA",
        "Encryption",
        "Incident_Response_Plan",
        "Known_Vulnerability",
        "Last_Risk_Review",
    ]



def detect_uploaded_csv_type(uploaded_df):
    """Detect whether the uploaded CSV looks like an input template or an output file."""
    columns = set(uploaded_df.columns)

    required_inventory_columns = set(get_required_batch_columns())

    batch_results_columns = {
        "Assessment Timestamp",
        "Vendor",
        "System / Service",
        "Risk Score",
        "Risk Level",
        "Recommended Priority",
        "Evidence Gaps",
    }

    evidence_tracker_columns = {
        "Vendor",
        "System / Service",
        "Risk Score",
        "Risk Level",
        "Evidence Gap",
        "Evidence Request",
        "Required Evidence",
        "Status",
    }

    assessment_history_columns = {
        "Assessment Timestamp",
        "Vendor",
        "System / Service",
        "Data Type",
        "Business Criticality",
        "Risk Score",
        "Risk Level",
    }

    validation_error_columns = {
        "Row",
        "Column",
        "Issue",
        "Expected Format",
    }

    if required_inventory_columns.issubset(columns):
        return "vendor_inventory", "This appears to be a valid vendor inventory input file."

    if evidence_tracker_columns.issubset(columns):
        return (
            "evidence_tracker_output",
            "This looks like an Evidence Request Tracker export. That file is an output, not a vendor inventory input."
        )

    if batch_results_columns.issubset(columns):
        return (
            "batch_results_output",
            "This looks like a Batch Risk Results export. That file is an output, not a vendor inventory input."
        )

    if assessment_history_columns.issubset(columns):
        return (
            "assessment_history_output",
            "This looks like an Assessment History export. That file is an output, not a vendor inventory input."
        )

    if validation_error_columns.issubset(columns):
        return (
            "validation_errors_output",
            "This looks like a CSV Validation Errors export. That file is an error report, not a vendor inventory input."
        )

    return (
        "unknown_or_incomplete",
        "This CSV does not match the required vendor inventory template."
    )


def validate_and_standardize_batch_dataframe(uploaded_df):
    """
    Validate uploaded vendor inventory data and standardize accepted values.
    Returns: standardized_df, validation_errors
    """
    standardized_df = uploaded_df.copy()
    errors = []

    required_columns = get_required_batch_columns()
    missing_columns = [col for col in required_columns if col not in standardized_df.columns]

    for col in missing_columns:
        errors.append({
            "Row": "File",
            "Column": col,
            "Issue": "Missing required column",
            "Expected Format": "Column must exist in the CSV template",
        })

    if missing_columns:
        return standardized_df, errors

    allowed_values = {
        "Business_Criticality": {
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        },
        "Has_SOC2": {
            "yes": "Yes",
            "no": "No",
        },
        "Has_MFA": {
            "yes": "Yes",
            "no": "No",
        },
        "Encryption": {
            "yes": "Yes",
            "no": "No",
            "unknown": "Unknown",
        },
        "Incident_Response_Plan": {
            "yes": "Yes",
            "no": "No",
        },
        "Known_Vulnerability": {
            "yes": "Yes",
            "no": "No",
        },
    }

    for idx, row in standardized_df.iterrows():
        csv_row_number = idx + 2

        vendor = normalize_batch_value(row["Vendor"])
        system = normalize_batch_value(row["System"])

        if not vendor:
            errors.append({
                "Row": csv_row_number,
                "Column": "Vendor",
                "Issue": "Vendor name is blank",
                "Expected Format": "Enter a vendor name",
            })

        if not system:
            errors.append({
                "Row": csv_row_number,
                "Column": "System",
                "Issue": "System / service name is blank",
                "Expected Format": "Enter the system or service name",
            })

        standardized_df.at[idx, "Vendor"] = vendor
        standardized_df.at[idx, "System"] = system

        for column, valid_map in allowed_values.items():
            raw_value = normalize_batch_value(row[column])
            normalized_value = raw_value.lower()

            if normalized_value not in valid_map:
                errors.append({
                    "Row": csv_row_number,
                    "Column": column,
                    "Issue": f"Invalid value: {raw_value}",
                    "Expected Format": "Use one of: " + ", ".join(sorted(set(valid_map.values()))),
                })
            else:
                standardized_df.at[idx, column] = valid_map[normalized_value]

        data_type = normalize_batch_value(row["Data_Type"])
        if not data_type:
            errors.append({
                "Row": csv_row_number,
                "Column": "Data_Type",
                "Issue": "Data type is blank",
                "Expected Format": "Example: Financial Data, PII, PHI, Confidential Data, Internal Data, Public Data",
            })
        else:
            standardized_df.at[idx, "Data_Type"] = data_type

        review_date = normalize_batch_value(row["Last_Risk_Review"])

        parsed_date = pd.to_datetime(review_date, format="%Y-%m-%d", errors="coerce")

        if pd.isna(parsed_date):
            errors.append({
                "Row": csv_row_number,
                "Column": "Last_Risk_Review",
                "Issue": f"Invalid date: {review_date}",
                "Expected Format": "Use YYYY-MM-DD, example: 2026-05-24",
            })
        elif parsed_date.date() > date.today():
            errors.append({
                "Row": csv_row_number,
                "Column": "Last_Risk_Review",
                "Issue": f"Future date not allowed: {review_date}",
                "Expected Format": "Use a past or current review date",
            })
        else:
            standardized_df.at[idx, "Last_Risk_Review"] = parsed_date.strftime("%Y-%m-%d")

    return standardized_df, errors


def analyze_batch_dataframe(uploaded_df):
    """Analyze multiple vendors from an uploaded CSV using TrustShield scoring logic."""
    required_columns = [
        "Vendor",
        "System",
        "Data_Type",
        "Business_Criticality",
        "Has_SOC2",
        "Has_MFA",
        "Encryption",
        "Incident_Response_Plan",
        "Known_Vulnerability",
        "Last_Risk_Review",
    ]

    missing_columns = [col for col in required_columns if col not in uploaded_df.columns]

    if missing_columns:
        return None, missing_columns

    results = []

    for _, input_row in uploaded_df.iterrows():
        row = pd.Series({
            "Vendor": normalize_batch_value(input_row["Vendor"]) or "Unnamed Vendor",
            "System": normalize_batch_value(input_row["System"]) or "Unspecified System",
            "Data_Type": normalize_batch_value(input_row["Data_Type"]) or "Internal Data",
            "Business_Criticality": normalize_batch_value(input_row["Business_Criticality"]) or "Low",
            "Has_SOC2": normalize_batch_value(input_row["Has_SOC2"]) or "No",
            "Has_MFA": normalize_batch_value(input_row["Has_MFA"]) or "No",
            "Encryption": normalize_batch_value(input_row["Encryption"]) or "Unknown",
            "Incident_Response_Plan": normalize_batch_value(input_row["Incident_Response_Plan"]) or "No",
            "Known_Vulnerability": normalize_batch_value(input_row["Known_Vulnerability"]) or "No",
            "Last_Risk_Review": normalize_batch_value(input_row["Last_Risk_Review"]) or "1900-01-01",
        })

        gaps = identify_gaps(row)
        score = score_vendor(row)
        risk_level = classify_risk(score)
        priority = prioritize_action(risk_level)
        mappings, recommendations = map_frameworks_and_recommendations(gaps)

        results.append({
            "Assessment Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Vendor": row["Vendor"],
            "System / Service": row["System"],
            "Data Type": row["Data_Type"],
            "Business Criticality": row["Business_Criticality"],
            "Risk Score": score,
            "Risk Level": risk_level,
            "Recommended Priority": priority,
            "Evidence Gaps": ", ".join(gaps) if gaps else "No major evidence gaps identified",
            "Framework Mapping": ", ".join(mappings) if mappings else "No framework mappings identified",
            "Recommended Actions": " | ".join(recommendations) if recommendations else "Continue routine monitoring",
        })

    results_df = pd.DataFrame(results).sort_values(
        by="Risk Score",
        ascending=False
    )

    return results_df, []




def dataframe_to_markdown_table(dataframe):
    """Create a Markdown table without requiring the external tabulate package."""
    preferred_columns = [
        "Vendor",
        "System / Service",
        "Data Type",
        "Business Criticality",
        "Risk Score",
        "Risk Level",
        "Recommended Priority",
        "Evidence Gaps",
    ]

    available_columns = [col for col in preferred_columns if col in dataframe.columns]
    report_df = dataframe[available_columns].copy()

    def clean_cell(value):
        return str(value).replace("\n", " ").replace("|", "/").strip()

    header = "| " + " | ".join(available_columns) + " |"
    separator = "| " + " | ".join(["---"] * len(available_columns)) + " |"

    rows = []
    for _, row in report_df.iterrows():
        rows.append("| " + " | ".join(clean_cell(row[col]) for col in available_columns) + " |")

    return "\n".join([header, separator] + rows)


def generate_batch_executive_report(batch_results):
    """Generate a consolidated executive report for uploaded vendor batch analysis."""
    total_vendors = len(batch_results)
    average_score = round(batch_results["Risk Score"].mean(), 2) if total_vendors else 0

    risk_counts = batch_results["Risk Level"].value_counts().to_dict()
    critical_count = risk_counts.get("Critical", 0)
    high_count = risk_counts.get("High", 0)
    medium_count = risk_counts.get("Medium", 0)
    low_count = risk_counts.get("Low", 0)

    top_vendors = batch_results.sort_values(
        by="Risk Score",
        ascending=False
    ).head(5)

    top_vendor_text = "\n".join([
        f"- **{row['Vendor']}** — {row['Risk Level']} risk, score {row['Risk Score']}/100, priority: {row['Recommended Priority']}"
        for _, row in top_vendors.iterrows()
    ]) if not top_vendors.empty else "- No vendors available."

    gap_counter = {}

    for gaps in batch_results["Evidence Gaps"]:
        if not gaps or gaps == "No major evidence gaps identified":
            continue

        for gap in str(gaps).split(","):
            clean_gap = gap.strip()
            if clean_gap:
                gap_counter[clean_gap] = gap_counter.get(clean_gap, 0) + 1

    common_gaps = sorted(
        gap_counter.items(),
        key=lambda item: item[1],
        reverse=True
    )

    common_gaps_text = "\n".join([
        f"- **{gap}** — observed in {count} vendor(s)"
        for gap, count in common_gaps
    ]) if common_gaps else "- No recurring evidence gaps identified."

    if critical_count > 0:
        executive_recommendation = (
            "Immediate executive review is recommended for critical-risk vendors. "
            "Prioritize remediation evidence collection, vulnerability validation, and vendor risk ownership assignment."
        )
    elif high_count > 0:
        executive_recommendation = (
            "Prioritize high-risk vendors for remediation tracking and evidence validation. "
            "Conditional approval may be appropriate where compensating controls are documented."
        )
    elif medium_count > 0:
        executive_recommendation = (
            "Continue monitoring medium-risk vendors and schedule periodic evidence refreshes."
        )
    else:
        executive_recommendation = (
            "Maintain routine vendor monitoring and annual reassessment."
        )

    batch_results_markdown = dataframe_to_markdown_table(batch_results)

    return f"""# TrustShield GRC Consolidated Vendor Risk Report

## Executive Summary

TrustShield GRC analyzed **{total_vendors} vendor(s)** from the uploaded vendor inventory and calculated an average cybersecurity vendor risk score of **{average_score}/100**.

This consolidated report supports vendor risk prioritization, cybersecurity governance, compliance documentation, and audit readiness.

---

## Risk Distribution

- **Critical Risk Vendors:** {critical_count}
- **High Risk Vendors:** {high_count}
- **Medium Risk Vendors:** {medium_count}
- **Low Risk Vendors:** {low_count}

---

## Highest-Risk Vendors

{top_vendor_text}

---

## Most Common Evidence Gaps

{common_gaps_text}

---

## Executive Recommendation

{executive_recommendation}

---

## Batch Risk Results

{batch_results_markdown}

---

## Consulting Use Case

This consolidated report can support vendor risk review meetings, audit preparation, remediation planning, compliance documentation, and executive-level vendor risk prioritization.

---

## Prototype Notice

This report was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate batch vendor risk analysis, evidence gap identification, framework mapping, remediation planning, and Python/Streamlit automation.

---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.
"""



def generate_evidence_request_tracker(history_records):
    """Create an evidence request tracker from completed assessment history."""
    evidence_catalog = {
        "Missing SOC 2": {
            "Evidence Request": "Request SOC 2 Type II report or equivalent assurance documentation",
            "Control Objective": "Validate third-party security, availability, confidentiality, and processing integrity controls",
            "Required Evidence": "SOC 2 Type II report, bridge letter if applicable, management response to exceptions",
            "Suggested Owner": "Vendor Risk / GRC Analyst",
            "Priority": "High",
            "Timeline": "15 business days",
        },
        "Missing MFA": {
            "Evidence Request": "Request MFA enforcement evidence for privileged and user access",
            "Control Objective": "Reduce account takeover risk and strengthen identity and access controls",
            "Required Evidence": "MFA policy, IdP configuration evidence, access control screenshots, user access review evidence",
            "Suggested Owner": "IT Security / IAM Owner",
            "Priority": "High",
            "Timeline": "10 business days",
        },
        "Missing Encryption": {
            "Evidence Request": "Request encryption documentation for data at rest and in transit",
            "Control Objective": "Protect sensitive information from unauthorized disclosure or interception",
            "Required Evidence": "Encryption policy, architecture diagram, TLS configuration, database/storage encryption evidence",
            "Suggested Owner": "Security Engineering / Vendor Technical Contact",
            "Priority": "High",
            "Timeline": "15 business days",
        },
        "Unknown Encryption": {
            "Evidence Request": "Request clarification and supporting evidence for encryption controls",
            "Control Objective": "Remove uncertainty around the vendor's data protection posture",
            "Required Evidence": "Encryption attestation, technical documentation, architecture diagram, policy excerpt",
            "Suggested Owner": "Vendor Risk / Security Review Team",
            "Priority": "Medium",
            "Timeline": "10 business days",
        },
        "Missing Incident Response Plan": {
            "Evidence Request": "Request incident response policy and escalation procedures",
            "Control Objective": "Validate readiness to detect, respond to, and communicate security incidents",
            "Required Evidence": "Incident response plan, breach notification procedure, escalation matrix, tabletop exercise summary",
            "Suggested Owner": "Incident Response / GRC Analyst",
            "Priority": "High",
            "Timeline": "15 business days",
        },
        "Known Vulnerability": {
            "Evidence Request": "Request remediation evidence or documented risk acceptance for known vulnerability exposure",
            "Control Objective": "Ensure timely remediation of exploitable weaknesses",
            "Required Evidence": "Vulnerability scan summary, remediation plan, patch evidence, risk acceptance if unresolved",
            "Suggested Owner": "Security Operations / Vendor Technical Owner",
            "Priority": "Critical",
            "Timeline": "5 business days",
        },
        "Stale Risk Review": {
            "Evidence Request": "Request updated vendor risk review and refreshed control evidence",
            "Control Objective": "Maintain current vendor risk documentation and audit readiness",
            "Required Evidence": "Updated questionnaire, refreshed control evidence, review notes, approval record",
            "Suggested Owner": "Vendor Risk / Compliance Owner",
            "Priority": "Medium",
            "Timeline": "30 business days",
        },
    }

    tracker_rows = []

    for record in history_records:
        vendor = record.get("Vendor", "Unknown Vendor")
        system = record.get("System / Service", "Unknown System")
        risk_level = record.get("Risk Level", "Unknown")
        risk_score = record.get("Risk Score", "")
        gaps_text = record.get("Evidence Gaps", "")

        if not gaps_text or gaps_text == "No major evidence gaps identified":
            tracker_rows.append({
                "Vendor": vendor,
                "System / Service": system,
                "Risk Score": risk_score,
                "Risk Level": risk_level,
                "Evidence Gap": "No major evidence gaps identified",
                "Evidence Request": "Continue routine monitoring",
                "Control Objective": "Maintain ongoing vendor oversight",
                "Required Evidence": "Periodic review record, updated vendor profile, monitoring notes",
                "Suggested Owner": "Vendor Risk / Compliance Owner",
                "Priority": "Low",
                "Timeline": "Quarterly",
                "Status": "Monitoring",
            })
            continue

        gaps = [gap.strip() for gap in str(gaps_text).split(",") if gap.strip()]

        for gap in gaps:
            item = evidence_catalog.get(gap)

            if item:
                tracker_rows.append({
                    "Vendor": vendor,
                    "System / Service": system,
                    "Risk Score": risk_score,
                    "Risk Level": risk_level,
                    "Evidence Gap": gap,
                    "Evidence Request": item["Evidence Request"],
                    "Control Objective": item["Control Objective"],
                    "Required Evidence": item["Required Evidence"],
                    "Suggested Owner": item["Suggested Owner"],
                    "Priority": item["Priority"],
                    "Timeline": item["Timeline"],
                    "Status": "Open",
                })
            else:
                tracker_rows.append({
                    "Vendor": vendor,
                    "System / Service": system,
                    "Risk Score": risk_score,
                    "Risk Level": risk_level,
                    "Evidence Gap": gap,
                    "Evidence Request": "Review and document evidence requirement",
                    "Control Objective": "Clarify risk treatment and evidence expectations",
                    "Required Evidence": "Supporting documentation to be determined",
                    "Suggested Owner": "GRC Analyst",
                    "Priority": "Medium",
                    "Timeline": "15 business days",
                    "Status": "Open",
                })

    return pd.DataFrame(tracker_rows)



def evidence_tracker_to_markdown_table(tracker_df):
    """Create a readable Markdown table for evidence requests without external dependencies."""
    preferred_columns = [
        "Vendor",
        "System / Service",
        "Risk Level",
        "Evidence Gap",
        "Evidence Request",
        "Suggested Owner",
        "Priority",
        "Timeline",
        "Status",
        "Reviewer Notes",
    ]

    available_columns = [col for col in preferred_columns if col in tracker_df.columns]
    report_df = tracker_df[available_columns].copy()

    def clean_cell(value):
        return str(value).replace("\\n", " ").replace("|", "/").strip()

    header = "| " + " | ".join(available_columns) + " |"
    separator = "| " + " | ".join(["---"] * len(available_columns)) + " |"

    rows = []
    for _, row in report_df.iterrows():
        rows.append("| " + " | ".join(clean_cell(row[col]) for col in available_columns) + " |")

    return "\\n".join([header, separator] + rows)


def generate_evidence_tracker_report(tracker_df):
    """Generate a human-readable executive report for evidence request tracking."""
    total_requests = len(tracker_df)
    critical_requests = len(tracker_df[tracker_df["Priority"] == "Critical"]) if "Priority" in tracker_df.columns else 0
    high_requests = len(tracker_df[tracker_df["Priority"] == "High"]) if "Priority" in tracker_df.columns else 0
    medium_requests = len(tracker_df[tracker_df["Priority"] == "Medium"]) if "Priority" in tracker_df.columns else 0
    low_requests = len(tracker_df[tracker_df["Priority"] == "Low"]) if "Priority" in tracker_df.columns else 0

    vendor_count = tracker_df["Vendor"].nunique() if "Vendor" in tracker_df.columns else 0

    if "Vendor" in tracker_df.columns:
        vendor_summary = tracker_df["Vendor"].value_counts().reset_index()
        vendor_summary.columns = ["Vendor", "Open Evidence Requests"]
        top_vendor_text = "\\n".join(
            [
                f"- **{row['Vendor']}** — {row['Open Evidence Requests']} evidence request(s)"
                for _, row in vendor_summary.head(10).iterrows()
            ]
        )
    else:
        top_vendor_text = "- Vendor information unavailable."

    if critical_requests > 0:
        executive_recommendation = (
            "Immediate follow-up is recommended for critical evidence requests. "
            "Critical items should be prioritized for escalation, remediation validation, or documented risk acceptance."
        )
    elif high_requests > 0:
        executive_recommendation = (
            "High-priority evidence requests should be tracked with assigned owners and target dates. "
            "Vendor approval should remain conditional until required evidence is received and reviewed."
        )
    else:
        executive_recommendation = (
            "Continue routine evidence monitoring and maintain periodic review documentation."
        )

    evidence_table = evidence_tracker_to_markdown_table(tracker_df)

    return f"""# TrustShield GRC Evidence Request Tracker Report

## Executive Summary

TrustShield GRC generated an evidence request tracker covering **{total_requests} evidence request(s)** across **{vendor_count} vendor(s)**.

This report converts vendor risk findings into practical evidence requests for follow-up, remediation tracking, audit readiness, and GRC documentation.

---

## Evidence Request Priority Summary

- **Critical Requests:** {critical_requests}
- **High Requests:** {high_requests}
- **Medium Requests:** {medium_requests}
- **Low Requests:** {low_requests}

---

## Vendors Requiring Follow-Up

{top_vendor_text}

---

## Executive Recommendation

{executive_recommendation}

---

## Evidence Request Tracker

{evidence_table}

---

## Consulting Use Case

This report can be used as a vendor follow-up tracker for compliance teams, security teams, audit readiness preparation, and third-party risk remediation workflows.

---

## Prototype Notice

This report was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate vendor risk analysis, evidence tracking, remediation planning, and Python/Streamlit automation.

---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.
"""



def generate_risk_acceptance_memo(tracker_df):
    """Generate a Risk Acceptance Memo for evidence requests marked as Risk Accepted."""
    accepted_df = tracker_df[tracker_df["Status"] == "Risk Accepted"].copy()

    if accepted_df.empty:
        return None

    accepted_count = len(accepted_df)
    vendor_count = accepted_df["Vendor"].nunique() if "Vendor" in accepted_df.columns else 0
    critical_count = len(accepted_df[accepted_df["Priority"] == "Critical"]) if "Priority" in accepted_df.columns else 0
    high_count = len(accepted_df[accepted_df["Priority"] == "High"]) if "Priority" in accepted_df.columns else 0

    def clean(value):
        return str(value).replace("\\n", " ").replace("|", "/").strip()

    memo_items = []

    for _, row in accepted_df.iterrows():
        memo_items.append(
            f"""### {clean(row.get('Vendor', 'Unknown Vendor'))} — {clean(row.get('Evidence Gap', 'Unknown Gap'))}

- **System / Service:** {clean(row.get('System / Service', 'Unknown System'))}
- **Risk Level:** {clean(row.get('Risk Level', 'Unknown'))}
- **Risk Score:** {clean(row.get('Risk Score', ''))}
- **Priority:** {clean(row.get('Priority', ''))}
- **Evidence Request:** {clean(row.get('Evidence Request', ''))}
- **Control Objective:** {clean(row.get('Control Objective', ''))}
- **Required Evidence:** {clean(row.get('Required Evidence', ''))}
- **Suggested Owner:** {clean(row.get('Suggested Owner', ''))}
- **Timeline:** {clean(row.get('Timeline', ''))}
- **Reviewer Notes:** {clean(row.get('Reviewer Notes', 'No notes provided.'))}

**Risk Acceptance Rationale:**  
The item above has been marked as risk accepted in the tracker. Formal acceptance should be reviewed and approved by the appropriate business owner, GRC owner, and security leadership before being treated as final.

**Recommended Follow-Up:**  
Document compensating controls, define an expiration or review date, and reassess the accepted risk during the next vendor review cycle.
"""
        )

    memo_body = "\\n---\\n".join(memo_items)

    return f"""# TrustShield GRC Risk Acceptance Memo

## Executive Summary

TrustShield GRC identified **{accepted_count} risk accepted item(s)** across **{vendor_count} vendor(s)**.

This memo is intended to document evidence gaps or vendor risk items that have been marked as **Risk Accepted** in the Evidence Request Tracker.

---

## Risk Acceptance Summary

- **Total Risk Accepted Items:** {accepted_count}
- **Vendors Involved:** {vendor_count}
- **Critical Priority Items:** {critical_count}
- **High Priority Items:** {high_count}

---

## Governance Note

Risk acceptance should not be treated as a passive decision. It should be reviewed, justified, approved, time-bound, and revisited periodically.

A mature risk acceptance process should include:

- Business justification
- Security or compliance review
- Compensating controls
- Named risk owner
- Review or expiration date
- Approval evidence
- Reassessment cadence

---

## Accepted Risk Items

{memo_body}

---

## Suggested Approval Fields

- **Business Owner:** __________________________
- **GRC / Compliance Owner:** __________________________
- **Security Reviewer:** __________________________
- **Approval Date:** __________________________
- **Review / Expiration Date:** __________________________

---

## Prototype Notice

This memo was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate vendor risk analysis, evidence tracking, risk acceptance documentation, and Python/Streamlit automation.

---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.
"""



def generate_critical_vendor_report_pack(batch_results, selected_levels=None):
    """Generate a consulting-style report pack focused on Critical and High risk vendors."""
    if selected_levels is None:
        selected_levels = ["Critical", "High"]

    focus_df = batch_results[batch_results["Risk Level"].isin(selected_levels)].copy()

    if focus_df.empty:
        return None

    focus_df = focus_df.sort_values(by="Risk Score", ascending=False)

    total_focus = len(focus_df)
    critical_count = len(focus_df[focus_df["Risk Level"] == "Critical"])
    high_count = len(focus_df[focus_df["Risk Level"] == "High"])
    average_focus_score = round(focus_df["Risk Score"].mean(), 2)

    def clean(value):
        return str(value).replace("\\n", " ").replace("|", "/").strip()

    executive_table_columns = [
        "Vendor",
        "System / Service",
        "Data Type",
        "Business Criticality",
        "Risk Score",
        "Risk Level",
        "Recommended Priority",
        "Evidence Gaps",
    ]

    available_columns = [col for col in executive_table_columns if col in focus_df.columns]

    header = "| " + " | ".join(available_columns) + " |"
    separator = "| " + " | ".join(["---"] * len(available_columns)) + " |"

    rows = []
    for _, row in focus_df.iterrows():
        rows.append("| " + " | ".join(clean(row[col]) for col in available_columns) + " |")

    focus_table = "\\n".join([header, separator] + rows)

    vendor_sections = []

    for _, row in focus_df.iterrows():
        gaps = clean(row.get("Evidence Gaps", "No major evidence gaps identified"))
        recommendations = clean(row.get("Recommended Actions", "Continue routine monitoring"))
        framework_mapping = clean(row.get("Framework Mapping", "No framework mappings identified"))

        if row.get("Risk Level") == "Critical":
            decision_guidance = (
                "Immediate review is recommended. Approval should remain conditional until priority evidence is received, "
                "reviewed, and either remediated or formally risk accepted."
            )
        else:
            decision_guidance = (
                "Remediation tracking is recommended before full approval. Evidence should be requested and reviewed "
                "within the target timeline."
            )

        vendor_sections.append(
            f"""## Vendor Review: {clean(row.get('Vendor', 'Unknown Vendor'))}

- **System / Service:** {clean(row.get('System / Service', 'Unknown System'))}
- **Data Type:** {clean(row.get('Data Type', 'Unknown'))}
- **Business Criticality:** {clean(row.get('Business Criticality', 'Unknown'))}
- **Risk Score:** {clean(row.get('Risk Score', ''))}/100
- **Risk Level:** {clean(row.get('Risk Level', 'Unknown'))}
- **Recommended Priority:** {clean(row.get('Recommended Priority', 'Unknown'))}

### Evidence Gaps

{gaps}

### Framework Mapping

{framework_mapping}

### Recommended Actions

{recommendations}

### Decision Guidance

{decision_guidance}
"""
        )

    vendor_sections_text = "\\n---\\n".join(vendor_sections)

    if critical_count > 0:
        executive_recommendation = (
            "Prioritize Critical vendors first. Assign owners, request evidence, track remediation, and document any risk acceptance decisions. "
            "Critical vendors should not receive unconditional approval without reviewed evidence or formal risk acceptance."
        )
    else:
        executive_recommendation = (
            "Prioritize High vendors for remediation tracking and evidence validation. Conditional approval may be appropriate with documented controls and follow-up timelines."
        )

    return f"""# TrustShield GRC Critical Vendor Report Pack

## Executive Summary

TrustShield GRC identified **{total_focus} vendor(s)** requiring priority review based on the selected risk levels: **{", ".join(selected_levels)}**.

- **Critical Vendors:** {critical_count}
- **High Vendors:** {high_count}
- **Average Focused Risk Score:** {average_focus_score}/100

This report pack is designed for executive review, vendor risk prioritization, remediation planning, audit readiness, and consulting follow-up.

---

## Scope

This report focuses on vendors classified as Critical or High risk from the uploaded vendor inventory. It is intended to help a GRC, security, compliance, or vendor risk team focus on the vendors that require immediate or near-term attention.

---

## Executive Recommendation

{executive_recommendation}

---

## Priority Vendor Summary

{focus_table}

---

{vendor_sections_text}

---

## Consulting Use Case

This report pack can support vendor risk meetings, remediation planning, evidence follow-up, audit preparation, risk acceptance discussions, and executive-level third-party risk reviews.

---

## Prototype Notice

This report was generated by TrustShield GRC, a cybersecurity GRC portfolio prototype created to demonstrate batch vendor risk analysis, critical vendor prioritization, evidence gap review, remediation planning, and Python/Streamlit automation.

---

## Ownership & Usage Notice

© 2026 América Trujillo. TrustShield GRC is the intellectual property of América Trujillo. This prototype is provided for demonstration and testing purposes only. It may not be sold, resold, redistributed, or used commercially without express written permission.

Do not enter confidential, client, or production data. Outputs generated by this prototype are for educational and portfolio demonstration purposes only and do not constitute legal, cybersecurity, audit, or compliance advice.
"""



def build_project_workspace_payload():
    """Build a portable project workspace payload for export/import."""
    return {
        "workspace_type": "TrustShield GRC Project Workspace",
        "workspace_version": "v2.8",
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": "América Trujillo",
        "project": "TrustShield GRC",
        "assessment_history": st.session_state.get("assessment_history", []),
        "evidence_tracker_state": st.session_state.get("evidence_tracker_state", []),
        "notice": (
            "This workspace is intended for prototype, portfolio, testing, and sanitized consulting workflow use only. "
            "Do not store confidential, client, regulated, or production data."
        ),
    }


def load_project_workspace_payload(payload):
    """Validate and load a TrustShield project workspace payload into session state."""
    if not isinstance(payload, dict):
        return False, "Workspace file must contain a JSON object."

    assessment_history = payload.get("assessment_history", [])
    evidence_tracker_state = payload.get("evidence_tracker_state", [])

    if not isinstance(assessment_history, list):
        return False, "Invalid workspace: assessment_history must be a list."

    if not isinstance(evidence_tracker_state, list):
        return False, "Invalid workspace: evidence_tracker_state must be a list."

    st.session_state.assessment_history = assessment_history
    st.session_state.evidence_tracker_state = evidence_tracker_state

    return True, "Workspace loaded successfully."


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

tab0, tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(
    [
        "🚀 Interactive Assessment",
        "📊 Dashboard",
        "🔎 Vendor Detail",
        "🧾 Report Generator",
        "🧠 Methodology",
        "📁 Assessment History",
        "📥 Batch CSV Upload",
        "📌 Evidence Request Tracker",
        "💾 Project Workspace"
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
        vendor = vendor.strip() or "Unnamed Vendor"
        system = system.strip() or "Unspecified System"

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

        history_record = {
            "Assessment Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Vendor": vendor,
            "System / Service": system,
            "Data Type": data_type,
            "Business Criticality": business_criticality,
            "Risk Score": score,
            "Risk Level": risk_level,
            "Recommended Priority": priority,
            "Evidence Gaps": ", ".join(gaps) if gaps else "No major evidence gaps identified",
            "Framework Mapping": ", ".join(mappings) if mappings else "No framework mappings identified",
            "Recommended Actions": " | ".join(recommendations) if recommendations else "Continue routine monitoring",
        }

        st.session_state.assessment_history.append(history_record)
        st.session_state.evidence_tracker_state = []

        st.success("Assessment completed and saved to session history.")

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



with tab5:
    st.header("Assessment History")

    st.write(
        "This section tracks vendor assessments completed during the current session. "
        "It allows a GRC analyst to review multiple assessments, compare risk levels, and export results for documentation."
    )

    st.warning(
        "Session-based storage: this history is temporary and will reset when the app session restarts. "
        "A future production version should store assessments in a secure database."
    )

    if st.session_state.assessment_history:
        history_df = pd.DataFrame(st.session_state.assessment_history)

        st.markdown("### Completed Assessments")
        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True
        )

        csv_data = history_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📤 Export Assessment History (.csv)",
            data=csv_data,
            file_name="trustshield_assessment_history.csv",
            mime="text/csv",
            use_container_width=True
        )

        col_clear, col_note = st.columns([1, 2])

        with col_clear:
            if st.button("Clear Session History", use_container_width=True):
                st.session_state.assessment_history = []
                st.rerun()

        with col_note:
            st.info(
                "Next product step: replace temporary session storage with a database so users can save, retrieve, and manage assessments over time."
            )

        st.markdown("### Risk Distribution")
        risk_counts = history_df["Risk Level"].value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]
        st.dataframe(risk_counts, use_container_width=True, hide_index=True)

    else:
        st.info(
            "No assessments have been saved yet. Run a vendor assessment in the Interactive Assessment tab to populate this history."
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



with tab6:
    st.header("Batch CSV Upload")

    st.write(
        "Upload a vendor inventory CSV to analyze multiple vendors at once. "
        "This is the next step toward using TrustShield as a practical consulting workflow for vendor risk prioritization."
    )

    st.warning(
        "Prototype notice: use fictional or sanitized data only. Do not upload confidential, client, or production vendor data."
    )

    st.markdown("### Download Sample Input Files")

    template_df = get_batch_template_df()
    template_csv = template_df.to_csv(index=False).encode("utf-8")

    rich_demo_df = get_rich_demo_vendor_inventory_df()
    rich_demo_csv = rich_demo_df.to_csv(index=False).encode("utf-8")

    invalid_demo_df = get_invalid_demo_vendor_inventory_df()
    invalid_demo_csv = invalid_demo_df.to_csv(index=False).encode("utf-8")

    d1, d2, d3 = st.columns(3)

    with d1:
        st.download_button(
            label="📄 Download Basic Vendor CSV Template",
            data=template_csv,
            file_name="trustshield_vendor_inventory_template.csv",
            mime="text/csv",
            use_container_width=True
        )

    with d2:
        st.download_button(
            label="🧪 Download Rich Demo Vendor Inventory",
            data=rich_demo_csv,
            file_name="trustshield_rich_demo_vendor_inventory.csv",
            mime="text/csv",
            use_container_width=True
        )

    with d3:
        st.download_button(
            label="⚠️ Download Invalid CSV Test File",
            data=invalid_demo_csv,
            file_name="trustshield_invalid_csv_test_file.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.info(
        "Use the basic template for clean input, the rich demo inventory for portfolio walkthroughs, "
        "and the invalid test file to demonstrate CSV validation and error handling."
    )

    uploaded_file = st.file_uploader(
        "Upload completed vendor inventory CSV",
        type=["csv"]
    )

    if uploaded_file is not None:
        try:
            uploaded_df = pd.read_csv(uploaded_file)

            st.markdown("### Uploaded Vendor Inventory Preview")
            st.dataframe(
                uploaded_df,
                use_container_width=True,
                hide_index=True
            )

            detected_type, detected_message = detect_uploaded_csv_type(uploaded_df)

            if detected_type != "vendor_inventory":
                st.error("Uploaded file is not a valid vendor inventory input file.")
                st.write(detected_message)

                st.markdown("### Required Vendor Inventory Columns")
                required_columns_df = pd.DataFrame({
                    "Required Column": get_required_batch_columns(),
                    "Purpose": [
                        "Vendor or third-party name",
                        "System, platform, or service provided by the vendor",
                        "Type of data handled by the vendor",
                        "Business importance of the vendor/service",
                        "Whether SOC 2 evidence is available",
                        "Whether MFA is implemented",
                        "Encryption status for sensitive data",
                        "Whether an incident response plan is available",
                        "Whether there is known vulnerability exposure",
                        "Last vendor risk review date in YYYY-MM-DD format",
                    ]
                })

                st.dataframe(
                    required_columns_df,
                    use_container_width=True,
                    hide_index=True
                )

                st.info(
                    "Download the Vendor CSV Template above, complete it, and upload that file here. "
                    "Do not upload exported reports, assessment history, batch results, evidence tracker files, or validation error files into this intake."
                )

                st.stop()

            st.success("CSV file type check passed. Vendor inventory detected.")

            standardized_df, validation_errors = validate_and_standardize_batch_dataframe(uploaded_df)

            if validation_errors:
                validation_df = pd.DataFrame(validation_errors)

                st.error(
                    "CSV validation failed. Please fix the issues below and upload the corrected file again."
                )

                st.markdown("### CSV Validation Errors")
                st.dataframe(
                    validation_df,
                    use_container_width=True,
                    hide_index=True
                )

                validation_csv = validation_df.to_csv(index=False).encode("utf-8")

                st.download_button(
                    label="📤 Export CSV Validation Errors (.csv)",
                    data=validation_csv,
                    file_name="trustshield_csv_validation_errors.csv",
                    mime="text/csv",
                    use_container_width=True
                )

                st.info(
                    "Tip: download the vendor CSV template and keep the column names exactly the same. "
                    "Use Yes/No values where required and dates in YYYY-MM-DD format."
                )

                st.stop()

            st.success("CSV validation passed. Batch analysis can proceed.")

            uploaded_df = standardized_df

            batch_results, missing_columns = analyze_batch_dataframe(uploaded_df)

            if missing_columns:
                st.error(
                    "The uploaded CSV is missing required columns: "
                    + ", ".join(missing_columns)
                )
                st.info(
                    "Download the template above and make sure your CSV includes all required columns."
                )
            else:
                st.success("Batch analysis completed.")

                st.markdown("### Batch Risk Prioritization Results")
                st.dataframe(
                    batch_results,
                    use_container_width=True,
                    hide_index=True
                )

                total_uploaded = len(batch_results)
                critical_count = len(batch_results[batch_results["Risk Level"] == "Critical"])
                high_count = len(batch_results[batch_results["Risk Level"] == "High"])
                average_score = round(batch_results["Risk Score"].mean(), 2)

                b1, b2, b3, b4 = st.columns(4)
                b1.metric("Vendors Analyzed", total_uploaded)
                b2.metric("Critical Risk", critical_count)
                b3.metric("High Risk", high_count)
                b4.metric("Average Risk Score", average_score)

                batch_csv = batch_results.to_csv(index=False).encode("utf-8")

                st.download_button(
                    label="📤 Export Batch Risk Results (.csv)",
                    data=batch_csv,
                    file_name="trustshield_batch_vendor_risk_results.csv",
                    mime="text/csv",
                    use_container_width=True
                )

                st.markdown("### Consolidated Executive Batch Report")
                st.write(
                    "Generate a consolidated executive report summarizing the uploaded vendor inventory, "
                    "risk distribution, highest-risk vendors, common evidence gaps, and remediation priorities."
                )

                batch_report = generate_batch_executive_report(batch_results)

                with st.expander("Preview Consolidated Executive Batch Report", expanded=False):
                    st.markdown(batch_report)

                st.download_button(
                    label="📥 Download Consolidated Executive Batch Report (.md)",
                    data=batch_report,
                    file_name="trustshield_consolidated_vendor_risk_report.md",
                    mime="text/markdown",
                    use_container_width=True
                )

                st.markdown("### Critical Vendor Report Pack")
                st.write(
                    "Generate a focused report pack for vendors that require priority review. "
                    "This is useful for executive review, remediation planning, and consulting follow-up."
                )

                selected_focus_levels = st.multiselect(
                    "Select risk levels to include in the focused report pack",
                    options=["Critical", "High", "Medium", "Low"],
                    default=["Critical", "High"]
                )

                critical_vendor_pack = generate_critical_vendor_report_pack(
                    batch_results,
                    selected_focus_levels
                )

                if critical_vendor_pack:
                    with st.expander("Preview Critical Vendor Report Pack", expanded=False):
                        st.markdown(critical_vendor_pack)

                    st.download_button(
                        label="📥 Download Critical Vendor Report Pack (.md)",
                        data=critical_vendor_pack,
                        file_name="trustshield_critical_vendor_report_pack.md",
                        mime="text/markdown",
                        use_container_width=True
                    )
                else:
                    st.info(
                        "No vendors match the selected risk levels. Adjust the selected levels or upload a different vendor inventory."
                    )

                if st.button("Add Batch Results to Assessment History", use_container_width=True):
                    st.session_state.assessment_history.extend(
                        batch_results.to_dict("records")
                    )
                    st.session_state.evidence_tracker_state = []
                    st.success("Batch results added to Assessment History.")

                st.info(
                    "Next product step: generate individual reports for each vendor in the uploaded batch."
                )

        except Exception as e:
            st.error("Unable to process the uploaded CSV.")
            st.code(str(e))





with tab7:
    st.header("Evidence Request Tracker")

    st.write(
        "This tracker converts assessment findings into evidence requests that can be used for vendor follow-up, "
        "audit readiness, remediation tracking, and consulting deliverables."
    )

    st.warning(
        "Session-based tracker: this table is generated from the current Assessment History only. "
        "A production version should store evidence requests in a secure database with assigned owners and status tracking."
    )

    if st.session_state.assessment_history:
        if st.session_state.evidence_tracker_state:
            tracker_df = pd.DataFrame(st.session_state.evidence_tracker_state)
        else:
            tracker_df = generate_evidence_request_tracker(st.session_state.assessment_history)

        st.markdown("### Evidence Requests Generated from Assessment History")
        st.markdown("#### Evidence Status Workflow")

        st.write(
            "Update the status and reviewer notes for each evidence request. "
            "All other fields remain locked to preserve the integrity of the assessment output."
        )

        status_options = [
            "Open",
            "Requested",
            "Received",
            "Under Review",
            "Accepted",
            "Rejected",
            "Risk Accepted",
        ]

        if "Reviewer Notes" not in tracker_df.columns:
            tracker_df["Reviewer Notes"] = ""

        tracker_df["Status"] = tracker_df["Status"].apply(
            lambda status: status if status in status_options else "Open"
        )

        editable_columns = ["Status", "Reviewer Notes"]
        disabled_columns = [column for column in tracker_df.columns if column not in editable_columns]

        edited_tracker_df = st.data_editor(
            tracker_df,
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            disabled=disabled_columns,
            column_config={
                "Status": st.column_config.SelectboxColumn(
                    "Status",
                    options=status_options,
                    required=True,
                    help="Track the current review status of the evidence request."
                ),
                "Reviewer Notes": st.column_config.TextColumn(
                    "Reviewer Notes",
                    help="Add reviewer notes, follow-up details, or risk acceptance comments."
                ),
            },
            key="evidence_status_editor"
        )

        st.session_state.evidence_tracker_state = edited_tracker_df.to_dict("records")

        total_requests = len(edited_tracker_df)
        critical_requests = len(edited_tracker_df[edited_tracker_df["Priority"] == "Critical"])
        active_requests = len(
            edited_tracker_df[
                edited_tracker_df["Status"].isin(["Open", "Requested", "Received", "Under Review"])
            ]
        )
        completed_requests = len(edited_tracker_df[edited_tracker_df["Status"] == "Accepted"])
        risk_accepted_requests = len(edited_tracker_df[edited_tracker_df["Status"] == "Risk Accepted"])

        e1, e2, e3, e4, e5 = st.columns(5)
        e1.metric("Evidence Requests", total_requests)
        e2.metric("Critical Requests", critical_requests)
        e3.metric("Active Items", active_requests)
        e4.metric("Accepted", completed_requests)
        e5.metric("Risk Accepted", risk_accepted_requests)

        tracker_csv = edited_tracker_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📤 Export Updated Evidence Tracker (.csv)",
            data=tracker_csv,
            file_name="trustshield_updated_evidence_request_tracker.csv",
            mime="text/csv",
            use_container_width=True
        )

        evidence_report = generate_evidence_tracker_report(edited_tracker_df)

        st.markdown("### Evidence Request Executive Report")
        st.write(
            "Generate a readable executive report summarizing evidence requests, priority levels, "
            "vendor follow-up needs, status updates, reviewer notes, and consulting recommendations."
        )

        with st.expander("Preview Evidence Request Executive Report", expanded=False):
            st.markdown(evidence_report)

        st.download_button(
            label="📥 Download Evidence Request Executive Report (.md)",
            data=evidence_report,
            file_name="trustshield_evidence_request_tracker_report.md",
            mime="text/markdown",
            use_container_width=True
        )

        risk_acceptance_memo = generate_risk_acceptance_memo(edited_tracker_df)

        st.markdown("### Risk Acceptance Memo")
        st.write(
            "If any evidence request is marked as **Risk Accepted**, TrustShield can generate a governance memo "
            "documenting the accepted risk, suggested approval fields, reviewer notes, and follow-up expectations."
        )

        if risk_acceptance_memo:
            with st.expander("Preview Risk Acceptance Memo", expanded=False):
                st.markdown(risk_acceptance_memo)

            st.download_button(
                label="📥 Download Risk Acceptance Memo (.md)",
                data=risk_acceptance_memo,
                file_name="trustshield_risk_acceptance_memo.md",
                mime="text/markdown",
                use_container_width=True
            )
        else:
            st.info(
                "No items are currently marked as Risk Accepted. Change one or more evidence request statuses to Risk Accepted to generate this memo."
            )

        st.info(
            "Consulting use case: this workflow can be used to track vendor evidence requests, "
            "document review status, record reviewer notes, and support audit preparation workflows."
        )

        # Evidence Status Workflow

    else:
        st.info(
            "No assessment history found. Run an individual assessment or upload a batch CSV and add results to Assessment History first."
        )





with tab8:
    st.header("Project Workspace")

    st.write(
        "Export or import a TrustShield workspace so assessment history, evidence requests, status updates, "
        "reviewer notes, and risk acceptance decisions can be saved and resumed later."
    )

    st.warning(
        "Prototype storage model: this workspace export is a portable JSON file. "
        "For production use, this should eventually be replaced with secure database storage, authentication, access control, and audit logging."
    )

    current_history_count = len(st.session_state.get("assessment_history", []))
    current_tracker_count = len(st.session_state.get("evidence_tracker_state", []))

    w1, w2 = st.columns(2)
    w1.metric("Saved Assessments in Session", current_history_count)
    w2.metric("Saved Evidence Tracker Rows", current_tracker_count)

    workspace_payload = build_project_workspace_payload()
    workspace_json = json.dumps(workspace_payload, indent=2, ensure_ascii=False, default=str).encode("utf-8")

    st.markdown("### Export Workspace")

    st.download_button(
        label="💾 Export Project Workspace (.json)",
        data=workspace_json,
        file_name="trustshield_project_workspace.json",
        mime="application/json",
        use_container_width=True
    )

    st.markdown("### Import Workspace")

    uploaded_workspace = st.file_uploader(
        "Upload TrustShield project workspace JSON",
        type=["json"],
        key="project_workspace_importer"
    )

    if uploaded_workspace is not None:
        try:
            payload = json.loads(uploaded_workspace.getvalue().decode("utf-8"))

            st.markdown("#### Workspace Preview")
            st.write(f"**Workspace Type:** {payload.get('workspace_type', 'Unknown')}")
            st.write(f"**Workspace Version:** {payload.get('workspace_version', 'Unknown')}")
            st.write(f"**Exported At:** {payload.get('exported_at', 'Unknown')}")
            st.write(f"**Assessment Records:** {len(payload.get('assessment_history', []))}")
            st.write(f"**Evidence Tracker Rows:** {len(payload.get('evidence_tracker_state', []))}")

            if st.button("Load Project Workspace", use_container_width=True):
                success, message = load_project_workspace_payload(payload)

                if success:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)

        except Exception as e:
            st.error("Unable to read the uploaded workspace JSON.")
            st.code(str(e))

    st.info(
        "Recommended workflow: run assessments, add batch results to Assessment History, update Evidence Tracker statuses and notes, "
        "generate memos/reports, then export the Project Workspace before closing the session."
    )



st.divider()

st.caption(
    "TrustShield GRC — Created by América Trujillo | GitHub: @ammetb18-create | Cybersecurity GRC Portfolio"
)
