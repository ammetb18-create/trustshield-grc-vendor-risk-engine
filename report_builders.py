from datetime import datetime

import pandas as pd


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
