import pandas as pd


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
