from datetime import datetime

import pandas as pd

from csv_tools import normalize_batch_value
from risk_engine import (
    identify_gaps,
    score_vendor,
    classify_risk,
    prioritize_action,
)


def load_control_catalog(control_file="data/control_catalog.csv"):
    """Load the control catalog used for framework mapping and recommendations."""
    try:
        controls = pd.read_csv(control_file)
        return controls.set_index("Gap").to_dict("index")
    except Exception:
        return {}


def map_frameworks_and_recommendations(gaps, control_file="data/control_catalog.csv"):
    """Map evidence gaps to frameworks and recommended remediation actions."""
    gap_mapping = load_control_catalog(control_file)
    mappings = []
    recommendations = []

    for gap in gaps:
        if gap in gap_mapping:
            mappings.append(f"{gap_mapping[gap]['Framework']} - {gap_mapping[gap]['Control']}")
            recommendations.append(gap_mapping[gap]["Recommendation"])

    return mappings, recommendations


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


def analyze_batch_dataframe(uploaded_df, control_file="data/control_catalog.csv"):
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
        mappings, recommendations = map_frameworks_and_recommendations(gaps, control_file=control_file)

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
