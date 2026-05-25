from pathlib import Path
import tempfile
from datetime import datetime, timedelta

import pandas as pd

from risk_engine import (
    identify_gaps,
    score_vendor,
    classify_risk,
    prioritize_action,
    analyze_vendors,
)
from report_generator import generate_markdown_report


APP_FILE = Path("app.py")


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def recent_date(days_ago=30):
    return (datetime.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def stale_date(days_ago=365):
    return (datetime.today() - timedelta(days=days_ago)).strftime("%Y-%m-%d")


def build_control_catalog_df():
    return pd.DataFrame([
        {
            "Gap": "Missing SOC 2",
            "Framework": "SOC 2",
            "Control": "Security",
            "Recommendation": "Request a SOC 2 Type II report or equivalent assurance documentation.",
        },
        {
            "Gap": "Missing MFA",
            "Framework": "NIST CSF 2.0",
            "Control": "PR.AA",
            "Recommendation": "Implement multi-factor authentication for user and privileged accounts.",
        },
        {
            "Gap": "Missing Encryption",
            "Framework": "NIST CSF 2.0",
            "Control": "PR.DS",
            "Recommendation": "Request encryption documentation and data protection controls.",
        },
        {
            "Gap": "Unknown Encryption",
            "Framework": "NIST CSF 2.0",
            "Control": "PR.DS",
            "Recommendation": "Request encryption documentation and data protection controls.",
        },
        {
            "Gap": "Missing Incident Response Plan",
            "Framework": "NIST SP 800-53",
            "Control": "IR Family",
            "Recommendation": "Create and test an incident response plan with vendor escalation procedures.",
        },
        {
            "Gap": "Known Vulnerability",
            "Framework": "CISA KEV",
            "Control": "Remediation Priority",
            "Recommendation": "Prioritize remediation validation or require documented compensating controls.",
        },
        {
            "Gap": "Stale Risk Review",
            "Framework": "NIST CSF 2.0",
            "Control": "GV.RM",
            "Recommendation": "Perform updated vendor risk review and document risk acceptance or remediation plan.",
        },
    ])


def build_rich_demo_inventory_df():
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
            "Last_Risk_Review": stale_date(),
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
            "Last_Risk_Review": recent_date(),
        },
        {
            "Vendor": "PayFlow Gateway",
            "System": "Payment processing API",
            "Data_Type": "Financial Data",
            "Business_Criticality": "High",
            "Has_SOC2": "Yes",
            "Has_MFA": "No",
            "Encryption": "Yes",
            "Incident_Response_Plan": "No",
            "Known_Vulnerability": "No",
            "Last_Risk_Review": recent_date(60),
        },
        {
            "Vendor": "MediClaims Portal",
            "System": "Healthcare claims intake platform",
            "Data_Type": "PHI",
            "Business_Criticality": "High",
            "Has_SOC2": "No",
            "Has_MFA": "No",
            "Encryption": "No",
            "Incident_Response_Plan": "No",
            "Known_Vulnerability": "Yes",
            "Last_Risk_Review": stale_date(),
        },
        {
            "Vendor": "PublicForms Lite",
            "System": "Public website form builder",
            "Data_Type": "Public Data",
            "Business_Criticality": "Low",
            "Has_SOC2": "Yes",
            "Has_MFA": "Yes",
            "Encryption": "Yes",
            "Incident_Response_Plan": "Yes",
            "Known_Vulnerability": "No",
            "Last_Risk_Review": recent_date(),
        },
    ])


def test_low_risk_vendor():
    row = pd.Series({
        "Vendor": "PublicForms Lite",
        "System": "Public website form builder",
        "Data_Type": "Public Data",
        "Business_Criticality": "Low",
        "Has_SOC2": "Yes",
        "Has_MFA": "Yes",
        "Encryption": "Yes",
        "Incident_Response_Plan": "Yes",
        "Known_Vulnerability": "No",
        "Last_Risk_Review": recent_date(),
    })

    gaps = identify_gaps(row)
    score = score_vendor(row)
    level = classify_risk(score)

    assert_true(score <= 35, f"Expected low score, got {score}")
    assert_true(level == "Low", f"Expected Low risk, got {level}")
    assert_true(gaps == [], f"Expected no major gaps, got {gaps}")


def test_critical_risk_vendor():
    row = pd.Series({
        "Vendor": "MediClaims Portal",
        "System": "Healthcare claims intake platform",
        "Data_Type": "PHI",
        "Business_Criticality": "High",
        "Has_SOC2": "No",
        "Has_MFA": "No",
        "Encryption": "No",
        "Incident_Response_Plan": "No",
        "Known_Vulnerability": "Yes",
        "Last_Risk_Review": stale_date(),
    })

    gaps = identify_gaps(row)
    score = score_vendor(row)
    level = classify_risk(score)
    priority = prioritize_action(level)

    expected_gaps = {
        "Missing SOC 2",
        "Missing MFA",
        "Missing Encryption",
        "Missing Incident Response Plan",
        "Known Vulnerability",
        "Stale Risk Review",
    }

    assert_true(expected_gaps.issubset(set(gaps)), f"Missing expected gaps. Got: {gaps}")
    assert_true(score == 100, f"Expected capped score of 100, got {score}")
    assert_true(level == "Critical", f"Expected Critical risk, got {level}")
    assert_true(priority == "Immediate review required", f"Unexpected priority: {priority}")


def test_risk_classification_boundaries():
    cases = [
        (20, "Low"),
        (35, "Medium"),
        (60, "High"),
        (80, "Critical"),
        (100, "Critical"),
    ]

    for score, expected in cases:
        actual = classify_risk(score)
        assert_true(actual == expected, f"Score {score}: expected {expected}, got {actual}")


def test_default_vendor_inventory_analysis():
    df = analyze_vendors()

    assert_true(not df.empty, "analyze_vendors returned an empty dataframe")
    assert_true("Risk_Score" in df.columns, "Missing Risk_Score column")
    assert_true("Risk_Level" in df.columns, "Missing Risk_Level column")
    assert_true("Evidence_Gaps" in df.columns, "Missing Evidence_Gaps column")
    assert_true(df["Risk_Score"].between(0, 100).all(), "Risk scores must be between 0 and 100")


def test_rich_demo_inventory_batch_analysis():
    vendors = build_rich_demo_inventory_df()
    controls = build_control_catalog_df()

    with tempfile.TemporaryDirectory() as tmpdir:
        vendor_path = Path(tmpdir) / "vendors.csv"
        control_path = Path(tmpdir) / "controls.csv"

        vendors.to_csv(vendor_path, index=False)
        controls.to_csv(control_path, index=False)

        analyzed = analyze_vendors(vendor_file=vendor_path, control_file=control_path)

    assert_true(len(analyzed) == len(vendors), "Rich demo inventory row count mismatch")
    assert_true(analyzed.iloc[0]["Risk_Score"] >= analyzed.iloc[-1]["Risk_Score"], "Vendors should be sorted by risk score")
    assert_true((analyzed["Risk_Level"] == "Critical").any(), "Rich demo should include at least one Critical vendor")
    assert_true((analyzed["Risk_Level"] == "Low").any(), "Rich demo should include at least one Low vendor")
    assert_true("Framework_Mapping" in analyzed.columns, "Missing Framework_Mapping column")
    assert_true("Recommendations" in analyzed.columns, "Missing Recommendations column")


def test_static_report_generation():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "vendor_risk_report.md"
        generated_path = generate_markdown_report(output_path=str(output_path))
        report_text = Path(generated_path).read_text(encoding="utf-8")

    assert_true("# TrustShield GRC" in report_text, "Report title missing")
    assert_true("Executive Summary" in report_text, "Executive Summary missing")
    assert_true("Ownership & Usage Notice" in report_text, "Ownership notice missing")


def test_app_feature_surface_present():
    assert_true(APP_FILE.exists(), "app.py not found")
    app_text = APP_FILE.read_text(encoding="utf-8")

    required_features = [
        "get_rich_demo_vendor_inventory_df",
        "get_invalid_demo_vendor_inventory_df",
        "detect_uploaded_csv_type",
        "validate_and_standardize_batch_dataframe",
        "generate_batch_executive_report",
        "generate_evidence_request_tracker",
        "generate_evidence_tracker_report",
        "generate_risk_acceptance_memo",
        "generate_critical_vendor_report_pack",
        "build_project_workspace_payload",
        "load_project_workspace_payload",
        "Project Workspace",
        "Evidence Status Workflow",
        "Risk Acceptance Memo",
        "Critical Vendor Report Pack",
    ]

    missing = [feature for feature in required_features if feature not in app_text]
    assert_true(not missing, f"Missing expected app features: {missing}")


def test_app_does_not_require_tabulate_for_markdown_tables():
    app_text = APP_FILE.read_text(encoding="utf-8")

    assert_true("to_markdown(" not in app_text, "app.py should not rely on pandas.to_markdown because it requires tabulate")
    assert_true("dataframe_to_markdown_table" in app_text, "Expected custom dataframe_to_markdown_table helper")


def test_workspace_json_structure_expected_keys():
    app_text = APP_FILE.read_text(encoding="utf-8")

    expected_keys = [
        "workspace_type",
        "workspace_version",
        "exported_at",
        "assessment_history",
        "evidence_tracker_state",
    ]

    missing = [key for key in expected_keys if key not in app_text]
    assert_true(not missing, f"Workspace payload missing expected keys: {missing}")


def run_quality_checks():
    checks = [
        ("Low-risk vendor scoring", test_low_risk_vendor),
        ("Critical-risk vendor scoring", test_critical_risk_vendor),
        ("Risk classification boundaries", test_risk_classification_boundaries),
        ("Default vendor inventory analysis", test_default_vendor_inventory_analysis),
        ("Rich demo inventory batch analysis", test_rich_demo_inventory_batch_analysis),
        ("Static report generation", test_static_report_generation),
        ("App feature surface present", test_app_feature_surface_present),
        ("No tabulate dependency for markdown tables", test_app_does_not_require_tabulate_for_markdown_tables),
        ("Workspace JSON structure", test_workspace_json_structure_expected_keys),
    ]

    print("TrustShield GRC Quality Checks")
    print("=" * 40)

    for name, check in checks:
        check()
        print(f"✅ {name}")

    print("=" * 40)
    print("All TrustShield quality checks passed.")


if __name__ == "__main__":
    run_quality_checks()
