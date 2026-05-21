import pandas as pd
from datetime import datetime

TODAY = datetime.today()

CRITICALITY_SCORE = {
    "High": 30,
    "Medium": 20,
    "Low": 10
}

DATA_SENSITIVITY_SCORE = {
    "Financial Data": 25,
    "PII": 25,
    "PHI": 25,
    "Confidential Data": 25,
    "Customer Inputs": 20,
    "Customer Emails": 15,
    "Internal Data": 10,
    "Public Data": 5
}

def normalize(value):
    return str(value).strip()

def calculate_review_age_days(review_date):
    try:
        parsed_date = datetime.strptime(str(review_date), "%Y-%m-%d")
        return (TODAY - parsed_date).days
    except ValueError:
        return 999

def identify_gaps(row):
    gaps = []

    if normalize(row["Has_SOC2"]) != "Yes":
        gaps.append("Missing SOC 2")

    if normalize(row["Has_MFA"]) != "Yes":
        gaps.append("Missing MFA")

    if normalize(row["Encryption"]) == "No":
        gaps.append("Missing Encryption")
    elif normalize(row["Encryption"]) == "Unknown":
        gaps.append("Unknown Encryption")

    if normalize(row["Incident_Response_Plan"]) != "Yes":
        gaps.append("Missing Incident Response Plan")

    if normalize(row["Known_Vulnerability"]) == "Yes":
        gaps.append("Known Vulnerability")

    review_age = calculate_review_age_days(row["Last_Risk_Review"])
    if review_age > 180:
        gaps.append("Stale Risk Review")

    return gaps

def score_vendor(row):
    score = 0

    score += CRITICALITY_SCORE.get(normalize(row["Business_Criticality"]), 10)
    score += DATA_SENSITIVITY_SCORE.get(normalize(row["Data_Type"]), 10)

    gaps = identify_gaps(row)

    for gap in gaps:
        if gap == "Known Vulnerability":
            score += 25
        elif gap in ["Missing SOC 2", "Missing MFA", "Missing Encryption", "Missing Incident Response Plan"]:
            score += 15
        elif gap in ["Unknown Encryption", "Stale Risk Review"]:
            score += 10

    return min(score, 100)

def classify_risk(score):
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 35:
        return "Medium"
    return "Low"

def prioritize_action(risk_level):
    if risk_level == "Critical":
        return "Immediate review required"
    elif risk_level == "High":
        return "Review within 30 days"
    elif risk_level == "Medium":
        return "Monitor and schedule review"
    return "Acceptable with routine monitoring"

def analyze_vendors(vendor_file="data/vendor_inventory.csv", control_file="data/control_catalog.csv"):
    vendors = pd.read_csv(vendor_file)
    controls = pd.read_csv(control_file)

    vendors["Evidence_Gaps"] = vendors.apply(lambda row: identify_gaps(row), axis=1)
    vendors["Risk_Score"] = vendors.apply(lambda row: score_vendor(row), axis=1)
    vendors["Risk_Level"] = vendors["Risk_Score"].apply(classify_risk)
    vendors["Recommended_Priority"] = vendors["Risk_Level"].apply(prioritize_action)

    gap_mapping = controls.set_index("Gap").to_dict("index")

    def map_frameworks(gaps):
        mapped = []
        for gap in gaps:
            if gap in gap_mapping:
                mapped.append(f"{gap_mapping[gap]['Framework']} - {gap_mapping[gap]['Control']}")
        return mapped

    def map_recommendations(gaps):
        recs = []
        for gap in gaps:
            if gap in gap_mapping:
                recs.append(gap_mapping[gap]["Recommendation"])
        return recs

    vendors["Framework_Mapping"] = vendors["Evidence_Gaps"].apply(map_frameworks)
    vendors["Recommendations"] = vendors["Evidence_Gaps"].apply(map_recommendations)

    return vendors.sort_values(by="Risk_Score", ascending=False)

if __name__ == "__main__":
    analyzed = analyze_vendors()
    print(analyzed[["Vendor", "System", "Risk_Score", "Risk_Level", "Recommended_Priority"]])
