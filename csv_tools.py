from datetime import date
import pandas as pd


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
