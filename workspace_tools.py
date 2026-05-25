from datetime import datetime


def build_project_workspace_payload(assessment_history, evidence_tracker_state):
    """Build a portable project workspace payload for export/import."""
    return {
        "workspace_type": "TrustShield GRC Project Workspace",
        "workspace_version": "v2.8",
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": "América Trujillo",
        "project": "TrustShield GRC",
        "assessment_history": assessment_history,
        "evidence_tracker_state": evidence_tracker_state,
        "notice": (
            "This workspace is intended for prototype, portfolio, testing, and sanitized consulting workflow use only. "
            "Do not store confidential, client, regulated, or production data."
        ),
    }


def validate_project_workspace_payload(payload):
    """Validate a TrustShield project workspace payload before loading it."""
    if not isinstance(payload, dict):
        return False, "Workspace file must contain a JSON object.", [], []

    assessment_history = payload.get("assessment_history", [])
    evidence_tracker_state = payload.get("evidence_tracker_state", [])

    if not isinstance(assessment_history, list):
        return False, "Invalid workspace: assessment_history must be a list.", [], []

    if not isinstance(evidence_tracker_state, list):
        return False, "Invalid workspace: evidence_tracker_state must be a list.", [], []

    return True, "Workspace loaded successfully.", assessment_history, evidence_tracker_state
