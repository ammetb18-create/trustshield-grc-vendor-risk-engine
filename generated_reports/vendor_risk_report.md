# TrustShield GRC — Vendor Risk Report

## Executive Summary

- Total vendors reviewed: 8
- Critical-risk vendors: 4
- High-risk vendors: 1
- Vendors missing SOC 2 evidence: 3
- Vendors missing MFA: 3
- Vendors with known vulnerability exposure: 2

## Prioritized Vendor Risk Findings

### Unknown CRM — Critical Risk
- System: Customer Management
- Data Type: PII
- Business Criticality: High
- Risk Score: 100/100
- Recommended Priority: Immediate review required
- Evidence Gaps:
  - Missing SOC 2
  - Missing MFA
  - Unknown Encryption
  - Missing Incident Response Plan
  - Known Vulnerability
  - Stale Risk Review
- Framework Mapping:
  - SOC 2 - Security
  - NIST CSF 2.0 - PR.AA
  - NIST CSF 2.0 - PR.DS
  - NIST SP 800-53 - IR Family
  - CISA KEV - Remediation Priority
  - NIST CSF 2.0 - GV.RM
- Recommended Actions:
  - Request a SOC 2 Type II report or equivalent assurance documentation.
  - Implement multi-factor authentication for user and privileged accounts.
  - Request encryption documentation and data protection controls.
  - Create and test an incident response plan with vendor escalation procedures.
  - Prioritize remediation validation or require documented compensating controls.
  - Perform updated vendor risk review and document risk acceptance or remediation plan.

### Legacy HR Platform — Critical Risk
- System: Human Resources
- Data Type: PII
- Business Criticality: High
- Risk Score: 100/100
- Recommended Priority: Immediate review required
- Evidence Gaps:
  - Missing SOC 2
  - Missing MFA
  - Missing Encryption
  - Missing Incident Response Plan
  - Known Vulnerability
  - Stale Risk Review
- Framework Mapping:
  - SOC 2 - Security
  - NIST CSF 2.0 - PR.AA
  - NIST CSF 2.0 - PR.DS
  - NIST SP 800-53 - IR Family
  - CISA KEV - Remediation Priority
  - NIST CSF 2.0 - GV.RM
- Recommended Actions:
  - Request a SOC 2 Type II report or equivalent assurance documentation.
  - Implement multi-factor authentication for user and privileged accounts.
  - Validate encryption at rest and in transit for sensitive data.
  - Create and test an incident response plan with vendor escalation procedures.
  - Prioritize remediation validation or require documented compensating controls.
  - Perform updated vendor risk review and document risk acceptance or remediation plan.

### Small Marketing Tool — Critical Risk
- System: Email Campaigns
- Data Type: Customer Emails
- Business Criticality: Low
- Risk Score: 90/100
- Recommended Priority: Immediate review required
- Evidence Gaps:
  - Missing SOC 2
  - Missing MFA
  - Unknown Encryption
  - Missing Incident Response Plan
  - Stale Risk Review
- Framework Mapping:
  - SOC 2 - Security
  - NIST CSF 2.0 - PR.AA
  - NIST CSF 2.0 - PR.DS
  - NIST SP 800-53 - IR Family
  - NIST CSF 2.0 - GV.RM
- Recommended Actions:
  - Request a SOC 2 Type II report or equivalent assurance documentation.
  - Implement multi-factor authentication for user and privileged accounts.
  - Request encryption documentation and data protection controls.
  - Create and test an incident response plan with vendor escalation procedures.
  - Perform updated vendor risk review and document risk acceptance or remediation plan.

### Cloud Backup Service — Critical Risk
- System: Backup Storage
- Data Type: Confidential Data
- Business Criticality: High
- Risk Score: 80/100
- Recommended Priority: Immediate review required
- Evidence Gaps:
  - Missing Incident Response Plan
  - Stale Risk Review
- Framework Mapping:
  - NIST SP 800-53 - IR Family
  - NIST CSF 2.0 - GV.RM
- Recommended Actions:
  - Create and test an incident response plan with vendor escalation procedures.
  - Perform updated vendor risk review and document risk acceptance or remediation plan.

### Dropbox — High Risk
- System: Cloud Storage
- Data Type: PII
- Business Criticality: Medium
- Risk Score: 70/100
- Recommended Priority: Review within 30 days
- Evidence Gaps:
  - Missing Incident Response Plan
  - Stale Risk Review
- Framework Mapping:
  - NIST SP 800-53 - IR Family
  - NIST CSF 2.0 - GV.RM
- Recommended Actions:
  - Create and test an incident response plan with vendor escalation procedures.
  - Perform updated vendor risk review and document risk acceptance or remediation plan.

### Stripe — Medium Risk
- System: Payment Processing
- Data Type: Financial Data
- Business Criticality: High
- Risk Score: 55/100
- Recommended Priority: Monitor and schedule review
- Evidence Gaps:
  - No major evidence gaps identified
- Framework Mapping:
  - No major control gaps mapped
- Recommended Actions:
  - Continue routine monitoring

### OpenAI API — Medium Risk
- System: AI Processing
- Data Type: Customer Inputs
- Business Criticality: Medium
- Risk Score: 40/100
- Recommended Priority: Monitor and schedule review
- Evidence Gaps:
  - No major evidence gaps identified
- Framework Mapping:
  - No major control gaps mapped
- Recommended Actions:
  - Continue routine monitoring

### Slack — Low Risk
- System: Internal Communications
- Data Type: Internal Data
- Business Criticality: Medium
- Risk Score: 30/100
- Recommended Priority: Acceptable with routine monitoring
- Evidence Gaps:
  - No major evidence gaps identified
- Framework Mapping:
  - No major control gaps mapped
- Recommended Actions:
  - Continue routine monitoring

## Portfolio Note

This report demonstrates a practical GRC workflow combining vendor risk analysis, compliance evidence review, control mapping, and Python-based automation.
