# TrustShield GRC — Vendor Risk & Evidence Engine

## Overview

TrustShield GRC is a Python and Streamlit-based cybersecurity governance, risk, and compliance tool designed to evaluate vendor cybersecurity risk, identify missing compliance evidence, map control gaps to security frameworks, and generate executive-style risk reports.

This project simulates a real-world GRC workflow used by cybersecurity, compliance, vendor risk, and audit readiness teams.

## Problem

Organizations often rely on third-party vendors, SaaS platforms, cloud tools, payment processors, and AI-enabled systems to manage sensitive business operations. However, many teams lack a structured way to quickly identify:

- Which vendors create the highest cybersecurity risk
- Which controls are missing or weak
- Which compliance evidence is unavailable
- Which vendors require immediate review
- How findings map to recognized security frameworks

Without a clear risk and evidence review process, organizations may face audit delays, data exposure, vendor risk, and compliance gaps.

## Solution

TrustShield GRC evaluates vendor and system risk using structured input data and produces a prioritized risk analysis. The tool calculates risk scores, identifies missing security evidence, maps findings to cybersecurity frameworks, and generates a report that can support audit readiness and remediation planning.

## Key Features

- Vendor and system risk scoring
- Missing evidence detection
- Control gap analysis
- Risk classification: Low, Medium, High, Critical
- Framework mapping for GRC documentation
- Executive-style risk report generation
- Streamlit dashboard for visual review
- CSV-based input for easy testing and customization

## Use Case

This tool can be used to simulate how a GRC analyst, cybersecurity risk analyst, compliance analyst, or vendor risk analyst may review third-party vendors and internal systems.

Example scenarios include:

- Reviewing vendors before onboarding
- Preparing evidence for an audit
- Identifying missing SOC 2, MFA, encryption, or incident response documentation
- Prioritizing high-risk vendors
- Supporting cybersecurity governance workflows

## Tech Stack

- Python
- Pandas
- Streamlit
- CSV data processing
- Markdown report generation

## Status

In development.
