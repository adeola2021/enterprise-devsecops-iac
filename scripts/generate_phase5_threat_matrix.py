#!/usr/bin/env python3

import csv
import json
from pathlib import Path

source = Path("reports/pytm-threat-model.json")
destination = Path("reports/phase5/threat-control-matrix.csv")

data = json.loads(source.read_text())
findings = data.get("findings", [])

metadata_fields = [
    "Control Owner", "Implementation Status", "Verification Status",
    "Control Classification", "OPA Policy Reference",
    "AWS Security Hub Control Reference", "Control Coverage Assessment",
    "Required Remediation Action", "Supporting API Gateway Boundary Control",
]
existing_metadata = {}

if destination.exists():
    with destination.open(newline="", encoding="utf-8-sig") as old_file:
        for old_row in csv.DictReader(old_file):
            existing_metadata[str(old_row.get("Finding ID", ""))] = {
                field: old_row.get(field, "") for field in metadata_fields
            }

control_mapping = {
    "INP05": (
        "Parameterized SQL queries; input validation; least-privilege DB access",
        "Application security / Semgrep / DAST",
        "Review query implementation and perform SQL injection testing",
    ),
    "HA01": (
        "Canonical path validation; restrict filesystem access",
        "Application security / Semgrep / DAST",
        "Perform path traversal tests and review filesystem permissions",
    ),
    "AC06": (
        "Validate uploaded files; malware scanning; isolated storage",
        "Application security / Malware scanning",
        "Test malicious file upload handling and storage restrictions",
    ),
    "SC02": (
        "Context-aware output encoding; content security policy",
        "Application security / Semgrep / DAST",
        "Perform XSS testing and inspect output encoding",
    ),
    "AC17": (
        "Secure session management; token rotation and expiration",
        "Authentication security / DAST",
        "Test session fixation, hijacking and token invalidation",
    ),
    "DE04": (
        "Require PostgreSQL CloudWatch log export and statement, connection, "
        "and disconnection logging in the Terraform plan",
        "OPA / policy/phase5-database-logging.rego / "
        "tests/phase5/verify_database_logging.py",
        "Passing policy tests; separately verify deployed logging, access "
        "controls, retention, and tamper protection",
    ),
}

columns = [
    "Finding ID",
    "Threat ID",
    "Threat Description",
    "Affected Component",
    "Severity",
    "PyTM Recommended Mitigation",
    "Proposed Control",
    "Proposed Verification Tool",
    "Required Verification Evidence",
    "Control Owner",
    "Implementation Status",
    "Verification Status",
    "Control Classification",
    "OPA Policy Reference",
    "AWS Security Hub Control Reference",
    "Control Coverage Assessment",
    "Required Remediation Action",
    "Supporting API Gateway Boundary Control",
]

rows = []

for index, finding in enumerate(findings, 1):
    threat_id = str(finding.get("threat_id", ""))

    control, tool, evidence = control_mapping.get(
        threat_id,
        (
            "Requires individual threat assessment",
            "To be determined",
            "Threat-specific verification evidence required",
        ),
    )

    rows.append({
        "Finding ID": finding.get("id") or f"PYTM-{index:03d}",
        "Threat ID": threat_id,
        "Threat Description": finding.get("description", ""),
        "Affected Component": finding.get("target", ""),
        "Severity": finding.get("severity", ""),
        "PyTM Recommended Mitigation": finding.get("mitigations", ""),
        "Proposed Control": control,
        "Proposed Verification Tool": tool,
        "Required Verification Evidence": evidence,
        "Control Owner": "To be assigned",
        "Implementation Status": "Not verified",
        "Verification Status": "Pending",
    })

    finding_id = str(rows[-1]["Finding ID"])
    rows[-1].update(existing_metadata.get(finding_id, {}))

    if threat_id == "DE04":
        rows[-1].update({
            "Control Owner": "To be assigned",
            "Implementation Status": "Policy and tests implemented; deployment not verified",
            "Verification Status": "Unit tests passed; CI and deployment verification pending",
            "Control Classification": "Preventive IaC configuration check",
            "OPA Policy Reference": "policy/phase5-database-logging.rego",
            "AWS Security Hub Control Reference": "Not yet mapped; confirm applicable AWS controls",
            "Control Coverage Assessment": (
                "Partial: validates planned PostgreSQL log export and logging "
                "parameters only; does not verify deployed settings, least-privilege "
                "access, retention, immutability, or resistance to privileged deletion."
            ),
            "Required Remediation Action": (
                "Verify deployed RDS and CloudWatch configuration; enforce "
                "least-privilege access; configure and test retention and tamper "
                "protection; assess log-deletion alerting."
            ),
            "Supporting API Gateway Boundary Control": "Not applicable",
        })

with destination.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated: {destination}")
print(f"Total threat records: {len(rows)}")

assert len(rows) == len(findings)
