#!/usr/bin/env python3

import csv
import json
from pathlib import Path

source = Path("reports/pytm-threat-model.json")
destination = Path("reports/phase5/threat-control-matrix.csv")

data = json.loads(source.read_text())
findings = data.get("findings", [])

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

with destination.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

print(f"Generated: {destination}")
print(f"Total threat records: {len(rows)}")

assert len(rows) == len(findings)
