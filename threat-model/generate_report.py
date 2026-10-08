#!/usr/bin/env python3
"""Generate a Markdown threat report from PyTM JSON output."""

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def safe_text(value):
    """Convert values to Markdown-safe text."""
    if value is None:
        return "Not specified"
    text = str(value).strip()
    if not text:
        return "Not specified"
    return text.replace("|", "\\|").replace("\n", " ")


def generate_report(source, destination):
    with source.open(encoding="utf-8") as file:
        model = json.load(file)

    findings = model.get("findings", [])
    boundaries = model.get("boundaries", [])
    flows = model.get("flows", [])
    elements = model.get("elements", [])

    severity_counts = Counter(
        str(finding.get("severity") or "Unspecified")
        for finding in findings
    )

    lines = [
        "# Phase 4 Automated Security Threat Report",
        "",
        f"**Threat Model:** {safe_text(model.get('name'))}",
        f"**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        "**Source:** PyTM automated threat modeling",
        "",
        "## 1. Executive Summary",
        "",
        f"The threat model identified **{len(findings)} threat findings** "
        f"across {len(elements)} modeled elements, "
        f"{len(boundaries)} trust boundaries, "
        f"and {len(flows)} data flows.",
        "",
        "## 2. Architecture Description",
        "",
        safe_text(model.get("description")),
        "",
        "## 3. Threat Severity Summary",
        "",
        "| Severity | Number of Findings |",
        "|---|---:|",
    ]

    severity_order = [
        "Very High", "Critical", "High",
        "Medium", "Low", "Very Low", "Unspecified"
    ]

    for severity in severity_order:
        if severity_counts.get(severity, 0):
            lines.append(
                f"| {severity} | {severity_counts[severity]} |"
            )

    for severity in sorted(set(severity_counts) - set(severity_order)):
        lines.append(f"| {safe_text(severity)} | {severity_counts[severity]} |")

    lines.extend([
        "",
        "## 4. Threats by Target",
        "",
        "| Target | Findings |",
        "|---|---:|",
    ])

    target_counts = Counter(
        str(finding.get("target") or "Unknown")
        for finding in findings
    )

    for target, count in target_counts.most_common():
        lines.append(f"| {safe_text(target)} | {count} |")

    lines.extend([
        "",
        "## 5. Detailed Threat Findings",
        "",
    ])

    for index, finding in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {safe_text(finding.get('description'))}",
            "",
            f"**Threat ID:** {safe_text(finding.get('threat_id'))}",
            "",
            f"**Severity:** {safe_text(finding.get('severity'))}",
            "",
            f"**Affected Target:** {safe_text(finding.get('target'))}",
            "",
            "**Threat Description**",
            "",
            safe_text(finding.get("details")),
            "",
            "**Recommended Mitigation**",
            "",
            safe_text(finding.get("mitigations")),
            "",
            "**References**",
            "",
            safe_text(finding.get("references")),
            "",
            "---",
            "",
        ])

    lines.extend([
        "## 6. Security Review and Next Steps",
        "",
        "The identified findings require security review and risk-based prioritization. "
        "Threat findings are potential weaknesses identified by the threat-modeling "
        "framework and do not independently establish that an exploit has occurred.",
        "",
        "Recommended follow-up activities include validating applicable threats, "
        "confirming existing mitigating controls, assigning remediation owners, "
        "and tracking residual risks.",
        "",
    ])

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")

    print(f"Report generated: {destination}")
    print(f"Total findings: {len(findings)}")
    print(f"Trust boundaries: {len(boundaries)}")
    print(f"Data flows: {len(flows)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    generate_report(args.input, args.output)
