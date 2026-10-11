#!/usr/bin/env python3
"""Verify positive and negative Phase 4 OPA policy results."""

import json
import subprocess
import sys

CASES = [
    {
        "name": "Genuine AWS secure plan",
        "file": "terraform-policy-test/aws-secure-plan/tfplan.json",
        "expected": "pass",
    },
    {
        "name": "Genuine AWS insecure plan",
        "file": "terraform-policy-test/aws-real-plan/tfplan.json",
        "expected": "fail",
        "required_findings": [
            "lacks matching SSE-KMS encryption",
            "lacks matching public-access-block protection",
            "exposes port 22 publicly",
        ],
    },
    {
        "name": "Phase 2 compliant fixture",
        "file": "terraform-policy-test/tfplan-phase2-compliant.json",
        "expected": "pass",
    },
    {
        "name": "Phase 2 insecure fixture",
        "file": "terraform-policy-test/tfplan-phase2-insecure.json",
        "expected": "fail",
        "required_findings": [
            "prohibited region",
            "EBS volume",
            "missing mandatory Project tag",
        ],
    },
]


def verify(case):
    result = subprocess.run(
        [
            "conftest",
            "test",
            case["file"],
            "--policy",
            "policy/",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    try:
        reports = json.loads(result.stdout)
        if not isinstance(reports, list) or not reports:
            raise ValueError("Missing Conftest result records")

        failures = []
        errors = []

        for report in reports:
            failures.extend(
                item.get("msg", "")
                for item in report.get("failures", [])
            )
            errors.extend(report.get("exceptions", []))
            errors.extend(report.get("errors", []))

        if errors:
            raise ValueError(f"Policy exceptions: {errors}")

        if case["expected"] == "pass":
            if result.returncode != 0 or failures:
                raise ValueError(
                    f"Expected pass; exit={result.returncode}, "
                    f"findings={failures}"
                )
        else:
            if result.returncode != 1 or not failures:
                raise ValueError(
                    f"Expected policy rejection; exit={result.returncode}, "
                    f"findings={failures}, stderr={result.stderr}"
                )

            for expected in case["required_findings"]:
                if not any(expected in msg for msg in failures):
                    raise ValueError(
                        f"Expected security finding not detected: {expected}"
                    )

        print(
            f"PASS: {case['name']} "
            f"({len(failures)} expected policy violations)"
        )
        return True

    except (ValueError, TypeError, KeyError) as exc:
        print(f"FAIL: {case['name']}: {exc}")
        if result.stderr:
            print(result.stderr)
        return False


if __name__ == "__main__":
    outcomes = [verify(case) for case in CASES]

    if not all(outcomes):
        sys.exit(1)

    print("\nSUCCESS: All Phase 4 policy regression tests passed.")
