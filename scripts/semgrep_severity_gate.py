#!/usr/bin/env python3
"""Fail the pipeline if Semgrep reports High/Critical findings.

Fails closed: a missing report, a Semgrep error, or an unrated
finding all block the pipeline.
"""
import json
import os
import sys

BLOCKING = {"HIGH", "CRITICAL"}
path = sys.argv[1] if len(sys.argv) > 1 else "reports/phase6/semgrep-appsec.json"

if not os.path.isfile(path):
    sys.exit(f"Security gate FAILED: report not found: {path}")

with open(path) as f:
    data = json.load(f)

errors = [e for e in data.get("errors", []) if e.get("level") == "error"]
if errors:
    for e in errors:
        print(f"  Semgrep error: {e.get('message')}")
    sys.exit("Security gate FAILED: Semgrep reported errors, so the scan cannot be trusted.")

results = data.get("results", [])
blocking = []
for r in results:
    sev = str(r.get("extra", {}).get("metadata", {}).get("security_severity", "")).upper()
    if sev in BLOCKING or sev == "":
        blocking.append((sev or "UNRATED", r["check_id"], r["path"], r["start"]["line"]))

print(f"Total findings: {len(results)} | Blocking (High/Critical/unrated): {len(blocking)}")
for sev, rule, file, line in blocking:
    print(f"  [{sev}] {rule} | {file}:{line}")

if blocking:
    sys.exit("Security gate FAILED: High/Critical findings present.")
print("Security gate PASSED.")
