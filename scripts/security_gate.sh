#!/usr/bin/env bash

set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${PROJECT_ROOT}/reports"

mkdir -p "${REPORT_DIR}"

SEMgrep_REPORT="${REPORT_DIR}/semgrep-gate.json"
GITLEAKS_REPORT="${REPORT_DIR}/gitleaks-gate.json"
LOG_FILE="${REPORT_DIR}/security-gate.log"

GATE_FAILED=0

exec > >(tee "${LOG_FILE}") 2>&1

echo "============================================================"
echo "ENTERPRISE DEVSECOPS SECURITY GATE"
echo "============================================================"
echo "Project : ${PROJECT_ROOT}"
echo "Date    : $(date -u)"
echo

echo "[1/2] Running Semgrep SAST..."
echo "------------------------------------------------------------"

semgrep \
    --config "${PROJECT_ROOT}/security/semgrep-rules.yml" \
    "${PROJECT_ROOT}/app" \
    --json \
    --output "${SEMgrep_REPORT}"

SEMgrep_EXIT=$?

if [ ${SEMgrep_EXIT} -ne 0 ]; then
    echo "❌ Semgrep execution failed."
    GATE_FAILED=1
else
    SEMgrep_FINDINGS=$(python3 - "${SEMgrep_REPORT}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

print(len(data.get("results", [])))
PY
)

    echo "Semgrep findings: ${SEMgrep_FINDINGS}"

    if [ "${SEMgrep_FINDINGS}" -gt 0 ]; then
        echo "❌ Semgrep security gate FAILED."
        GATE_FAILED=1
    else
        echo "✅ Semgrep security gate PASSED."
    fi
fi

echo
echo "[2/2] Running Gitleaks secret scan..."
echo "------------------------------------------------------------"

gitleaks dir "${PROJECT_ROOT}/app" \
    --config "${PROJECT_ROOT}/security/gitleaks.toml" \
    --no-banner \
    --redact \
    --report-format json \
    --report-path "${GITLEAKS_REPORT}"

GITLEAKS_EXIT=$?

if [ ${GITLEAKS_EXIT} -ne 0 ]; then
    echo "❌ Gitleaks security gate FAILED."
    GATE_FAILED=1
else
    echo "✅ Gitleaks security gate PASSED."
fi

echo
echo "============================================================"
echo "SECURITY GATE RESULT"
echo "============================================================"

if [ ${GATE_FAILED} -eq 0 ]; then
    echo "✅ SECURITY GATE PASSED"
    exit 0
else
    echo "❌ SECURITY GATE FAILED"
    exit 1
fi
