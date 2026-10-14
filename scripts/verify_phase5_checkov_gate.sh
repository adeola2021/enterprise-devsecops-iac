#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT

echo "Testing that critical Checkov findings block CI..."

if bash scripts/phase5_checkov_gate.sh \
    tests/phase5/critical-gate \
    > "$LOG_FILE" 2>&1; then

    echo "FAIL: Insecure Terraform passed the security gate."
    cat "$LOG_FILE"
    exit 1
fi

for check in CKV_AWS_24 CKV_AWS_145; do
    if ! grep -q "Check: ${check}:" "$LOG_FILE"; then
        echo "FAIL: Expected finding ${check} was not reported."
        cat "$LOG_FILE"
        exit 1
    fi
done

echo "PASS: Both critical vulnerabilities were detected and blocked."
