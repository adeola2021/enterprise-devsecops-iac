#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " PHASE 5: CRITICAL CHECKOV SECURITY GATE"
echo "=========================================="

echo "Blocking checks: CKV_AWS_24, CKV_AWS_145"

if [[ "$#" -gt 0 ]]; then
    targets=("$@")
else
    targets=(
        "terraform"
        "terraform-policy-test/aws-secure-plan"
    )
fi

for target in "${targets[@]}"; do
    if [[ ! -d "$target" ]]; then
        echo "ERROR: Terraform directory not found: $target"
        exit 2
    fi

    echo
    echo "Scanning: $target"

    checkov \
        --directory "$target" \
        --framework terraform \
        --check CKV_AWS_24,CKV_AWS_145 \
        --compact \
        --quiet

    echo "PASS: $target"
done

echo
echo "PASS: All selected Terraform directories passed."
