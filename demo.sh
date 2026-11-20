#!/usr/bin/env bash
# End-to-end demo. Usage:
#   Workstation/CI : ./demo.sh                       (real terraform plan + init/validate)
#   Sandbox        : TF_BIN=tofu PLAN_MODE=mock VALIDATE_MODE=offline ./demo.sh
set -u
TF_BIN=${TF_BIN:-terraform}; PLAN_MODE=${PLAN_MODE:-real}; VALIDATE_MODE=${VALIDATE_MODE:-full}
KMS=${KMS_ARN:-arn:aws:kms:us-east-1:111122223333:key/REPLACE-ME}
FIX=terraform/fixture; CK="CKV_AWS_19,CKV_AWS_24,CKV_AWS_25,CKV_AWS_145"
banner() { printf '\n\033[1m######## %s ########\033[0m\n' "$*"; }

make_plan() {
  if [ "$PLAN_MODE" = mock ]; then python3 tools/mock_plan.py $FIX plan.json
  else ( cd $FIX && $TF_BIN init -backend=false -input=false >/dev/null && $TF_BIN plan -input=false -out=tfplan >/dev/null \
         && $TF_BIN show -json tfplan > ../../plan.json ) && echo "wrote plan.json (real plan)"; fi
}

banner "0. Tool versions"
$TF_BIN version | head -1; opa version | head -1; conftest --version; checkov --version; python3 --version

banner "1. Policy unit tests"
opa check policies/ --strict && opa test policies/ -v | tail -3

banner "2. BEFORE: scan vulnerable fixture (plan mode: $PLAN_MODE)"
make_plan
echo "--- Conftest/OPA ---"
conftest test plan.json -p policies -n cloud_security --no-color; echo "[exit=$?]"
conftest test plan.json -p policies -n cloud_security -o json > reports/conftest.json
echo "--- Checkov ---"
checkov -d $FIX --framework terraform --check $CK,CKV_AWS_63,CKV_AWS_355 -o json > reports/checkov.json 2>/dev/null
checkov -d $FIX --framework terraform --compact --quiet --check $CK 2>/dev/null | grep -E "Passed checks|Check:|FAILED"

banner "3. FIX: generate_security_pr.py --mode iac"
python3 generate_security_pr.py --mode iac --tf-bin $TF_BIN --validate-mode $VALIDATE_MODE \
   --kms-key-arn "$KMS" --local-only

banner "4. DIFF of the autofix commit"
git show --stat --format='commit %h  %s' HEAD | head -8; echo
git show --format= HEAD -- $FIX

banner "5. AFTER: re-scan patched fixture"
make_plan
echo "--- Conftest/OPA ---"
conftest test plan.json -p policies -n cloud_security --no-color; echo "[exit=$?]"
echo "--- Checkov (blocking scope) ---"
checkov -d $FIX --framework terraform --compact --quiet --check $CK 2>/dev/null | grep -E "Passed checks|Check:|FAILED"; echo "[exit=${PIPESTATUS[0]}]"
echo "--- Checkov IAM (advisory; expected to still fail) ---"
checkov -d $FIX --framework terraform --compact --quiet --check CKV_AWS_63,CKV_AWS_355 2>/dev/null | grep -E "Passed checks|Check:|FAILED"
echo "--- fmt gate ---"; $TF_BIN fmt -check -recursive terraform/ && echo "fmt clean [exit=0]"
echo "--- unit tests ---"; python3 -m pytest -q 2>&1 | tail -2

banner "6. Generated PR body (reports/pr_body.md)"
cat reports/pr_body.md
