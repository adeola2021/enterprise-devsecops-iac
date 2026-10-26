import json
import subprocess

POLICY = "policy/"


def resource(address, type_, values=None):
    return {"address": address, "type": type_, "values": values or {}}


def evaluate(root_module):
    plan = {"planned_values": {"root_module": root_module}}
    result = subprocess.run(
        ["opa", "eval", "--format=json", "--data", POLICY,
         "--input", "/dev/stdin", "data.main.deny"],
        input=json.dumps(plan), text=True, capture_output=True, check=True,
    )
    parsed = json.loads(result.stdout)
    exprs = parsed.get("result", [])
    if not exprs:
        return []
    value = exprs[0]["expressions"][0]["value"]
    return [v for v in value if "WAFv2" in v]


stage = resource("aws_api_gateway_stage.prod", "aws_api_gateway_stage")
assoc = resource("aws_wafv2_web_acl_association.prod", "aws_wafv2_web_acl_association")

tests = [
    ("Stage with WAF association",
     {"resources": [stage, assoc]}, False),
    ("Stage without WAF association",
     {"resources": [stage]}, True),
    ("No API Gateway stage",
     {"resources": [resource("aws_s3_bucket.x", "aws_s3_bucket")]}, False),
    ("Nested module stage without association",
     {"resources": [], "child_modules": [{"address": "module.api", "resources": [stage]}]}, True),
    ("Nested stage with association in root",
     {"resources": [assoc], "child_modules": [{"address": "module.api", "resources": [stage]}]}, False),
    ("HTTP API v2 stage is out of scope",
     {"resources": [resource("aws_apigatewayv2_stage.x", "aws_apigatewayv2_stage")]}, False),
]

for name, root, should_block in tests:
    violations = evaluate(root)
    blocked = len(violations) > 0
    assert blocked == should_block, (
        f"FAIL: {name}: expected block={should_block}, got violations={violations}"
    )
    print(f"PASS: {name}")

print("\nSUCCESS: Phase 5 WAF association policy tests passed")
