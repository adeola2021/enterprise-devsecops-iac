import json
import subprocess

POLICY = "policy/"

def evaluate(resources):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": resources
            }
        }
    }

    result = subprocess.run(
        [
            "opa", "eval",
            "--format=json",
            "--data", POLICY,
            "--input", "/dev/stdin",
            "data.main.deny"
        ],
        input=json.dumps(plan),
        text=True,
        capture_output=True,
        check=True
    )

    parsed = json.loads(result.stdout)
    expressions = parsed.get("result", [])

    if not expressions:
        return []

    value = expressions[0]["expressions"][0]["value"]
    return value


def resource(address, type_, values):
    return {
        "address": address,
        "type": type_,
        "values": values
    }


tests = [
    (
        "REST API with authorization",
        [
            resource(
                "aws_api_gateway_method.secure",
                "aws_api_gateway_method",
                {"authorization": "AWS_IAM"}
            )
        ],
        False
    ),
    (
        "REST API without authorization",
        [
            resource(
                "aws_api_gateway_method.insecure",
                "aws_api_gateway_method",
                {"authorization": "NONE"}
            )
        ],
        True
    ),
    (
        "HTTP API with JWT authorization",
        [
            resource(
                "aws_apigatewayv2_route.secure",
                "aws_apigatewayv2_route",
                {"authorization_type": "JWT"}
            )
        ],
        False
    ),
    (
        "HTTP API without authorization",
        [
            resource(
                "aws_apigatewayv2_route.insecure",
                "aws_apigatewayv2_route",
                {"authorization_type": "NONE"}
            )
        ],
        True
    )
]

for name, resources, should_block in tests:
    violations = evaluate(resources)

    blocked = len(violations) > 0

    assert blocked == should_block, (
        f"FAIL: {name}: expected block={should_block}, "
        f"got violations={violations}"
    )

    print(f"PASS: {name}")

print("\nSUCCESS: Phase 5 API Gateway policy tests passed")
