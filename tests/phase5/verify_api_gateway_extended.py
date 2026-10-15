import json
import subprocess

def evaluate(plan):
    result = subprocess.run(
        [
            "opa", "eval",
            "--format=json",
            "--data", "policy/",
            "--input", "/dev/stdin",
            "data.main.deny",
        ],
        input=json.dumps(plan),
        text=True,
        capture_output=True,
        check=True,
    )

    data = json.loads(result.stdout)
    return data.get("result", [{}])[0].get(
        "expressions", [{}]
    )[0].get("value", [])


def plan(resources=None, children=None):
    return {
        "planned_values": {
            "root_module": {
                "resources": resources or [],
                "child_modules": children or [],
            }
        }
    }


def resource(address, type_, values):
    return {
        "address": address,
        "type": type_,
        "values": values,
    }


cases = [
    (
        "Missing REST authorization",
        plan([
            resource(
                "aws_api_gateway_method.missing",
                "aws_api_gateway_method",
                {},
            )
        ]),
        True,
    ),
    (
        "Missing V2 authorization",
        plan([
            resource(
                "aws_apigatewayv2_route.missing",
                "aws_apigatewayv2_route",
                {},
            )
        ]),
        True,
    ),
    (
        "Nested module insecure route",
        plan(children=[{
            "address": "module.api",
            "resources": [],
            "child_modules": [{
                "address": "module.api.module.routes",
                "resources": [
                    resource(
                        "module.api.module.routes.aws_apigatewayv2_route.open",
                        "aws_apigatewayv2_route",
                        {"authorization_type": "NONE"},
                    )
                ],
            }],
        }]),
        True,
    ),
    (
        "Nested module secure route",
        plan(children=[{
            "address": "module.api",
            "resources": [
                resource(
                    "module.api.aws_apigatewayv2_route.secure",
                    "aws_apigatewayv2_route",
                    {"authorization_type": "JWT"},
                )
            ],
        }]),
        False,
    ),
]

for name, test_plan, should_block in cases:
    violations = evaluate(test_plan)
    blocked = bool(violations)

    assert blocked == should_block, (
        f"FAIL: {name}: expected block={should_block}; "
        f"violations={violations}"
    )

    print(f"PASS: {name}")

print("SUCCESS: Extended API Gateway tests passed")
