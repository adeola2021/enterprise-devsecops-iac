import json
import subprocess

POLICY = "policy/"


def resource(address, type_, values):
    return {
        "address": address,
        "type": type_,
        "values": values,
    }


def parameter(name, value):
    return {"name": name, "value": value}


def database_resources(
    exports=None,
    parameters=None,
    include_parameter_group=True,
):
    if exports is None:
        exports = ["postgresql"]

    if parameters is None:
        parameters = [
            parameter("log_statement", "all"),
            parameter("log_connections", "1"),
            parameter("log_disconnections", "1"),
        ]

    resources = [
        resource(
            "aws_db_instance.enterprise_database",
            "aws_db_instance",
            {
                "engine": "postgres",
                "enabled_cloudwatch_logs_exports": exports,
                "parameter_group_name": "enterprise-postgres",
                "tags": {"Environment": "test", "Owner": "security", "CostCenter": "CC001"},
            },
        )
    ]

    if include_parameter_group:
        resources.append(
            resource(
                "aws_db_parameter_group.enterprise_postgres",
                "aws_db_parameter_group",
                {
                    "name": "enterprise-postgres",
                    "tags": {"Environment": "test", "Owner": "security", "CostCenter": "CC001"},
                    "parameter": parameters,
                },
            )
        )

    return resources


def evaluate(resources):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": resources,
            }
        }
    }

    result = subprocess.run(
        [
            "opa", "eval",
            "--format=json",
            "--data", POLICY,
            "--input", "/dev/stdin",
            "data.main.deny",
        ],
        input=json.dumps(plan),
        text=True,
        capture_output=True,
        check=True,
    )

    parsed = json.loads(result.stdout)
    expressions = parsed.get("result", [])

    if not expressions:
        return []

    return expressions[0]["expressions"][0]["value"]


tests = [
    (
        "Compliant PostgreSQL logging configuration",
        database_resources(),
        False,
    ),
    (
        "Missing CloudWatch PostgreSQL log export",
        database_resources(exports=[]),
        True,
    ),
    (
        "Missing statement logging",
        database_resources(
            parameters=[
                parameter("log_connections", "1"),
                parameter("log_disconnections", "1"),
            ]
        ),
        True,
    ),
    (
        "Incorrect connection logging value",
        database_resources(
            parameters=[
                parameter("log_statement", "all"),
                parameter("log_connections", "0"),
                parameter("log_disconnections", "1"),
            ]
        ),
        True,
    ),
    (
        "Missing associated parameter group",
        database_resources(include_parameter_group=False),
        True,
    ),
]

for name, resources, should_block in tests:
    violations = evaluate(resources)
    blocked = len(violations) > 0

    assert blocked == should_block, (
        f"FAIL: {name}: expected block={should_block}, "
        f"got violations={violations}"
    )

    print(f"PASS: {name}")

print("\nSUCCESS: Phase 5 database logging policy tests passed")
