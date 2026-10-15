package main

import rego.v1

# Discover resources in root and nested Terraform modules.
phase5_api_resources contains resource if {
    root := input.planned_values.root_module

    walk(root, [path, value])

    count(path) > 0
    path[count(path) - 1] == "resources"
    is_array(value)

    resource := value[_]
    is_object(resource)
    object.get(resource, "type", "") != ""
    object.get(resource, "address", "") != ""
}

# Block REST API methods with no authorization.
deny contains msg if {
    resource := phase5_api_resources[_]
    resource.type == "aws_api_gateway_method"

    auth := object.get(resource.values, "authorization", "NONE")
    auth == "NONE"

    msg := sprintf(
        "Phase 5: REST API method %s lacks authorization",
        [resource.address]
    )
}

# Block HTTP/WebSocket API routes with no authorization.
deny contains msg if {
    resource := phase5_api_resources[_]
    resource.type == "aws_apigatewayv2_route"

    auth := object.get(resource.values, "authorization_type", "NONE")
    auth == "NONE"

    msg := sprintf(
        "Phase 5: API Gateway V2 route %s lacks authorization",
        [resource.address]
    )
}
