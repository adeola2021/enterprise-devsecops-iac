package main

required_tags := {
    "Environment",
    "Owner",
    "CostCenter",
}

allowed_nonprod_instance_types := {
    "t3.micro",
    "t3.small",
    "t3.medium",
}

sensitive_ports := {
    22,
    3389,
}

# Mandatory tags
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]

    taggable_resource_types := {
        "aws_instance",
        "aws_security_group",
        "aws_s3_bucket",
        "aws_kms_key",
        "aws_sqs_queue",
        "aws_db_instance",
        "aws_db_parameter_group",
    }

    taggable_resource_types[resource.type]

    tags := object.get(resource.values, "tags", {})

    missing := required_tags - object.keys(tags)

    count(missing) > 0

    msg := sprintf(
        "Resource %s is missing mandatory tags: %v",
        [resource.address, missing]
    )
}

# EC2 instance size restriction
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]

    resource.type == "aws_instance"

    tags := object.get(resource.values, "tags", {})

    environment := object.get(tags, "Environment", "")

    environment != "production"

    instance_type := resource.values.instance_type

    not allowed_nonprod_instance_types[instance_type]

    msg := sprintf(
        "EC2 instance %s uses prohibited instance type %s in non-production environment %s",
        [resource.address, instance_type, environment]
    )
}

# Restrict public SSH and RDP access
deny contains msg if {
    resource := input.planned_values.root_module.resources[_]

    resource.type == "aws_security_group"

    ingress := resource.values.ingress[_]

    sensitive_ports[ingress.from_port]

    "0.0.0.0/0" == ingress.cidr_blocks[_]

    msg := sprintf(
        "Security Group %s allows public access to sensitive port %v",
        [resource.address, ingress.from_port]
    )
}
