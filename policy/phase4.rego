package main

# Phase 4 supplementary controls.
# Phase 1 and Phase 2 controls remain in terraform.rego.

# Collect resources from the root module and nested modules.

# Collect AWS resources from root and nested Terraform modules.
# walk() traverses the plan without recursive Rego functions.

phase4_resources contains resource if {
    root := input.planned_values.root_module

    walk(root, [path, resource])

    count(path) > 0
    path[count(path) - 1] >= 0

    is_object(resource)
    object.get(resource, "mode", "") == "managed"
    startswith(object.get(resource, "type", ""), "aws_")
}

# Resource types supporting mandatory organizational tags.

phase4_taggable_types := {
    "aws_instance",
    "aws_security_group",
    "aws_s3_bucket",
    "aws_kms_key",
    "aws_sqs_queue",
    "aws_db_instance",
    "aws_db_parameter_group",
    "aws_ebs_volume",
    "aws_iam_role",
    "aws_ssm_parameter",
}

# Require Project tag in addition to existing Phase 1 requirements.

deny contains msg if {
    resource := phase4_resources[_]
    phase4_taggable_types[resource.type]

    tags := object.get(resource.values, "tags", {})
    project := object.get(tags, "Project", "")

    project == ""

    msg := sprintf(
        "Phase 4: AWS resource %s is missing mandatory Project tag",
        [resource.address],
    )
}

# Detect sensitive ports within an ingress port range.

phase4_sensitive_port(from_port, to_port, protocol, port) if {
    protocol == "tcp"
    from_port <= port
    to_port >= port
}

phase4_sensitive_port(from_port, to_port, protocol, port) if {
    protocol == "-1"
}


# Inline security group ingress rules.

deny contains msg if {
    resource := phase4_resources[_]
    resource.type == "aws_security_group"

    ingress := resource.values.ingress[_]
    ingress.cidr_blocks[_] == "0.0.0.0/0"

    port := {22, 3389}[_]

    phase4_sensitive_port(
        ingress.from_port,
        ingress.to_port,
        ingress.protocol,
        port,
    )

    msg := sprintf(
        "Phase 4: Security group %s exposes port %v publicly",
        [resource.address, port],
    )
}

# Standalone security group ingress rules.

deny contains msg if {
    resource := phase4_resources[_]
    resource.type == "aws_security_group_rule"
    resource.values.type == "ingress"

    resource.values.cidr_blocks[_] == "0.0.0.0/0"

    port := {22, 3389}[_]

    phase4_sensitive_port(
        resource.values.from_port,
        resource.values.to_port,
        resource.values.protocol,
        port,
    )

    msg := sprintf(
        "Phase 4: Security group rule %s exposes port %v publicly",
        [resource.address, port],
    )
}

# Modern VPC security group ingress resources.

deny contains msg if {
    resource := phase4_resources[_]
    resource.type == "aws_vpc_security_group_ingress_rule"
    resource.values.cidr_ipv4 == "0.0.0.0/0"

    port := {22, 3389}[_]

    phase4_sensitive_port(
        resource.values.from_port,
        resource.values.to_port,
        resource.values.ip_protocol,
        port,
    )

    msg := sprintf(
        "Phase 4: VPC ingress rule %s exposes port %v publicly",
        [resource.address, port],
    )
}

# ==========================================================
# PHASE 4: STRICT S3 SECURITY CONTROLS
# ==========================================================

# Match S3 security configuration using the bucket name,
# not a partial Terraform resource address.

phase4_s3_has_kms(bucket) if {
    encryption := phase4_resources[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"

    s3_resource_matches_bucket(encryption, bucket)

    rule := encryption.values.rule[_]
    setting := rule.apply_server_side_encryption_by_default[_]

    setting.sse_algorithm == "aws:kms"
    s3_has_customer_kms_reference(encryption)
}

phase4_s3_has_public_access_block(bucket) if {
    block := phase4_resources[_]
    block.type == "aws_s3_bucket_public_access_block"

    s3_resource_matches_bucket(block, bucket)

    block.values.block_public_acls == true
    block.values.ignore_public_acls == true
    block.values.block_public_policy == true
    block.values.restrict_public_buckets == true
}

deny contains msg if {
    bucket := phase4_resources[_]
    bucket.type == "aws_s3_bucket"

    bucket_name := bucket.values.bucket
    is_string(bucket_name)

    not phase4_s3_has_kms(bucket)

    msg := sprintf(
        "Phase 4: S3 bucket %s lacks matching SSE-KMS encryption",
        [bucket.address],
    )
}

deny contains msg if {
    bucket := phase4_resources[_]
    bucket.type == "aws_s3_bucket"

    bucket_name := bucket.values.bucket
    is_string(bucket_name)

    not phase4_s3_has_public_access_block(bucket)

    msg := sprintf(
        "Phase 4: S3 bucket %s lacks matching public-access-block protection",
        [bucket.address],
    )
}
