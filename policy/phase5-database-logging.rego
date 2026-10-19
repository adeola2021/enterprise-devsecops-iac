package main

# Terraform plan checks only; not proof of deployment or immutability.

phase5_db_resources contains resource if {
    root := object.get(object.get(input, "planned_values", {}), "root_module", {})
    resource := object.get(root, "resources", [])[_]
}

phase5_postgres_instances contains resource if {
    resource := phase5_db_resources[_]
    resource.type == "aws_db_instance"
    object.get(resource.values, "engine", "") == "postgres"
}

phase5_db_parameter_groups contains resource if {
    resource := phase5_db_resources[_]
    resource.type == "aws_db_parameter_group"
}

phase5_has_export(instance) if {
    exports := object.get(instance.values, "enabled_cloudwatch_logs_exports", [])
    exports[_] == "postgresql"
}

phase5_has_parameter(group, name, expected) if {
    parameters := object.get(group.values, "parameter", [])
    parameter := parameters[_]
    parameter.name == name
    parameter.value == expected
}

phase5_parameters_valid(group) if {
    phase5_has_parameter(group, "log_statement", "all")
    phase5_has_parameter(group, "log_connections", "1")
    phase5_has_parameter(group, "log_disconnections", "1")
}

deny contains msg if {
    instance := phase5_postgres_instances[_]
    not phase5_has_export(instance)
    msg := sprintf("Phase 5: PostgreSQL instance %s must export PostgreSQL logs to CloudWatch", [instance.address])
}

deny contains msg if {
    instance := phase5_postgres_instances[_]
    some group in phase5_db_parameter_groups
    object.get(instance.values, "parameter_group_name", "") == object.get(group.values, "name", "")
    not phase5_parameters_valid(group)
    msg := sprintf("Phase 5: PostgreSQL parameter group %s must enable statement, connection, and disconnection logging", [group.address])
}

deny contains msg if {
    instance := phase5_postgres_instances[_]
    not phase5_has_matching_group(instance)
    msg := sprintf("Phase 5: PostgreSQL instance %s must reference a parameter group present in the Terraform plan", [instance.address])
}

phase5_has_matching_group(instance) if {
    group := phase5_db_parameter_groups[_]
    object.get(instance.values, "parameter_group_name", "") == object.get(group.values, "name", "")
}
