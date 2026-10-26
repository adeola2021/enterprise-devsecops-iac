package main

import rego.v1

# Phase 5: REST API stages must be associated with a WAFv2 web ACL.
# Maps to PyTM threats INP05, SC02, HA01 (supporting control only) and
# AWS Security Hub APIGateway.4 (verify the ID in AWS docs before citing).
# WAFv2 supports REST API stages only, so HTTP API (v2) stages are out of scope.

waf_all_resources contains r if {
	walk(input.planned_values.root_module, [_, m])
	r := m.resources[_]
}

waf_stages contains r if {
	some r in waf_all_resources
	r.type == "aws_api_gateway_stage"
}

waf_associations contains r if {
	some r in waf_all_resources
	r.type == "aws_wafv2_web_acl_association"
}

deny contains msg if {
	some stage in waf_stages
	count(waf_associations) == 0
	msg := sprintf("%s: API Gateway REST stage has no WAFv2 web ACL association in the plan (Security Hub APIGateway.4)", [stage.address])
}
