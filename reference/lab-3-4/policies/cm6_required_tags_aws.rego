# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# description: "Every taggable resource must carry the four required tags."
# authors:
#   - CGE-P
# custom:
#   control_id: CM-6
#   framework: nist-800-53-rev5
#   severity: medium
#   remediation: "Add the four required tags, or set them once via provider default_tags."
package compliance.cm6_aws

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

taggable_type(t) if t == "aws_s3_bucket"

# Lab 2.3 v2 creates one of these, and an untagged key is a resource
# outside your boundary enumeration.
taggable_type(t) if t == "aws_kms_key"

taggable_type(t) if t == "aws_dynamodb_table"

taggable_type(t) if t == "aws_lambda_function"

taggable_type(t) if t == "aws_cloudtrail"

deny contains msg if {
	some resource in all_resources
	taggable_type(resource.type)
	missing := required - tag_keys(resource)
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add them, or use provider default_tags.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if {
	some r in input.planned_values.root_module.resources
}

all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

# With provider default_tags, the merged set lives in tags_all.
tag_keys(resource) := keys if {
	resource.values.tags_all
	keys := {k | resource.values.tags_all[k]}
}

tag_keys(resource) := keys if {
	not resource.values.tags_all
	resource.values.tags
	keys := {k | resource.values.tags[k]}
}

tag_keys(resource) := set() if {
	not resource.values.tags_all
	not resource.values.tags
}

sort_array(s) := sort([x | some x in s])
