package compliance.sc8_aws_test

import data.compliance.sc8_aws
import rego.v1

has_policy := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
	{
		"type": "aws_s3_bucket_policy",
		"name": "primary",
		"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id", "aws_s3_bucket.primary"]}},
	},
]}}}

no_policy := {"configuration": {"root_module": {"resources": [
	{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
]}}}

# Tier 2 only evaluates when the rendered JSON is known.
rendered_good := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "primary",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.primary",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
	}]}},
}

rendered_bad := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "primary",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.primary",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\"}]}"},
	}]}},
}

# Condition values may be a bare string or an array; both are valid.
rendered_array_form := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "primary", "expressions": {}},
		{
			"type": "aws_s3_bucket_policy",
			"name": "primary",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.primary.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.primary",
		"type": "aws_s3_bucket_policy",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":[\"false\"]}}}]}"},
	}]}},
}

test_tier1_policy_present_passes if {
	count(sc8_aws.deny) == 0 with input as has_policy
}

test_tier1_no_policy_fails if {
	some msg in sc8_aws.deny with input as no_policy
	contains(msg, "SC-8")
	contains(msg, "no aws_s3_bucket_policy")
}

test_tier2_rendered_deny_passes if {
	count(sc8_aws.deny) == 0 with input as rendered_good
}

test_tier2_policy_without_tls_deny_fails if {
	some msg in sc8_aws.deny with input as rendered_bad
	contains(msg, "SC-8")
	contains(msg, "no Deny on aws:SecureTransport")
}

test_tier2_accepts_array_condition_form if {
	count(sc8_aws.deny) == 0 with input as rendered_array_form
}
