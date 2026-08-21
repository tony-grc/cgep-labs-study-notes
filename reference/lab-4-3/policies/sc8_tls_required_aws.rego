# METADATA
# title: SC-8 - Transmission Confidentiality (S3 TLS enforcement)
# description: "Every aws_s3_bucket must have a bucket policy, and that policy must deny requests where aws:SecureTransport is false."
# authors:
#   - CGE-P
# custom:
#   control_id: SC-8
#   framework: nist-800-53-rev5
#   severity: high
#   remediation: "Add an aws_s3_bucket_policy with a Deny statement on s3:* when Bool aws:SecureTransport = false."
#   plan_time_limitation: "Rendered policy JSON is unknown at plan time when bucket ARNs are computed. Tier 1 (a policy exists) always evaluates; tier 2 (it denies non-TLS) evaluates only when the JSON is known. Post-apply verification closes the gap."
package compliance.sc8_aws

import rego.v1

# Tier 1: structural. Always evaluable. A bucket with no policy at all
# cannot be enforcing TLS.
deny contains msg if {
	some bucket in bucket_addresses
	not has_policy(bucket)
	msg := sprintf(
		"[SC-8] %s: no aws_s3_bucket_policy references this bucket, so non-TLS requests are permitted. Remediation: add a policy denying aws:SecureTransport = false.",
		[bucket],
	)
}

# Tier 2: semantic. Only fires when the rendered JSON is known, which happens
# for hardcoded bucket names or on a re-plan against existing state.
deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_policy"
	is_string(r.values.policy)
	doc := json.unmarshal(r.values.policy)
	not denies_insecure_transport(doc)
	msg := sprintf(
		"[SC-8] %s: bucket policy is present but contains no Deny on aws:SecureTransport = false.",
		[r.address],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_policy(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

# Two definitions because an IAM condition value may be a bare string or an
# array, and both are valid policy JSON. Rego's multiple-definition semantics
# handle that cleanly: either matches.
denies_insecure_transport(doc) if {
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

denies_insecure_transport(doc) if {
	some stmt in doc.Statement
	stmt.Effect == "Deny"
	some v in stmt.Condition.Bool["aws:SecureTransport"]
	v == "false"
}

references_bucket(ref, addr) if ref == addr

references_bucket(ref, addr) if ref == sprintf("%s.id", [addr])

references_bucket(ref, addr) if ref == sprintf("%s.bucket", [addr])
