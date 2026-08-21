# METADATA
# title: AU-9 - Protection of Audit Information (S3 log bucket versioning)
# description: "A bucket named as an aws_s3_bucket_logging target must itself have versioning enabled."
# authors:
#   - CGE-P
# custom:
#   control_id: AU-9
#   framework: nist-800-53-rev5
#   severity: high
#   remediation: "Add aws_s3_bucket_versioning for the log bucket with status = Enabled."
package compliance.au9_aws

import rego.v1

# This rule is the mechanical form of a common and quiet mistake: an
# architecture that promises versioning on both buckets, and code that
# versions only the one holding data.
deny contains msg if {
	some target in log_target_addresses
	not versioned(target)
	msg := sprintf(
		"[AU-9] %s: used as an access-log target but has no aws_s3_bucket_versioning. Audit records can be silently overwritten.",
		[target],
	)
}

log_target_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_logging"
	some ref in r.expressions.target_bucket.references
	addr := trim_suffix(trim_suffix(ref, ".id"), ".bucket")
	startswith(addr, "aws_s3_bucket.")
}

versioned(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

references_bucket(ref, addr) if ref == addr

references_bucket(ref, addr) if ref == sprintf("%s.id", [addr])

references_bucket(ref, addr) if ref == sprintf("%s.bucket", [addr])
