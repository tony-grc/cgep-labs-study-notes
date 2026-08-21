# METADATA
# title: AU-9 - Protection of Audit Information (log target versioning)
# description: "A bucket named as a logging target must have versioning enabled so audit records cannot be silently overwritten."
# authors:
#   - CGE-P
# custom:
#   control_id: AU-9
#   framework: nist-800-53-rev5
#   severity: high
#   remediation: "Enable versioning { enabled = true } on the bucket used as a logging target."
package compliance.au9

import rego.v1

deny contains msg if {
	some target_name in log_target_names
	some bucket in buckets
	bucket.values.name == target_name
	not versioned(bucket)
	msg := sprintf(
		"[AU-9] %s: used as a logging target but versioning is disabled. Audit records can be silently overwritten. Remediation: versioning { enabled = true }.",
		[bucket.address],
	)
}

buckets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "google_storage_bucket"
}

buckets contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "google_storage_bucket"
}

log_target_names contains name if {
	some b in buckets
	count(b.values.logging) > 0
	name := b.values.logging[0].log_bucket
}

versioned(bucket) if {
	count(bucket.values.versioning) > 0
	bucket.values.versioning[0].enabled == true
}
