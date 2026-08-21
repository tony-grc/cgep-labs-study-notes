# METADATA
# title: AU-3 - Content of Audit Records (GCS access logging)
# description: "Every google_storage_bucket must emit access logs to a named target bucket."
# authors:
#   - CGE-P
# custom:
#   control_id: AU-3
#   framework: nist-800-53-rev5
#   severity: medium
#   remediation: "Add a logging { log_bucket = ... } block naming a dedicated log bucket."
package compliance.au3

import rego.v1

deny contains msg if {
	some resource in buckets
	not is_log_sink(resource)
	not has_logging(resource)
	msg := sprintf(
		"[AU-3] %s: no access logging configured. Remediation: add logging { log_bucket = ... }.",
		[resource.address],
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

has_logging(resource) if {
	count(resource.values.logging) > 0
	resource.values.logging[0].log_bucket != ""
}

# A bucket that is itself a logging target is exempt. Without this the rule
# demands infinite regress: every log bucket needs a log bucket. Deciding
# where the recursion stops is a policy decision, and stating it in the rule
# beats suppressing the finding later.
is_log_sink(resource) if {
	some other in buckets
	count(other.values.logging) > 0
	other.values.logging[0].log_bucket == resource.values.name
}
