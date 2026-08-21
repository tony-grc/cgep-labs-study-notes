# METADATA
# title: AC-3 - Access Enforcement (no public GCS, no open management ports)
# description: "GCS buckets must enforce uniform_bucket_level_access AND public_access_prevention=enforced. Firewalls must not allow 0.0.0.0/0 on ports 22 or 3389."
# authors:
#   - CGE-P
# custom:
#   control_id: AC-3
#   framework: nist-800-53-rev5
#   severity: critical
#   remediation: "Set uniform_bucket_level_access = true and public_access_prevention = enforced. For firewalls, narrow source_ranges."
package compliance.ac3

import rego.v1

deny contains msg if {
	some r in buckets
	not locked_down(r)
	msg := sprintf(
		"[AC-3] %s: bucket allows public access. Remediation: set uniform_bucket_level_access=true and public_access_prevention=enforced.",
		[r.address],
	)
}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "google_compute_firewall"
	r.values.direction == "INGRESS"
	some src in r.values.source_ranges
	public_range(src)
	some allow in r.values.allow
	some port in allow.ports
	mgmt_port(port)
	msg := sprintf(
		"[AC-3] %s: management port %s open to %s. Remediation: narrow source_ranges or remove the rule.",
		[r.address, port, src],
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

locked_down(r) if {
	r.values.uniform_bucket_level_access == true
	r.values.public_access_prevention == "enforced"
}

mgmt_port(p) if p == "22"

mgmt_port(p) if p == "3389"

public_range(s) if s == "0.0.0.0/0"

public_range(s) if s == "*"
