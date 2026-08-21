package compliance.cm6_test

import data.compliance.cm6
import rego.v1

complete := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {"labels": {
		"project": "x",
		"environment": "dev",
		"managed_by": "terraform",
		"compliance_scope": "cge-p-lab",
	}},
}]}}}

partial := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {"labels": {"project": "x"}},
}]}}}

none := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.naked",
	"type": "google_storage_bucket",
	"values": {},
}]}}}

in_module := {"planned_values": {"root_module": {"child_modules": [{"resources": [{
	"address": "module.m.google_storage_bucket.wrapped",
	"type": "google_storage_bucket",
	"values": {"labels": {"project": "x"}},
}]}]}}}

test_complete_passes if {
	count(cm6.deny) == 0 with input as complete
}

test_partial_fails if {
	some msg in cm6.deny with input as partial
	contains(msg, "CM-6")
}

test_no_labels_fails if {
	some msg in cm6.deny with input as none
	contains(msg, "CM-6")
}

# Module-wrapped resources live under child_modules, not root_module.resources.
# A rule that forgets to recurse silently covers nothing.
test_child_module_is_covered if {
	some msg in cm6.deny with input as in_module
	contains(msg, "module.m.google_storage_bucket.wrapped")
}

# A type outside labelable_type must be ignored entirely, even with no
# labels. Without this, nothing constrains labelable_type and the mutation
# test correctly reports the policy as unconstrained.
not_labelable := {"planned_values": {"root_module": {"resources": [{
	"address": "google_compute_network.demo",
	"type": "google_compute_network",
	"values": {},
}]}}}

test_non_labelable_type_ignored if {
	count(cm6.deny) == 0 with input as not_labelable
}
