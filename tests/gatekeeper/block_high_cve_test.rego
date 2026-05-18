# =============================================================================
# Unit tests for policies/gatekeeper/block-high-cve.rego
# =============================================================================
#
# Coverage matrix:
#
#                            criticals  highs  param.critT  param.highT  expect
#   missing_annotation_deny      -         -         -            -        DENY
#   zero_findings_allow          0         0         0           -1        ALLOW
#   one_critical_default_deny    1         0         0           -1        DENY
#   one_critical_threshold_allow 1         0         1           -1        ALLOW
#   high_default_allow         100       100         0           -1        ALLOW
#   high_threshold_deny         50         5         0            3        DENY
#   high_threshold_allow         5         3         0            5        ALLOW
#   deployment_critical_deny     2         -         0           -1        DENY
# =============================================================================

package k8sblockhighcve_test

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.k8sblockhighcve

# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

make_pod_with_findings(findings, params) := obj if {
	obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {
				"name": "p",
				"namespace": "demo",
				"annotations": {"inspector.aws/findings": findings},
			},
			"spec": {"containers": [{"name": "app", "image": "registry.invalid/img:v1"}]},
		}},
		"parameters": params,
	}
}

make_pod_no_annotations(params) := obj if {
	obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {"name": "p", "namespace": "demo"},
			"spec": {"containers": [{"name": "app", "image": "registry.invalid/img:v1"}]},
		}},
		"parameters": params,
	}
}

# Default parameter block matching constraints.yaml.
default_params := {"criticalThreshold": 0, "highThreshold": -1}

# -----------------------------------------------------------------------------
# Missing annotation (fail-closed)
# -----------------------------------------------------------------------------

test_missing_annotation_deny if {
	result := k8sblockhighcve.violation with input as make_pod_no_annotations(default_params)
	count(result) >= 1
	some v in result
	contains(v.msg, "missing Inspector findings annotation")
}

# Empty parameters block: still fail-closed because findings annotation is missing.
test_missing_annotation_empty_params_deny if {
	result := k8sblockhighcve.violation with input as make_pod_no_annotations({})
	count(result) >= 1
}

# -----------------------------------------------------------------------------
# Allow path: zero criticals, high check disabled
# -----------------------------------------------------------------------------

test_zero_findings_allow if {
	input_obj := make_pod_with_findings("critical=0,high=0,medium=2,low=5", default_params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

test_only_medium_low_allow if {
	# No critical or high keys at all -- parser must return 0 for both.
	input_obj := make_pod_with_findings("medium=2,low=5", default_params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

# -----------------------------------------------------------------------------
# Critical thresholds
# -----------------------------------------------------------------------------

test_one_critical_default_deny if {
	input_obj := make_pod_with_findings("critical=1,high=0", default_params)
	result := k8sblockhighcve.violation with input as input_obj
	count(result) >= 1
	some v in result
	contains(v.msg, "CRITICAL")
}

test_many_criticals_deny if {
	input_obj := make_pod_with_findings("critical=42,high=10", default_params)
	result := k8sblockhighcve.violation with input as input_obj
	count(result) >= 1
}

# Opt-in: allow up to N criticals (used by legacy namespaces during migration).
test_critical_threshold_allow if {
	params := {"criticalThreshold": 5, "highThreshold": -1}
	input_obj := make_pod_with_findings("critical=3,high=0", params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

test_critical_threshold_exceeded_deny if {
	params := {"criticalThreshold": 5, "highThreshold": -1}
	input_obj := make_pod_with_findings("critical=6,high=0", params)
	result := k8sblockhighcve.violation with input as input_obj
	count(result) >= 1
}

# -----------------------------------------------------------------------------
# High thresholds (opt-in via parameters.highThreshold >= 0)
# -----------------------------------------------------------------------------

test_high_default_disabled_allow if {
	# Default config does not gate on HIGH at all; 100 highs must still pass
	# because criticals are zero.
	input_obj := make_pod_with_findings("critical=0,high=100", default_params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

test_high_threshold_deny if {
	params := {"criticalThreshold": 0, "highThreshold": 3}
	input_obj := make_pod_with_findings("critical=0,high=50", params)
	result := k8sblockhighcve.violation with input as input_obj
	count(result) >= 1
	some v in result
	contains(v.msg, "HIGH")
}

test_high_threshold_allow if {
	params := {"criticalThreshold": 0, "highThreshold": 5}
	input_obj := make_pod_with_findings("critical=0,high=3", params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

# -----------------------------------------------------------------------------
# Pod-template (Deployment) propagation
# -----------------------------------------------------------------------------

test_deployment_template_annotation_deny if {
	input_obj := {
		"review": {"object": {
			"kind": "Deployment",
			"metadata": {"name": "d", "namespace": "demo"},
			"spec": {"template": {
				"metadata": {"annotations": {"inspector.aws/findings": "critical=2,high=10"}},
				"spec": {"containers": [{"name": "app", "image": "x.invalid/y:z"}]},
			}},
		}},
		"parameters": default_params,
	}
	result := k8sblockhighcve.violation with input as input_obj
	count(result) >= 1
}

test_deployment_template_annotation_allow if {
	input_obj := {
		"review": {"object": {
			"kind": "Deployment",
			"metadata": {"name": "d", "namespace": "demo"},
			"spec": {"template": {
				"metadata": {"annotations": {"inspector.aws/findings": "critical=0,high=0"}},
				"spec": {"containers": [{"name": "app", "image": "x.invalid/y:z"}]},
			}},
		}},
		"parameters": default_params,
	}
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}

# -----------------------------------------------------------------------------
# Whitespace tolerance in the findings string.
# -----------------------------------------------------------------------------

test_findings_with_whitespace_parsed_correctly if {
	# The pipeline may write annotation values with spaces. Parser must trim.
	input_obj := make_pod_with_findings(" critical = 0 , high = 0 , medium = 2 ", default_params)
	count(k8sblockhighcve.violation) == 0 with input as input_obj
}
