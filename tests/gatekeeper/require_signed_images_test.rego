# =============================================================================
# Unit tests for policies/gatekeeper/require-signed-images.rego
# =============================================================================
#
# These tests are run by `opa test policies/gatekeeper tests/gatekeeper` and
# by the supply-chain-ci workflow on every PR.
#
# Each test name follows the convention:
#
#   test_<scenario>_<expected_outcome>
#
# `_allow` cases assert that the policy produces zero violations on a known
# good input. `_deny_<reason>` cases assert exactly one (or more) violation
# is raised, AND assert on the reason string so refactors that change the
# message text without changing intent are caught.
# =============================================================================

package k8srequiresignedimages_test

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.k8srequiresignedimages

# -----------------------------------------------------------------------------
# Common fixtures
# -----------------------------------------------------------------------------

# The "approved" registry the test inputs reference. Mirrors the value used
# in policies/gatekeeper/constraints.yaml; the policy itself is registry-
# agnostic and reads the list from input.parameters.approvedRegistries.
approved_registry_prefix := "123456789012.dkr.ecr.us-east-1.amazonaws.com"

# Build an admission review object representing a Pod with the given
# annotation + container image. `extra` overrides individual fields.
make_pod(annotation_value, image) := obj if {
	obj := {
		"review": {
			"object": {
				"kind": "Pod",
				"metadata": {
					"name": "test-pod",
					"namespace": "demo",
					"annotations": {"cosign.sigstore.dev/signed": annotation_value},
				},
				"spec": {"containers": [{"name": "app", "image": image}]},
			},
		},
		"parameters": {"approvedRegistries": [approved_registry_prefix]},
	}
}

# Pod with NO annotations block at all.
make_pod_no_annotations(image) := obj if {
	obj := {
		"review": {
			"object": {
				"kind": "Pod",
				"metadata": {"name": "test-pod", "namespace": "demo"},
				"spec": {"containers": [{"name": "app", "image": image}]},
			},
		},
		"parameters": {"approvedRegistries": [approved_registry_prefix]},
	}
}

# Build a Deployment whose pod template carries the annotation.
make_deployment(annotation_value, image) := obj if {
	obj := {
		"review": {
			"object": {
				"kind": "Deployment",
				"metadata": {"name": "test-deploy", "namespace": "demo"},
				"spec": {"template": {
					"metadata": {"annotations": {"cosign.sigstore.dev/signed": annotation_value}},
					"spec": {"containers": [{"name": "app", "image": image}]},
				}},
			},
		},
		"parameters": {"approvedRegistries": [approved_registry_prefix]},
	}
}

# -----------------------------------------------------------------------------
# Allow cases
# -----------------------------------------------------------------------------

test_pod_signed_approved_registry_allow if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	count(k8srequiresignedimages.violation) == 0 with input as make_pod("true", good_image)
}

test_deployment_signed_approved_registry_allow if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	count(k8srequiresignedimages.violation) == 0 with input as make_deployment("true", good_image)
}

test_pod_multiple_approved_registries_allow if {
	good_image := "222222222222.dkr.ecr.eu-west-1.amazonaws.com/platform/api:v1"
	input_obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {
				"name": "p",
				"namespace": "demo",
				"annotations": {"cosign.sigstore.dev/signed": "true"},
			},
			"spec": {"containers": [{"name": "app", "image": good_image}]},
		}},
		"parameters": {"approvedRegistries": [
			"111111111111.dkr.ecr.us-east-1.amazonaws.com",
			"222222222222.dkr.ecr.eu-west-1.amazonaws.com",
		]},
	}
	count(k8srequiresignedimages.violation) == 0 with input as input_obj
}

# -----------------------------------------------------------------------------
# Deny cases -- signature
# -----------------------------------------------------------------------------

test_pod_missing_annotation_deny if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	result := k8srequiresignedimages.violation with input as make_pod_no_annotations(good_image)
	count(result) >= 1
	some v in result
	contains(v.msg, "not signed")
}

test_pod_annotation_false_deny if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	result := k8srequiresignedimages.violation with input as make_pod("false", good_image)
	count(result) >= 1
	some v in result
	contains(v.msg, "not signed")
}

test_pod_annotation_arbitrary_string_deny if {
	# Anything other than the exact string "true" must fail closed.
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	result := k8srequiresignedimages.violation with input as make_pod("maybe", good_image)
	count(result) >= 1
}

# -----------------------------------------------------------------------------
# Deny cases -- registry
# -----------------------------------------------------------------------------

test_pod_unapproved_registry_deny if {
	# Signed annotation present but image lives on a non-approved registry.
	bad_image := "evil-registry.example.invalid/app:v1"
	result := k8srequiresignedimages.violation with input as make_pod("true", bad_image)
	count(result) >= 1
	some v in result
	contains(v.msg, "not from an approved registry")
}

test_pod_prefix_confusion_attack_deny if {
	# An attacker registers a registry that shares a prefix with the approved
	# one. The startswith check requires a trailing slash, so this MUST deny.
	tricky := sprintf("%s.attacker.example/api:v1", [approved_registry_prefix])
	result := k8srequiresignedimages.violation with input as make_pod("true", tricky)
	count(result) >= 1
}

test_pod_empty_approved_registries_deny if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	input_obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {
				"name": "p",
				"namespace": "demo",
				"annotations": {"cosign.sigstore.dev/signed": "true"},
			},
			"spec": {"containers": [{"name": "app", "image": good_image}]},
		}},
		"parameters": {"approvedRegistries": []},
	}
	result := k8srequiresignedimages.violation with input as input_obj
	count(result) >= 1
}

# -----------------------------------------------------------------------------
# Multi-container coverage: a deny on ONE container must surface.
# -----------------------------------------------------------------------------

test_pod_one_bad_one_good_container_deny if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	bad_image := "evil.invalid/x:y"
	input_obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {
				"name": "p",
				"namespace": "demo",
				"annotations": {"cosign.sigstore.dev/signed": "true"},
			},
			"spec": {"containers": [
				{"name": "good", "image": good_image},
				{"name": "bad", "image": bad_image},
			]},
		}},
		"parameters": {"approvedRegistries": [approved_registry_prefix]},
	}
	result := k8srequiresignedimages.violation with input as input_obj
	count(result) >= 1
	some v in result
	contains(v.msg, "evil.invalid/x:y")
}

# init-containers must be evaluated alongside main containers.
test_init_container_unapproved_deny if {
	good_image := sprintf("%s/platform/api:abc123", [approved_registry_prefix])
	bad_image := "untrusted.invalid/init:v1"
	input_obj := {
		"review": {"object": {
			"kind": "Pod",
			"metadata": {
				"name": "p",
				"namespace": "demo",
				"annotations": {"cosign.sigstore.dev/signed": "true"},
			},
			"spec": {
				"initContainers": [{"name": "init", "image": bad_image}],
				"containers": [{"name": "main", "image": good_image}],
			},
		}},
		"parameters": {"approvedRegistries": [approved_registry_prefix]},
	}
	result := k8srequiresignedimages.violation with input as input_obj
	count(result) >= 1
}
