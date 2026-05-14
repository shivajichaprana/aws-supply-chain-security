# =============================================================================
# Gatekeeper Policy: require-signed-images
# =============================================================================
#
# Enforces that every container image deployed to the cluster carries a valid
# Cosign signature attestation. The signature is expected to be advertised on
# the pod via an annotation produced by the CI/CD pipeline (see
# pipelines/buildspec.yml -- `cosign sign` adds a corresponding annotation
# when the pod manifest is rendered by the deployment system).
#
# Two equally important paths are checked:
#
#   1. The pod (or pod-template) MUST declare the `cosign.sigstore.dev/signed`
#      annotation set to `"true"`.
#   2. The image reference MUST come from an approved registry list -- typically
#      the customer-owned ECR registries that the CodeBuild pipeline pushes to.
#      An image that lives outside those registries cannot have been signed by
#      our pipeline and therefore must be rejected.
#
# Reviewers note: the package name `k8srequiresignedimages` is the standard
# Gatekeeper convention -- the corresponding ConstraintTemplate
# `K8sRequireSignedImages` (see constraints.yaml) wires this Rego into the
# admission controller. Keep the two in sync.
#
# Test cases for this policy live in
# tests/gatekeeper/require_signed_images_test.rego and are run by the
# supply-chain-ci workflow on every PR.

package k8srequiresignedimages

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# Main violation rules. Gatekeeper invokes `data.<package>.violation` for every
# admission request and aggregates the messages returned by every matched rule.
# -----------------------------------------------------------------------------
violation contains {"msg": msg, "details": details} if {
	# Walk every container (init + side-car + main) in the pod spec.
	container := input_containers[_]

	# A container fails closed if the signature annotation is missing or false.
	not image_signed(container.image)

	msg := sprintf(
		"image %q is not signed by an approved Cosign profile (annotation %q missing or false)",
		[container.image, signature_annotation_key],
	)

	details := {
		"container":  container.name,
		"image":      container.image,
		"annotation": signature_annotation_key,
	}
}

violation contains {"msg": msg, "details": details} if {
	container := input_containers[_]
	not approved_registry(container.image)

	msg := sprintf(
		"image %q is not from an approved registry -- list provided via parameters.approvedRegistries",
		[container.image],
	)

	details := {
		"container":          container.name,
		"image":              container.image,
		"approvedRegistries": parameters_approved_registries,
	}
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# The annotation key the CI pipeline stamps on every Pod / PodTemplate after
# a successful Cosign signature verification step. Centralised so it can be
# changed in one place.
signature_annotation_key := "cosign.sigstore.dev/signed"

# image_signed is true iff the pod-level (or pod-template-level) annotation
# advertises the signature as verified.
image_signed(_image) if {
	val := pod_annotation(signature_annotation_key)
	val == "true"
}

# approved_registry walks the parameters list and returns true if the image
# reference begins with any of the allowed prefixes (registry/repo). A
# trailing slash is enforced to prevent prefix-confusion attacks where a
# malicious registry name could share a prefix with an approved one.
approved_registry(image) if {
	prefix := parameters_approved_registries[_]
	startswith(image, sprintf("%s/", [trim_suffix(prefix, "/")]))
}

# When the parameters block is empty we fail closed -- defence in depth.
parameters_approved_registries := registries if {
	registries := input.parameters.approvedRegistries
	count(registries) > 0
} else := []

# input_containers collapses init / ephemeral / main containers into one
# iterable list. Gatekeeper passes the full review object on input.review;
# the actual resource is at input.review.object.
input_containers contains container if {
	container := input.review.object.spec.containers[_]
}

input_containers contains container if {
	container := input.review.object.spec.initContainers[_]
}

input_containers contains container if {
	container := input.review.object.spec.template.spec.containers[_]
}

input_containers contains container if {
	container := input.review.object.spec.template.spec.initContainers[_]
}

# pod_annotation reads the annotation from whichever metadata block is present
# (Pod, Deployment, StatefulSet, Job, etc.). Returns "" when missing -- the
# caller must compare to "true" so missing annotations always fail closed.
pod_annotation(key) := value if {
	value := input.review.object.metadata.annotations[key]
} else := value if {
	value := input.review.object.spec.template.metadata.annotations[key]
} else := ""
