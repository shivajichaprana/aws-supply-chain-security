# =============================================================================
# Gatekeeper Policy: block-high-cve
# =============================================================================
#
# Blocks pods (and pod-template owners: Deployment, StatefulSet, DaemonSet,
# Job, CronJob) whose images carry an annotation indicating that one or more
# CRITICAL CVEs were detected by Amazon Inspector v2.
#
# How the annotation is populated:
#
#   The CodeBuild pipeline (pipelines/buildspec.yml) queries Inspector v2 for
#   findings against the image digest immediately after `docker push`. The
#   pipeline writes the resulting severity counts onto the deployment as a
#   single annotation, for example:
#
#       inspector.aws/findings: "critical=2,high=11,medium=37,low=4"
#
#   The same annotation is propagated to the pod template by the GitOps tool
#   (Argo CD / Flux) when the manifest is rendered.
#
# Policy decision:
#
#   - If the annotation is MISSING, fail closed -- we cannot prove the image
#     is safe and policy requires that every image be scanned.
#   - If the annotation is PRESENT but critical>0 (or critical>=threshold
#     supplied via parameters), deny admission.
#   - The threshold for "high" severities is also configurable, defaulting to
#     unlimited (i.e. "high" alone does not block) but allowing teams to opt
#     in to a stricter posture per-namespace.
#
# Reviewers note: the package name `k8sblockhighcve` matches the corresponding
# ConstraintTemplate `K8sBlockHighCVE` declared in constraints.yaml. Keep the
# two in sync.

package k8sblockhighcve

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# -----------------------------------------------------------------------------
# 1. Missing annotation -> deny (fail closed).
# -----------------------------------------------------------------------------
violation contains {"msg": msg, "details": details} if {
	# Only need to evaluate once per object, not once per container.
	annotation_missing
	msg := sprintf(
		"image is missing Inspector findings annotation %q -- every image must be scanned before deploy",
		[findings_annotation_key],
	)
	details := {"annotation": findings_annotation_key}
}

# -----------------------------------------------------------------------------
# 2. Critical findings exceed threshold -> deny.
# -----------------------------------------------------------------------------
violation contains {"msg": msg, "details": details} if {
	not annotation_missing

	criticals := findings_count("critical")
	criticals > critical_threshold

	msg := sprintf(
		"image has %d CRITICAL Inspector findings (threshold = %d). Remediate via base-image bump or package patch.",
		[criticals, critical_threshold],
	)
	details := {
		"critical":  criticals,
		"threshold": critical_threshold,
		"findings":  findings_raw,
	}
}

# -----------------------------------------------------------------------------
# 3. High findings exceed (optional, opt-in) threshold -> deny.
# -----------------------------------------------------------------------------
violation contains {"msg": msg, "details": details} if {
	not annotation_missing

	highs := findings_count("high")
	highs > high_threshold
	high_threshold >= 0  # negative threshold means "do not evaluate"

	msg := sprintf(
		"image has %d HIGH Inspector findings (threshold = %d).",
		[highs, high_threshold],
	)
	details := {
		"high":      highs,
		"threshold": high_threshold,
		"findings":  findings_raw,
	}
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

findings_annotation_key := "inspector.aws/findings"

# Raw annotation value -- e.g. "critical=2,high=11,medium=37,low=4"
findings_raw := value if {
	value := input.review.object.metadata.annotations[findings_annotation_key]
} else := value if {
	value := input.review.object.spec.template.metadata.annotations[findings_annotation_key]
} else := ""

annotation_missing if {
	findings_raw == ""
}

# Parse the comma-separated key=value list into a map { severity: count }.
findings_map := result if {
	pairs := split(findings_raw, ",")
	result := {key: count |
		pair := pairs[_]
		kv := split(pair, "=")
		count(kv) == 2
		key := lower(trim_space(kv[0]))
		count := to_number(trim_space(kv[1]))
	}
}

findings_count(severity) := n if {
	n := findings_map[severity]
} else := 0

# critical_threshold: number of critical findings tolerated before deny.
# Default 0 -- a single CRITICAL is enough to block.
critical_threshold := t if {
	t := input.parameters.criticalThreshold
} else := 0

# high_threshold: -1 disables the check; >=0 enforces.
high_threshold := t if {
	t := input.parameters.highThreshold
} else := -1
