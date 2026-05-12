###############################################################################
# Amazon Inspector v2 — enhanced container vulnerability scanning.
#
# Notes:
#   - Inspector v2 is enabled at the *account* (or organization-delegated-admin)
#     level. The aws_inspector2_enabler resource is idempotent and may be
#     applied from multiple stacks in the same account; here we declare it
#     once as the canonical owner.
#   - ECR is the only scan target we enable by default. EC2 and Lambda
#     scanning are optional and controlled by `enable_inspector_ec2` and
#     `enable_inspector_lambda` to avoid surprise pricing in fresh accounts.
#   - Findings flow into Security Hub automatically once both services are
#     enabled (Security Hub wiring lives in security-hub.tf — see Day 52).
###############################################################################

locals {
  # Build the list of resource types Inspector should monitor. ECR is
  # always-on for this project; EC2/Lambda are opt-in.
  inspector_resource_types = compact([
    "ECR",
    var.enable_inspector_ec2 ? "EC2" : "",
    var.enable_inspector_lambda ? "LAMBDA" : "",
  ])
}

resource "aws_inspector2_enabler" "this" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = local.inspector_resource_types
}

# ---------------------------------------------------------------------------
# Tweak which severity findings get auto-suppressed.
#
# By default Inspector v2 emits findings for every severity (INFORMATIONAL ->
# CRITICAL). We do NOT suppress anything in this baseline — every finding
# should reach Security Hub so the team owns the triage. To suppress noisy
# findings, add an aws_inspector2_filter resource here keyed by finding
# criteria (e.g. `INFORMATIONAL` severity, specific package name).
# ---------------------------------------------------------------------------

# Placeholder filter showing the structure for future suppressions.
# Currently disabled by setting action = "NONE" so it has no effect.
resource "aws_inspector2_filter" "informational_noise" {
  name        = "${var.project_tag}-informational-noise"
  description = "Placeholder filter — suppress INFORMATIONAL findings if/when triage decides they are noise."
  action      = "NONE"

  filter_criteria {
    severity {
      comparison = "EQUALS"
      value      = "INFORMATIONAL"
    }
  }

  tags = {
    Purpose = "finding-suppression-template"
  }

  depends_on = [aws_inspector2_enabler.this]
}
