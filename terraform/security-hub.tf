###############################################################################
# AWS Security Hub — central aggregator for supply-chain findings.
#
# Why this exists:
#   - Inspector v2 (containers, EC2, Lambda), GuardDuty (runtime), and Config
#     (resource posture) all emit findings in different formats. Security Hub
#     normalises them into the AWS Security Finding Format (ASFF) and gives us
#     a single API + UI for triage.
#   - The AWS Foundational Security Best Practices (FSBP) standard adds
#     ~150 detective controls that map to CIS / NIST 800-53 — they catch the
#     long tail of misconfigurations that point-solutions miss (e.g. an ECR
#     repo accidentally created without scan-on-push elsewhere in the org).
#   - Inspector findings, once Inspector v2 is enabled (see inspector.tf),
#     auto-flow into Security Hub once we declare the product subscription.
#
# What this file owns:
#   1. Enabling the Security Hub account-level service.
#   2. Subscribing to the AWS FSBP standard (CIS/NIST/PCI are opt-in).
#   3. Wiring the Inspector v2 → Security Hub integration.
#   4. Optional integrations (GuardDuty, Macie, IAM Access Analyzer, Config,
#      Health) — gated by booleans so fresh accounts don't get charged for
#      services they don't use yet.
#   5. (Optional) cross-region finding aggregation when more than one region
#      is in scope. Defaults to single-region (this region only).
#   6. Two starter Insights (saved queries) for the highest-value views.
#
# What this file does NOT own:
#   - Notification routing — see findings-forwarder.tf.
#   - Custom suppressions — those belong with the team that owns the underlying
#     control (e.g. platform team owns insights for IAM rules).
###############################################################################

locals {
  partition = data.aws_partition.current.partition
  region    = data.aws_region.current.name

  # ARNs of AWS-managed standards available in Security Hub. Centralising as a
  # local makes it trivial to add a new standard by extending the list below.
  security_hub_standards = {
    aws_fsbp = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    cis      = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
    nist     = "arn:${local.partition}:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"
    pci_dss  = "arn:${local.partition}:securityhub:${local.region}::standards/pci-dss/v/3.2.1"
  }

  standards_to_enable = compact([
    local.security_hub_standards.aws_fsbp,
    var.enable_cis_standard ? local.security_hub_standards.cis : "",
    var.enable_nist_standard ? local.security_hub_standards.nist : "",
    var.enable_pci_standard ? local.security_hub_standards.pci_dss : "",
  ])

  # ARNs of integration *products* that send findings into Security Hub.
  # Each ARN has the form arn:aws:securityhub:REGION::product/aws/<product>.
  # Inspector is always-on (this project's primary source); the rest are
  # opt-in to keep blast radius small.
  product_arns = {
    inspector       = "arn:${local.partition}:securityhub:${local.region}::product/aws/inspector"
    guardduty       = "arn:${local.partition}:securityhub:${local.region}::product/aws/guardduty"
    macie           = "arn:${local.partition}:securityhub:${local.region}::product/aws/macie"
    access_analyzer = "arn:${local.partition}:securityhub:${local.region}::product/aws/access-analyzer"
    config          = "arn:${local.partition}:securityhub:${local.region}::product/aws/config"
    health          = "arn:${local.partition}:securityhub:${local.region}::product/aws/health"
  }

  products_to_enable = compact([
    local.product_arns.inspector,
    var.enable_guardduty_integration ? local.product_arns.guardduty : "",
    var.enable_macie_integration ? local.product_arns.macie : "",
    var.enable_access_analyzer_integration ? local.product_arns.access_analyzer : "",
    var.enable_config_integration ? local.product_arns.config : "",
    var.enable_health_integration ? local.product_arns.health : "",
  ])
}

# ---------------------------------------------------------------------------
# 1. Enable Security Hub for the account.
#
# `auto_enable_controls = true` means future controls added to subscribed
# standards are auto-enabled — preferred for security-first projects so we
# don't silently miss new AWS guidance.
#
# `control_finding_generator = "SECURITY_CONTROL"` switches the account to the
# consolidated control findings model: one finding per control per resource,
# de-duplicated across overlapping standards.
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  enable_default_standards  = false # we manage subscriptions explicitly below
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
}

# ---------------------------------------------------------------------------
# 2. Subscribe to standards.
# ---------------------------------------------------------------------------
resource "aws_securityhub_standards_subscription" "enabled" {
  for_each = toset(local.standards_to_enable)

  standards_arn = each.value

  depends_on = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# 3. Subscribe to product integrations.
# ---------------------------------------------------------------------------
resource "aws_securityhub_product_subscription" "enabled" {
  for_each = toset(local.products_to_enable)

  product_arn = each.value

  depends_on = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# 4. (Optional) cross-region finding aggregator.
# ---------------------------------------------------------------------------
resource "aws_securityhub_finding_aggregator" "this" {
  count = var.enable_finding_aggregation ? 1 : 0

  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# 5. Insight: open CRITICAL/HIGH findings on container resources.
#
# Insights are saved Security Hub queries surfaced on the dashboard. This one
# focuses ops on the highest-impact, action-required signal — open container
# findings, which is precisely the supply-chain failure mode this stack is
# built to detect.
# ---------------------------------------------------------------------------
resource "aws_securityhub_insight" "open_critical_container_findings" {
  name               = "${var.project_tag}-open-critical-container"
  group_by_attribute = "ResourceType"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NOTIFIED"
    }
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEcr"
    }
    resource_type {
      comparison = "PREFIX"
      value      = "AwsEksCluster"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  depends_on = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# 6. Insight: ECR misconfigurations failing FSBP controls.
# ---------------------------------------------------------------------------
resource "aws_securityhub_insight" "ecr_misconfigurations" {
  name               = "${var.project_tag}-ecr-misconfigurations"
  group_by_attribute = "ComplianceStatus"

  filters {
    generator_id {
      comparison = "PREFIX"
      value      = "aws-foundational-security-best-practices/v/1.0.0/ECR"
    }
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  depends_on = [aws_securityhub_standards_subscription.enabled]
}
