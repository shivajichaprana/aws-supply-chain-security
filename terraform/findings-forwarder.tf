###############################################################################
# Security Hub findings -> EventBridge -> SNS -> Slack forwarder.
#
# Pipeline:
#
#   Security Hub Imported Finding (severity >= threshold)
#         │
#         ▼
#   EventBridge default bus (rule: aws.securityhub - Security Hub Findings - Imported)
#         │
#         ├──> SNS topic ────────► (optional) email subscriber for permanent record
#         │
#         └──> Slack-forwarder Lambda  ─────► incoming Slack webhook
#                                              (URL fetched from Secrets Manager
#                                               at cold-start; never stored in env)
#
# Design notes:
#   - We listen on the default event bus because Security Hub publishes
#     "Security Hub Findings - Imported" events there with no extra setup.
#   - The EventBridge pattern filters by severity label so MEDIUM/LOW noise
#     doesn't page the team. The threshold is configurable via
#     `finding_severity_threshold` (defaults to HIGH).
#   - SNS is the durable fan-out point. Slack is one consumer; teams can
#     subscribe additional endpoints (e.g. PagerDuty https subscription, an
#     SQS queue for archiving) without changing the Lambda.
#   - The Lambda reads the Slack webhook URL from Secrets Manager at cold
#     start and caches it. Storing the webhook directly in env vars would be
#     visible to anyone with iam:GetFunctionConfiguration on the function.
###############################################################################

locals {
  forwarder_name = "${var.project_tag}-securityhub-forwarder"

  # Severity values >= the configured threshold.
  severity_levels   = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  threshold_index   = index(local.severity_levels, var.finding_severity_threshold)
  matched_severities = slice(local.severity_levels, local.threshold_index, length(local.severity_levels))

  # Whether to deploy the Slack Lambda. Without a secret name we still ship
  # the SNS topic + EventBridge rule so other consumers can hang off them.
  deploy_slack_lambda = var.slack_webhook_secret_name != null
}

# ---------------------------------------------------------------------------
# 1. SNS topic — durable fan-out for findings.
# ---------------------------------------------------------------------------
resource "aws_kms_key" "sns" {
  description             = "CMK for SNS topic encrypting Security Hub finding events."
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRoot"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowSnsService"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      },
      {
        Sid       = "AllowEventsService"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "sns" {
  name          = "alias/${var.project_tag}-securityhub-sns"
  target_key_id = aws_kms_key.sns.key_id
}

resource "aws_sns_topic" "findings" {
  name              = "${var.project_tag}-securityhub-findings"
  kms_master_key_id = aws_kms_key.sns.id

  # Server-side delivery policy: short, capped retries to avoid backing up
  # behind a flapping subscriber.
  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayTarget     = 5
        maxDelayTarget     = 60
        numRetries         = 5
        numMaxDelayRetries = 0
        numNoDelayRetries  = 0
        numMinDelayRetries = 0
        backoffFunction    = "exponential"
      }
      disableSubscriptionOverrides = false
    }
  })
}

resource "aws_sns_topic_policy" "findings" {
  arn = aws_sns_topic.findings.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.findings.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.security_hub_findings.arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.findings.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# Optional email subscription — useful for permanent compliance records.
resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email == null ? 0 : 1
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------------------------------------------------------------------------
# 2. EventBridge rule — match Security Hub findings >= threshold.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${var.project_tag}-securityhub-findings"
  description = "Forward Security Hub Imported findings (>= ${var.finding_severity_threshold}) to SNS + Slack."

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = local.matched_severities
        }
        Workflow = {
          Status = ["NEW", "NOTIFIED"]
        }
        RecordState = ["ACTIVE"]
      }
    }
  })

  depends_on = [aws_securityhub_account.this]
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "sns"
  arn       = aws_sns_topic.findings.arn

  # Use input transformation to keep the SNS message compact and human-readable.
  # The transformer extracts only the most actionable fields per finding.
  input_transformer {
    input_paths = {
      account     = "$.detail.findings[0].AwsAccountId"
      region      = "$.region"
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      product     = "$.detail.findings[0].ProductName"
      resource    = "$.detail.findings[0].Resources[0].Id"
      finding_id  = "$.detail.findings[0].Id"
      created_at  = "$.detail.findings[0].CreatedAt"
    }
    input_template = <<EOT
{
  "severity": "<severity>",
  "title": "<title>",
  "product": "<product>",
  "account": "<account>",
  "region": "<region>",
  "resource": "<resource>",
  "finding_id": "<finding_id>",
  "created_at": "<created_at>"
}
EOT
  }
}

resource "aws_cloudwatch_event_target" "to_lambda" {
  count = local.deploy_slack_lambda ? 1 : 0

  rule      = aws_cloudwatch_event_rule.security_hub_findings.name
  target_id = "slack-forwarder"
  arn       = aws_lambda_function.slack_forwarder[0].arn
}

# ---------------------------------------------------------------------------
# 3. Slack forwarder Lambda.
# ---------------------------------------------------------------------------
data "archive_file" "slack_forwarder_zip" {
  count = local.deploy_slack_lambda ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/.build/slack_forwarder.zip"

  source {
    filename = "index.py"
    content  = file("${path.module}/lambda/slack_forwarder.py")
  }
}

resource "aws_iam_role" "slack_forwarder" {
  count = local.deploy_slack_lambda ? 1 : 0

  name = "${local.forwarder_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "slack_forwarder" {
  count = local.deploy_slack_lambda ? 1 : 0

  name = "${local.forwarder_name}-policy"
  role = aws_iam_role.slack_forwarder[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.slack_forwarder[0].arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = "arn:${local.partition}:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:${var.slack_webhook_secret_name}-*"
      },
    ]
  })
}

resource "aws_cloudwatch_log_group" "slack_forwarder" {
  count = local.deploy_slack_lambda ? 1 : 0

  name              = "/aws/lambda/${local.forwarder_name}"
  retention_in_days = var.lambda_log_retention_days
}

resource "aws_lambda_function" "slack_forwarder" {
  count = local.deploy_slack_lambda ? 1 : 0

  function_name = local.forwarder_name
  role          = aws_iam_role.slack_forwarder[0].arn
  handler       = "index.handler"
  runtime       = "python3.12"
  timeout       = 15
  memory_size   = 256

  filename         = data.archive_file.slack_forwarder_zip[0].output_path
  source_code_hash = data.archive_file.slack_forwarder_zip[0].output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_SECRET_NAME = var.slack_webhook_secret_name
      MIN_SEVERITY              = var.finding_severity_threshold
      LOG_LEVEL                 = "INFO"
    }
  }

  reserved_concurrent_executions = 5 # cap concurrency so a finding storm can't blow runtime quota.

  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_cloudwatch_log_group.slack_forwarder,
    aws_iam_role_policy.slack_forwarder,
  ]
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count = local.deploy_slack_lambda ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_forwarder[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}

# ---------------------------------------------------------------------------
# 4. Outputs.
# ---------------------------------------------------------------------------
output "findings_topic_arn" {
  description = "ARN of the SNS topic carrying Security Hub findings."
  value       = aws_sns_topic.findings.arn
}

output "findings_event_rule_name" {
  description = "Name of the EventBridge rule matching Security Hub findings."
  value       = aws_cloudwatch_event_rule.security_hub_findings.name
}

output "slack_forwarder_function_name" {
  description = "Name of the Slack forwarder Lambda (null when not deployed)."
  value       = local.deploy_slack_lambda ? aws_lambda_function.slack_forwarder[0].function_name : null
}

output "matched_severities" {
  description = "Severity labels currently routed to the forwarder."
  value       = local.matched_severities
}
