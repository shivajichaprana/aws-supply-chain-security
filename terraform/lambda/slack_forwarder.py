"""
Security Hub findings -> Slack forwarder.

Deployed by terraform/findings-forwarder.tf. Triggered directly by EventBridge
(Security Hub Findings - Imported event). One Lambda invocation per matched
finding, posted to a Slack incoming webhook with severity-coloured attachment.

The Slack webhook URL is fetched from AWS Secrets Manager at cold start so it
never appears in environment variables or CloudFormation drift output.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
SECRET_NAME = os.environ["SLACK_WEBHOOK_SECRET_NAME"]
MIN_SEVERITY = os.environ.get("MIN_SEVERITY", "HIGH").upper()

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

SEVERITY_ORDER: Dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_COLORS: Dict[str, str] = {
    "INFORMATIONAL": "#9aa3af",
    "LOW": "#3b82f6",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#dc2626",
}

SEVERITY_EMOJIS: Dict[str, str] = {
    "INFORMATIONAL": ":information_source:",
    "LOW": ":large_blue_circle:",
    "MEDIUM": ":warning:",
    "HIGH": ":fire:",
    "CRITICAL": ":rotating_light:",
}


@lru_cache(maxsize=1)
def _slack_webhook_url() -> str:
    """Fetch the Slack incoming-webhook URL from Secrets Manager (cached)."""
    client = boto3.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=SECRET_NAME)
    except ClientError as exc:
        logger.exception("failed to read slack webhook secret %s", SECRET_NAME)
        raise RuntimeError(f"could not load secret {SECRET_NAME}") from exc

    raw = response.get("SecretString")
    if not raw:
        raise RuntimeError(f"secret {SECRET_NAME} has no SecretString payload")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Allow plain-string secrets where the entire value IS the URL.
        return raw.strip()

    url = payload.get("webhook_url") or payload.get("url")
    if not url:
        raise RuntimeError(f"secret {SECRET_NAME} missing 'webhook_url' key")
    return url


def _meets_threshold(severity_label: str) -> bool:
    """Return True if `severity_label` is at or above MIN_SEVERITY."""
    label = (severity_label or "").upper()
    return SEVERITY_ORDER.get(label, -1) >= SEVERITY_ORDER.get(MIN_SEVERITY, 99)


def _console_url(account: str, region: str, finding_id: str) -> str:
    """Build a deep-link to the finding in the Security Hub console."""
    encoded = urllib.parse.quote(finding_id, safe="")
    return (
        f"https://{region}.console.aws.amazon.com/securityhub/home"
        f"?region={region}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{encoded}"
    )


def _format_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single ASFF finding into a Slack message attachment."""
    severity = (finding.get("Severity", {}).get("Label") or "INFORMATIONAL").upper()
    title = finding.get("Title", "Untitled finding")
    description = (finding.get("Description") or "").strip()
    if len(description) > 800:
        description = description[:797] + "..."

    account = finding.get("AwsAccountId", "unknown")
    region = finding.get("Region", "unknown")
    product = finding.get("ProductName", "unknown")
    resources: List[Dict[str, Any]] = finding.get("Resources") or []
    resource_summary = (
        ", ".join(r.get("Id", "?") for r in resources[:3]) if resources else "none"
    )

    finding_id = finding.get("Id", "")
    workflow = (finding.get("Workflow") or {}).get("Status", "NEW")
    remediation = (
        (finding.get("Remediation") or {}).get("Recommendation") or {}
    ).get("Text") or "No remediation guidance provided."

    fields = [
        {"title": "Account", "value": account, "short": True},
        {"title": "Region", "value": region, "short": True},
        {"title": "Product", "value": product, "short": True},
        {"title": "Workflow", "value": workflow, "short": True},
        {"title": "Resources", "value": resource_summary, "short": False},
        {"title": "Remediation", "value": remediation, "short": False},
    ]

    return {
        "color": SEVERITY_COLORS.get(severity, "#9aa3af"),
        "title": f"{SEVERITY_EMOJIS.get(severity, ':grey_question:')} [{severity}] {title}",
        "title_link": _console_url(account, region, finding_id),
        "text": description or "_no description_",
        "fields": fields,
        "footer": f"Security Hub | {product}",
        "mrkdwn_in": ["text", "fields"],
    }


def _post_to_slack(payload: Dict[str, Any]) -> None:
    """POST a Slack incoming-webhook payload."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url=_slack_webhook_url(),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.getcode()
            if status >= 300:
                raise RuntimeError(f"slack webhook returned HTTP {status}")
            logger.info("slack webhook ok (status=%s)", status)
    except urllib.error.URLError as exc:
        logger.exception("slack webhook delivery failed")
        raise RuntimeError("slack webhook delivery failed") from exc


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point. Returns delivery counts for CloudWatch metrics."""
    logger.debug("incoming event: %s", json.dumps(event)[:2000])

    findings = (event.get("detail") or {}).get("findings") or []
    if not findings:
        logger.info("event carried no findings; nothing to forward")
        return {"forwarded": 0, "skipped": 0}

    forwarded = 0
    skipped = 0
    for finding in findings:
        severity = (finding.get("Severity", {}).get("Label") or "").upper()
        if not _meets_threshold(severity):
            skipped += 1
            continue
        attachment = _format_finding(finding)
        _post_to_slack({"attachments": [attachment]})
        forwarded += 1

    logger.info("forwarded=%d skipped=%d", forwarded, skipped)
    return {"forwarded": forwarded, "skipped": skipped}
