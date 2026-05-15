#!/usr/bin/env python3
"""
query-findings — list recent Security Hub findings for triage.

Examples
--------
List CRITICAL/HIGH findings active in the last 24h, table output:

    ./scripts/query-findings.py --hours 24 --severity HIGH

JSON output, CRITICAL only, last week, only Inspector findings:

    ./scripts/query-findings.py --hours 168 --severity CRITICAL \
        --product Inspector --output json

Filter by workflow status (NEW only — already-triaged findings hidden):

    ./scripts/query-findings.py --workflow NEW
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError as exc:  # pragma: no cover - convenience for runtime
    sys.stderr.write("boto3 is required: pip install boto3\n")
    raise SystemExit(2) from exc

LOG = logging.getLogger("query-findings")

SEVERITY_ORDER = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Tput-style colour codes (only emit when stdout is a TTY).
_COLOR_TABLE = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[34m",
    "INFORMATIONAL": "\033[37m",
}
_RESET = "\033[0m"


@dataclass
class Finding:
    """Subset of ASFF fields we render for triage."""

    finding_id: str
    title: str
    severity: str
    product: str
    account: str
    region: str
    resource: str
    workflow: str
    record_state: str
    created_at: str
    updated_at: str

    @classmethod
    def from_asff(cls, raw: Dict[str, Any]) -> "Finding":
        """Build a Finding from a raw Security Hub ASFF document."""
        resources = raw.get("Resources") or []
        return cls(
            finding_id=raw.get("Id", ""),
            title=raw.get("Title", "")[:120],
            severity=(raw.get("Severity") or {}).get("Label", "UNKNOWN"),
            product=raw.get("ProductName", "unknown"),
            account=raw.get("AwsAccountId", "unknown"),
            region=raw.get("Region", "unknown"),
            resource=resources[0].get("Id", "n/a") if resources else "n/a",
            workflow=(raw.get("Workflow") or {}).get("Status", "NEW"),
            record_state=raw.get("RecordState", "ACTIVE"),
            created_at=raw.get("CreatedAt", ""),
            updated_at=raw.get("UpdatedAt", ""),
        )


def _build_filters(args: argparse.Namespace) -> Dict[str, Any]:
    """Build a Security Hub `Filters` dict from CLI args."""
    severities = [
        s for s in SEVERITY_ORDER if SEVERITY_ORDER[s] >= SEVERITY_ORDER[args.severity]
    ]

    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    filters: Dict[str, Any] = {
        "SeverityLabel": [{"Comparison": "EQUALS", "Value": s} for s in severities],
        "WorkflowStatus": [{"Comparison": "EQUALS", "Value": args.workflow}],
        "RecordState": [{"Comparison": "EQUALS", "Value": "ACTIVE"}],
        "UpdatedAt": [{"DateRange": {"Value": args.hours, "Unit": "HOURS"}}],
    }

    if args.product:
        filters["ProductName"] = [{"Comparison": "EQUALS", "Value": args.product}]

    if args.resource_type:
        filters["ResourceType"] = [
            {"Comparison": "PREFIX", "Value": args.resource_type}
        ]

    LOG.debug(
        "constructed filters covering since=%s severities=%s",
        cutoff.isoformat(),
        severities,
    )
    return filters


def _iter_findings(client: Any, filters: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Yield findings page-by-page (handles Security Hub pagination)."""
    paginator = client.get_paginator("get_findings")
    page_iter = paginator.paginate(
        Filters=filters,
        MaxResults=100,
        SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}],
    )
    for page in page_iter:
        yield from page.get("Findings", [])


def _render_table(findings: List[Finding], use_color: bool) -> str:
    """Render findings as a fixed-width text table."""
    if not findings:
        return "No findings matched the filter."

    headers = ["SEVERITY", "PRODUCT", "TITLE", "RESOURCE", "WORKFLOW", "UPDATED"]
    rows = [
        [
            f.severity,
            f.product[:18],
            f.title[:60],
            f.resource[-50:],  # tail of ARN is usually the most informative part.
            f.workflow,
            f.updated_at[:19].replace("T", " "),
        ]
        for f in findings
    ]

    widths = [
        max(len(str(row[col])) for row in [headers] + rows)
        for col in range(len(headers))
    ]

    def _fmt_row(row: List[str], color: Optional[str] = None) -> str:
        cells = "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row))
        if color and use_color:
            return f"{color}{cells}{_RESET}"
        return cells

    lines = [_fmt_row(headers)]
    lines.append("  ".join("-" * w for w in widths))
    for f, row in zip(findings, rows):
        lines.append(_fmt_row(row, _COLOR_TABLE.get(f.severity)))
    return "\n".join(lines)


def _render_json(findings: List[Finding]) -> str:
    """Render findings as JSON (one document per finding)."""
    return json.dumps([f.__dict__ for f in findings], indent=2, default=str)


def _build_client(region: Optional[str]) -> Any:
    """Build the Security Hub boto3 client with sensible retries."""
    config = Config(
        retries={"max_attempts": 8, "mode": "adaptive"},
        user_agent_extra="aws-supply-chain-security/query-findings",
    )
    if region:
        return boto3.client("securityhub", region_name=region, config=config)
    return boto3.client("securityhub", config=config)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="query-findings",
        description="List recent AWS Security Hub findings for triage.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--severity",
        choices=list(SEVERITY_ORDER),
        default="HIGH",
        help="Minimum severity label to include.",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Look back this many hours (UpdatedAt window).",
    )
    parser.add_argument(
        "--workflow",
        choices=["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"],
        default="NEW",
        help="Workflow status to filter on.",
    )
    parser.add_argument(
        "--product",
        help="Filter by Security Hub product name (e.g. Inspector, GuardDuty).",
    )
    parser.add_argument(
        "--resource-type",
        help="Filter by resource type prefix (e.g. AwsEcrContainerImage).",
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION"),
        help="AWS region to query (defaults to AWS_REGION env var).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of findings to print.",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour in table output.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    try:
        client = _build_client(args.region)
        filters = _build_filters(args)

        findings: List[Finding] = []
        for raw in _iter_findings(client, filters):
            findings.append(Finding.from_asff(raw))
            if len(findings) >= args.limit:
                break
    except (BotoCoreError, ClientError) as exc:
        LOG.error("AWS API call failed: %s", exc)
        return 1

    if args.output == "json":
        sys.stdout.write(_render_json(findings) + "\n")
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        sys.stdout.write(_render_table(findings, use_color) + "\n")
        sys.stdout.write(f"\n{len(findings)} finding(s) shown.\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
