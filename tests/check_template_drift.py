#!/usr/bin/env python3
"""Detect drift between standalone Rego policies and the Rego embedded inside
Gatekeeper ConstraintTemplates.

The standalone policy files (``policies/gatekeeper/*.rego``) are the source of
truth for unit tests and for human review. The same logic is also embedded
verbatim inside ``policies/gatekeeper/constraints.yaml`` so that ``kubectl
apply -f constraints.yaml`` installs both the templates and the constraints in
one step.

Keeping the two in sync is critical -- if the embedded Rego diverges from the
standalone .rego, unit tests pass while admission control silently runs old
logic. This script extracts the embedded Rego, normalises it, and compares it
to the standalone file at a tokens-only level (ignoring header comments and
the small syntactic differences between "v0" Rego inside ConstraintTemplates
and "v1" Rego in the standalone files).

Exit codes:
    0   no drift detected
    1   drift detected (with a unified diff printed to stderr)
    2   internal error (missing files, unparsable YAML, ...)
"""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable
from difflib import unified_diff
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO_ROOT / "policies" / "gatekeeper"
CONSTRAINTS_YAML = POLICY_DIR / "constraints.yaml"

# Map of ConstraintTemplate name -> the standalone .rego file that should
# match its embedded body. Keep this list in sync as new policies are added.
TEMPLATE_TO_REGO: dict[str, str] = {
    "k8srequiresignedimages": "require-signed-images.rego",
    "k8sblockhighcve": "block-high-cve.rego",
}


def normalise_rego(text: str) -> list[str]:
    """Return a canonical token sequence for a Rego file.

    Normalisation steps:
      * Strip Rego header comments (lines starting with ``#``) -- the
        standalone files have long banners that are not present inside the
        ConstraintTemplate.
      * Drop ``import future.keywords.*`` directives -- ConstraintTemplates
        running on the older Rego v0 dialect declare these (or not)
        differently than the standalone file.
      * Translate the v1 ``violation contains ... if { ... }`` form to the
        v0 ``violation[ ... ] { ... }`` form so both files reduce to the
        same canonical shape.
      * Collapse consecutive whitespace and remove blank lines.
    """
    # 1. Strip full-line comments and trailing inline comments.
    lines: list[str] = []
    for raw in text.splitlines():
        stripped = raw.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        if stripped.lstrip().startswith("import future.keywords"):
            continue
        lines.append(stripped)

    body = "\n".join(lines)

    # 2. Translate v1 -> v0 syntax.
    #    `violation contains X if {` -> `violation[X] {`
    body = re.sub(
        r"violation\s+contains\s+(\{[^}]*\})\s+if\s*\{",
        r"violation[\1] {",
        body,
    )
    #    `input_containers contains X if {` -> `input_containers[X] {`
    body = re.sub(
        r"(\w+)\s+contains\s+(\w+)\s+if\s*\{",
        r"\1[\2] {",
        body,
    )
    #    `X(args) if {` -> `X(args) {`        (function-style)
    body = re.sub(r"(\w+\([^)]*\))\s+if\s*\{", r"\1 {", body)
    #    `name if {` -> `name {`              (rule-without-args)
    body = re.sub(r"^\s*(\w+)\s+if\s*\{", r"\1 {", body, flags=re.M)
    #    `X := Y if {` -> `X := Y {`
    body = re.sub(r":=\s+(\w+)\s+if\s*\{", r":= \1 {", body)

    # 3. Tokenise on whitespace.
    tokens = body.split()
    return tokens


def load_constraint_template_rego(yaml_path: Path) -> dict[str, str]:
    """Return {template_name_lower: embedded_rego_string} for every
    ConstraintTemplate document found in ``yaml_path``."""
    out: dict[str, str] = {}
    with yaml_path.open() as fh:
        documents = list(yaml.safe_load_all(fh))
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") != "ConstraintTemplate":
            continue
        name = (doc.get("metadata") or {}).get("name", "").lower()
        targets = ((doc.get("spec") or {}).get("targets") or [])
        for tgt in targets:
            rego = tgt.get("rego")
            if rego:
                out[name] = rego
                break
    return out


def diff_tokens(a: Iterable[str], b: Iterable[str], a_label: str, b_label: str) -> str:
    """Return a unified diff string between two token sequences, or empty
    string if they are identical."""
    a_list = list(a)
    b_list = list(b)
    if a_list == b_list:
        return ""
    diff_lines = unified_diff(a_list, b_list, fromfile=a_label, tofile=b_label, lineterm="")
    return "\n".join(diff_lines)


def main() -> int:
    if not CONSTRAINTS_YAML.is_file():
        print(f"ERROR: missing {CONSTRAINTS_YAML}", file=sys.stderr)
        return 2

    try:
        embedded = load_constraint_template_rego(CONSTRAINTS_YAML)
    except yaml.YAMLError as exc:
        print(f"ERROR: cannot parse {CONSTRAINTS_YAML}: {exc}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for template_name, rego_filename in TEMPLATE_TO_REGO.items():
        standalone_path = POLICY_DIR / rego_filename
        if not standalone_path.is_file():
            failures.append(f"missing standalone Rego: {standalone_path}")
            continue
        if template_name not in embedded:
            failures.append(
                f"ConstraintTemplate {template_name!r} not found in constraints.yaml"
            )
            continue

        a = normalise_rego(standalone_path.read_text())
        b = normalise_rego(embedded[template_name])
        diff = diff_tokens(
            a,
            b,
            f"{rego_filename} (standalone)",
            f"constraints.yaml::{template_name}",
        )
        if diff:
            failures.append(
                f"DRIFT: {rego_filename} <-> {template_name} embedded body\n{diff}"
            )
        else:
            print(f"OK: {rego_filename} matches embedded {template_name}")

    if failures:
        for msg in failures:
            print(msg, file=sys.stderr)
        print(
            "\nFix the embedded Rego in policies/gatekeeper/constraints.yaml "
            "to match the standalone file (or vice versa).",
            file=sys.stderr,
        )
        return 1

    print("\nNo drift detected across all ConstraintTemplates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
