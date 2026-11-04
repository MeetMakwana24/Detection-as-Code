#!/usr/bin/env python3
"""
Sigma Rule Validator for Detection-as-Code Pipeline.

Validates all Sigma YAML rules in the rules/ directory against:
  - YAML syntax correctness
  - Required field presence (title, id, status, description, author, date,
    logsource, detection, level)
  - UUID v4 format for rule IDs
  - Duplicate rule ID detection across all files
  - Valid status values (test, experimental, stable, deprecated, unsupported)
  - Valid severity levels (informational, low, medium, high, critical)
  - Logsource structure (must contain product, category, or service)
  - Detection structure (must contain a 'condition' key)
  - ATT&CK tag format (attack.tNNNN or attack.tNNNN.NNN)

Exit codes:
  0 - All rules passed validation
  1 - One or more validation errors found
  2 - Rules directory not found or other fatal error
"""

import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "author",
    "date", "logsource", "detection", "level",
]

VALID_STATUSES = {"test", "experimental", "stable", "deprecated", "unsupported"}

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

# Matches attack.tNNNN or attack.tNNNN.NNN (technique IDs)
# as well as attack.<tactic_name> (e.g., attack.execution)
ATTACK_TECHNIQUE_RE = re.compile(
    r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE
)
ATTACK_TACTIC_RE = re.compile(
    r"^attack\.[a-z][a-z_]+$"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ValidationError:
    """A single validation finding."""
    file: str
    message: str
    severity: str = "error"  # "error" or "warning"

    def __str__(self) -> str:
        tag = self.severity.upper()
        return f"{tag} [{self.file}]: {self.message}"


@dataclass
class ValidationResult:
    """Aggregated results from validating a set of rules."""
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    rules_checked: int = 0
    rules_passed: int = 0

    @property
    def has_errors(self) -> bool:
        return len(self.errors) > 0


# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

def validate_rule(filepath: Path, seen_ids: dict) -> List[ValidationError]:
    """Validate a single Sigma rule file and return a list of findings."""
    findings: List[ValidationError] = []
    rel = str(filepath)

    # --- YAML parsing ---
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return [ValidationError(rel, f"YAML parsing error: {exc}")]
    except OSError as exc:
        return [ValidationError(rel, f"File read error: {exc}")]

    if not isinstance(rule, dict):
        return [ValidationError(rel, "Rule file must contain a YAML mapping (key: value pairs)")]

    # --- Required fields ---
    for req in REQUIRED_FIELDS:
        if req not in rule:
            findings.append(ValidationError(rel, f"Missing required field: '{req}'"))

    # --- ID: UUID format + duplicate check ---
    if "id" in rule:
        rule_id = str(rule["id"])
        try:
            uuid.UUID(rule_id)
        except ValueError:
            findings.append(ValidationError(rel, f"Invalid UUID format for id: '{rule_id}'"))

        if rule_id in seen_ids:
            findings.append(
                ValidationError(rel, f"Duplicate rule ID '{rule_id}' (first seen in {seen_ids[rule_id]})")
            )
        else:
            seen_ids[rule_id] = rel

    # --- Status ---
    if "status" in rule and rule["status"] not in VALID_STATUSES:
        findings.append(
            ValidationError(rel, f"Invalid status '{rule['status']}'. "
                            f"Must be one of: {', '.join(sorted(VALID_STATUSES))}")
        )

    # --- Level ---
    if "level" in rule and rule["level"] not in VALID_LEVELS:
        findings.append(
            ValidationError(rel, f"Invalid level '{rule['level']}'. "
                            f"Must be one of: {', '.join(sorted(VALID_LEVELS))}")
        )

    # --- Logsource structure ---
    if "logsource" in rule:
        ls = rule["logsource"]
        if not isinstance(ls, dict):
            findings.append(ValidationError(rel, "logsource must be a YAML mapping"))
        else:
            has_key = any(k in ls for k in ("product", "category", "service"))
            if not has_key:
                findings.append(
                    ValidationError(rel, "logsource must contain at least one of: product, category, service")
                )

    # --- Detection structure ---
    if "detection" in rule:
        det = rule["detection"]
        if not isinstance(det, dict):
            findings.append(ValidationError(rel, "detection must be a YAML mapping"))
        elif "condition" not in det:
            findings.append(ValidationError(rel, "detection must include a 'condition' key"))

    # --- Tags / ATT&CK format ---
    if "tags" in rule:
        tags = rule["tags"]
        if not isinstance(tags, list):
            findings.append(ValidationError(rel, "tags must be a list"))
        else:
            for tag in tags:
                if not isinstance(tag, str):
                    findings.append(ValidationError(rel, f"Each tag must be a string, got: {type(tag).__name__}"))
                    continue
                if tag.startswith("attack."):
                    # Must be either a valid tactic name or technique ID
                    if not (ATTACK_TACTIC_RE.match(tag) or ATTACK_TECHNIQUE_RE.match(tag)):
                        findings.append(
                            ValidationError(rel,
                                            f"Malformed ATT&CK tag '{tag}'. "
                                            "Expected attack.<tactic> or attack.tNNNN[.NNN]",
                                            severity="warning")
                        )

    # --- Title length (warning only) ---
    if "title" in rule and isinstance(rule["title"], str) and len(rule["title"]) > 256:
        findings.append(ValidationError(rel, "Title exceeds 256 characters", severity="warning"))

    return findings


def validate_rules_directory(rules_dir: Path) -> ValidationResult:
    """Walk *rules_dir*, validate every .yml/.yaml file, and return results."""
    result = ValidationResult()
    seen_ids: dict = {}

    rule_files = sorted(
        list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    )

    if not rule_files:
        result.errors.append(
            ValidationError(str(rules_dir), "No .yml or .yaml rule files found")
        )
        return result

    for rule_file in rule_files:
        result.rules_checked += 1
        findings = validate_rule(rule_file, seen_ids)

        errs = [f for f in findings if f.severity == "error"]
        warns = [f for f in findings if f.severity == "warning"]

        result.errors.extend(errs)
        result.warnings.extend(warns)

        if not errs:
            result.rules_passed += 1

    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(rules_dir: Path | None = None) -> int:
    """Run validation and print results.  Returns the process exit code."""
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parent.parent / "rules"

    if not rules_dir.exists():
        print(f"FATAL: Rules directory not found: {rules_dir}")
        return 2

    result = validate_rules_directory(rules_dir)

    # Print findings
    for err in result.errors:
        print(err)
    for warn in result.warnings:
        print(warn)

    # Summary
    print(f"\n{'='*60}")
    print(f"Validation Summary")
    print(f"{'='*60}")
    print(f"  Rules checked : {result.rules_checked}")
    print(f"  Rules passed  : {result.rules_passed}")
    print(f"  Errors        : {len(result.errors)}")
    print(f"  Warnings      : {len(result.warnings)}")

    if result.has_errors:
        print(f"\n  RESULT: FAILED")
        return 1

    print(f"\n  RESULT: ALL RULES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
