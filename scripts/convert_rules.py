#!/usr/bin/env python3
"""Convert Sigma rules to Splunk SPL, Elasticsearch Lucene, or Sentinel KQL."""

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from sigma.rule import SigmaRule
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


TARGETS = {
    "splunk": {"label": "Splunk SPL", "extension": "spl"},
    "elasticsearch": {"label": "Elasticsearch Lucene", "extension": "lucene"},
    "sentinel": {"label": "Microsoft Sentinel KQL", "extension": "kql"},
}


class BackendUnavailableError(RuntimeError):
    """Raised when a selected pySigma target package is not installed."""


SENTINEL_FIELD_RENAMES = {
    # Sentinel ASIM normalizes Windows logon type as its logon-method field.
    "LogonType": "LogonMethod",
    # Windows Security event account field to Sentinel ASIM authentication field.
    "TargetUserName": "TargetUsername",
    # Service image paths are represented as audited objects in ASIM.
    "ServiceFileName": "Object",
}


def _rename_sentinel_fields(value: Any) -> Any:
    """Recursively rename Windows-only fields to their Sentinel ASIM equivalents."""
    if isinstance(value, list):
        return [_rename_sentinel_fields(item) for item in value]
    if not isinstance(value, dict):
        return value

    renamed = {}
    for key, item in value.items():
        field, separator, modifiers = key.partition("|")
        renamed_field = SENTINEL_FIELD_RENAMES.get(field, field)
        renamed_key = separator.join((renamed_field, modifiers)) if separator else renamed_field
        renamed[renamed_key] = _rename_sentinel_fields(item)
    return renamed


def _sentinel_query_table(rule: Any) -> str | None:
    """Choose an ASIM table for rule categories not inferred by the backend."""
    category = rule.logsource.category
    service = rule.logsource.service
    if category in {"process_creation", "process_access"}:
        return "imProcessCreate"
    if category in {"registry_add", "registry_delete", "registry_event", "registry_set"}:
        return "imRegistry"
    if service == "security":
        return "imAuthentication"
    if service == "system":
        return "imAuditEvent"
    return None


class SentinelBackend:
    """Adapt each Sigma rule to its appropriate Microsoft Sentinel ASIM table."""

    def __init__(self, backend_class: Any, pipeline_factory: Any):
        self._backend_class = backend_class
        self._pipeline_factory = pipeline_factory

    def convert_rule(self, rule: Any) -> list[str]:
        pipeline = self._pipeline_factory(query_table=_sentinel_query_table(rule))
        return self._backend_class(processing_pipeline=pipeline).convert_rule(rule)


def _build_splunk_backend() -> Any:
    """Build a Splunk backend with available Windows processing pipelines."""
    try:
        from sigma.backends.splunk import SplunkBackend
    except ImportError as exc:
        raise BackendUnavailableError(
            "Install pySigma-backend-splunk to convert to Splunk SPL."
        ) from exc

    pipelines = []
    for module_name, factory_name in (
        ("sigma.pipelines.splunk", "splunk_windows_pipeline"),
        ("sigma.pipelines.sysmon", "sysmon_pipeline"),
        ("sigma.pipelines.windows", "windows_logsource_pipeline"),
    ):
        try:
            module = __import__(module_name, fromlist=[factory_name])
            pipelines.append(getattr(module, factory_name)())
        except (ImportError, AttributeError):
            continue

    if not pipelines:
        return SplunkBackend()
    pipeline = pipelines[0]
    for item in pipelines[1:]:
        pipeline += item
    return SplunkBackend(processing_pipeline=pipeline)


def _build_elasticsearch_backend() -> Any:
    """Build an Elasticsearch Lucene backend with ECS Windows mappings."""
    try:
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.pipelines.elasticsearch.windows import ecs_windows
    except ImportError as exc:
        raise BackendUnavailableError(
            "Install pySigma-backend-elasticsearch to convert to Elasticsearch."
        ) from exc
    return LuceneBackend(processing_pipeline=ecs_windows())


def _build_sentinel_backend() -> Any:
    """Build a Kusto backend with the Microsoft Sentinel ASIM pipeline."""
    try:
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
    except ImportError as exc:
        raise BackendUnavailableError(
            "Install pySigma-backend-kusto to convert to Microsoft Sentinel KQL."
        ) from exc
    return SentinelBackend(KustoBackend, sentinel_asim_pipeline)


def build_backend(target: str) -> Any:
    """Return the configured pySigma backend for *target*."""
    builders = {
        "splunk": _build_splunk_backend,
        "elasticsearch": _build_elasticsearch_backend,
        "sentinel": _build_sentinel_backend,
    }
    if target not in builders:
        raise ValueError(f"Unsupported target '{target}'. Choose from: {', '.join(TARGETS)}")
    return builders[target]()


def _build_backend() -> Any:
    """Backward-compatible alias for callers that expect the Splunk backend."""
    return build_backend("splunk")


def convert_rule_file(rule_path: Path, backend: Any, target: str = "splunk") -> dict:
    """Convert one Sigma file and return its query plus source metadata."""
    rule_text = rule_path.read_text(encoding="utf-8")
    if target == "sentinel":
        rule_data = yaml.safe_load(rule_text)
        rule_data["detection"] = _rename_sentinel_fields(rule_data["detection"])
        rule_text = yaml.safe_dump(rule_data, sort_keys=False)
    sigma_rule = SigmaRule.from_yaml(rule_text)
    return {
        "title": sigma_rule.title,
        "id": str(sigma_rule.id) if sigma_rule.id else "unknown",
        "level": sigma_rule.level.name if sigma_rule.level else "unknown",
        "queries": backend.convert_rule(sigma_rule),
        "source_file": str(rule_path),
        "target": target,
    }


def _write_queries(result: dict, rule_path: Path, output_dir: Path, target: str) -> None:
    """Write vendor-specific query files with metadata headers."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{rule_path.stem}.{TARGETS[target]['extension']}"
    with output_file.open("w", encoding="utf-8") as handle:
        comment_prefix = {"splunk": "| #", "sentinel": "//"}.get(target)
        if comment_prefix:
            handle.write(f"{comment_prefix} Title:  {result['title']}\n")
            handle.write(f"{comment_prefix} ID:     {result['id']}\n")
            handle.write(f"{comment_prefix} Level:  {result['level']}\n")
            handle.write(f"{comment_prefix} Source: {result['source_file']}\n\n")
        handle.write("\n".join(result["queries"]))
        handle.write("\n")


def convert_all(
    rules_dir: Path,
    target: str = "splunk",
    output_dir: Path | None = None,
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Convert all rules in *rules_dir* for a single vendor target."""
    backend = build_backend(target)
    rule_files = sorted(list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml")))
    if not rule_files:
        print(f"No rule files found in {rules_dir}")
        return [], []

    results: list[dict] = []
    errors: list[tuple[str, str]] = []
    print(f"Target: {TARGETS[target]['label']}")
    for rule_file in rule_files:
        try:
            result = convert_rule_file(rule_file, backend, target)
            results.append(result)
            print(f"[OK] {result['title']}")
            for query in result["queries"]:
                print(f"     Query: {query}")
            if output_dir:
                _write_queries(result, rule_file, output_dir, target)
        except Exception as exc:  # noqa: BLE001
            errors.append((str(rule_file), str(exc)))
            print(f"[FAIL] {rule_file.name}: {exc}")

    print(f"\n{'=' * 60}\nConversion Summary\n{'=' * 60}")
    print(f"  Target    : {TARGETS[target]['label']}")
    print(f"  Converted : {len(results)}")
    print(f"  Errors    : {len(errors)}")
    if output_dir:
        print(f"  Output dir: {output_dir}")
    return results, errors


def main() -> int:
    """Run the converter from the command line."""
    if not PYSIGMA_AVAILABLE:
        print("ERROR: pySigma is not installed. Run: pip install -r requirements.txt")
        return 2

    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to Splunk SPL, Elasticsearch Lucene, or Sentinel KQL."
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "rules",
        help="Directory containing Sigma rules (default: rules/)",
    )
    parser.add_argument(
        "--target",
        choices=[*TARGETS, "all"],
        action="append",
        default=None,
        help="Target to convert. Repeat for several targets; default: splunk.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for query files; multiple targets create subdirectories.",
    )
    args = parser.parse_args()

    if not args.rules_dir.exists():
        print(f"FATAL: Rules directory not found: {args.rules_dir}")
        return 2

    requested = args.target or ["splunk"]
    targets = list(TARGETS) if "all" in requested else list(dict.fromkeys(requested))
    failures = 0
    for target in targets:
        target_output_dir = (
            args.output_dir / target if args.output_dir and len(targets) > 1 else args.output_dir
        )
        try:
            _, errors = convert_all(args.rules_dir, target, target_output_dir)
            failures += len(errors)
        except BackendUnavailableError as exc:
            failures += 1
            print(f"[FAIL] {TARGETS[target]['label']}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
