#!/usr/bin/env python3
"""
Convert Sigma rules to Splunk SPL queries using pySigma.

This script loads all Sigma YAML rules from the rules/ directory,
applies the Splunk Windows processing pipeline, and outputs the
resulting SPL queries to the console or to files under --output-dir.

Usage:
    python scripts/convert_rules.py
    python scripts/convert_rules.py --output-dir output/splunk/
    python scripts/convert_rules.py --rules-dir rules/windows/process_creation/
"""

import argparse
import sys
from pathlib import Path

import yaml

try:
    from sigma.rule import SigmaRule
    from sigma.backends.splunk import SplunkBackend
    from sigma.processing.pipeline import ProcessingPipeline

    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


def _build_backend() -> "SplunkBackend":
    """Build a SplunkBackend with the best available pipeline."""
    pipelines = []

    # Try to load community-maintained pipelines (optional dependencies)
    try:
        from sigma.pipelines.splunk import splunk_windows_pipeline
        pipelines.append(splunk_windows_pipeline())
    except ImportError:
        pass

    try:
        from sigma.pipelines.sysmon import sysmon_pipeline
        pipelines.append(sysmon_pipeline())
    except ImportError:
        pass

    try:
        from sigma.pipelines.windows import windows_pipeline
        pipelines.append(windows_pipeline())
    except ImportError:
        pass

    if pipelines:
        # Merge all available pipelines
        combined = pipelines[0]
        for p in pipelines[1:]:
            combined += p
        return SplunkBackend(processing_pipeline=combined)

    # Fallback: no pipeline — generic Sigma-to-SPL conversion
    return SplunkBackend()


def convert_rule_file(rule_path: Path, backend: "SplunkBackend") -> dict:
    """Convert a single Sigma rule file to Splunk SPL.

    Returns a dict with title, id, level, queries, and source_file.
    Raises on any conversion error.
    """
    with open(rule_path, "r", encoding="utf-8") as fh:
        rule_text = fh.read()

    sigma_rule = SigmaRule.from_yaml(rule_text)
    spl_queries = backend.convert_rule(sigma_rule)

    return {
        "title": sigma_rule.title,
        "id": str(sigma_rule.id) if sigma_rule.id else "unknown",
        "level": sigma_rule.level.name if sigma_rule.level else "unknown",
        "queries": spl_queries,
        "source_file": str(rule_path),
    }


def convert_all(rules_dir: Path, output_dir: Path | None = None):
    """Convert every rule under *rules_dir*.  Prints and optionally writes results."""
    backend = _build_backend()

    rule_files = sorted(
        list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    )

    if not rule_files:
        print(f"No rule files found in {rules_dir}")
        return [], []

    results = []
    errors = []

    for rule_file in rule_files:
        try:
            result = convert_rule_file(rule_file, backend)
            results.append(result)

            print(f"[OK] {result['title']}")
            for query in result["queries"]:
                print(f"     SPL: {query}")
            print()

            # Optionally write to disk
            if output_dir:
                out_file = output_dir / f"{rule_file.stem}.spl"
                out_file.parent.mkdir(parents=True, exist_ok=True)
                with open(out_file, "w", encoding="utf-8") as fh:
                    fh.write(f"| # Title:  {result['title']}\n")
                    fh.write(f"| # ID:     {result['id']}\n")
                    fh.write(f"| # Level:  {result['level']}\n")
                    fh.write(f"| # Source: {result['source_file']}\n\n")
                    for query in result["queries"]:
                        fh.write(query + "\n")

        except Exception as exc:  # noqa: BLE001
            errors.append((str(rule_file), str(exc)))
            print(f"[FAIL] {rule_file.name}: {exc}\n")

    # Summary
    print(f"{'='*60}")
    print(f"Conversion Summary")
    print(f"{'='*60}")
    print(f"  Converted : {len(results)}")
    print(f"  Errors    : {len(errors)}")
    if output_dir:
        print(f"  Output dir: {output_dir}")

    return results, errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    if not PYSIGMA_AVAILABLE:
        print(
            "ERROR: pySigma or pySigma-backend-splunk is not installed.\n"
            "Install with: pip install pySigma pySigma-backend-splunk"
        )
        return 2

    parser = argparse.ArgumentParser(description="Convert Sigma rules to Splunk SPL")
    parser.add_argument(
        "--rules-dir", type=Path,
        default=Path(__file__).resolve().parent.parent / "rules",
        help="Directory containing Sigma rules (default: rules/)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None,
        help="Write .spl files to this directory",
    )
    args = parser.parse_args()

    if not args.rules_dir.exists():
        print(f"FATAL: Rules directory not found: {args.rules_dir}")
        return 2

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    _, errors = convert_all(args.rules_dir, args.output_dir)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
