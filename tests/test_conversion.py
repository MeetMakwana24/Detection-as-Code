"""Tests for vendor query conversion (scripts/convert_rules.py).

These tests verify that:
  1. The pySigma backend can parse each Sigma rule without exceptions.
  2. The resulting vendor query strings are non-empty.
  3. Key detection terms survive the conversion (sanity check).

IMPORTANT — All tests here are *synthetic*:
  - They confirm that the conversion pipeline produces structurally valid SPL.
  - They do NOT execute these queries against a live Splunk instance.
  - Validating that the queries return correct results against real Windows
    event logs is a separate, manual step documented in docs/TESTING.md.
"""

from pathlib import Path

import pytest

# Guard: skip entire module if pySigma backend is not installed
SplunkBackend = pytest.importorskip(
    "sigma.backends.splunk", reason="pySigma-backend-splunk not installed"
).SplunkBackend
SigmaRule = pytest.importorskip(
    "sigma.rule", reason="pySigma not installed"
).SigmaRule

from convert_rules import build_backend, convert_rule_file, _build_backend


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def backend():
    """Shared SplunkBackend instance (expensive to build)."""
    return _build_backend()


@pytest.fixture(scope="module")
def all_rule_files():
    """Discover all production rule files."""
    files = sorted(list(RULES_DIR.rglob("*.yml")) + list(RULES_DIR.rglob("*.yaml")))
    assert len(files) >= 5, f"Expected >= 5 rules, found {len(files)}"
    return files


# -----------------------------------------------------------------------
# Conversion tests (per rule)
# -----------------------------------------------------------------------

class TestConversion:
    """Verify that every production rule converts to non-empty SPL."""

    def test_all_rules_convert_successfully(self, all_rule_files, backend):
        """Each rule must convert without raising an exception."""
        failures = []
        for rule_file in all_rule_files:
            try:
                result = convert_rule_file(rule_file, backend)
                assert result["queries"], f"Empty SPL output for {rule_file.name}"
            except Exception as exc:
                failures.append(f"{rule_file.name}: {exc}")

        if failures:
            raise AssertionError(
                "Conversion failures:\n" + "\n".join(failures)
            )

    def test_powershell_rule_contains_key_terms(self, backend):
        path = RULES_DIR / "windows" / "process_creation" / "powershell_encoded_command.yml"
        result = convert_rule_file(path, backend)
        spl = " ".join(result["queries"]).lower()
        # The converted query should mention powershell and encoded command indicators
        assert "powershell" in spl or "pwsh" in spl, f"SPL missing powershell reference: {spl}"

    def test_lsass_rule_contains_key_terms(self, backend):
        path = RULES_DIR / "windows" / "process_creation" / "lsass_credential_dump.yml"
        result = convert_rule_file(path, backend)
        spl = " ".join(result["queries"]).lower()
        assert "lsass" in spl or "mimikatz" in spl or "comsvcs" in spl, (
            f"SPL missing LSASS-related terms: {spl}"
        )

    def test_schtasks_rule_contains_key_terms(self, backend):
        path = RULES_DIR / "windows" / "process_creation" / "suspicious_schtasks.yml"
        result = convert_rule_file(path, backend)
        spl = " ".join(result["queries"]).lower()
        assert "schtasks" in spl or "/create" in spl, (
            f"SPL missing schtasks reference: {spl}"
        )

    def test_conversion_result_has_metadata(self, all_rule_files, backend):
        """Converted results should include title, id, level, and queries."""
        for rule_file in all_rule_files:
            result = convert_rule_file(rule_file, backend)
            assert result["title"], f"Missing title in {rule_file.name}"
            assert result["id"] != "unknown", f"Missing id in {rule_file.name}"
            assert isinstance(result["queries"], list)


@pytest.mark.parametrize(
    ("target", "backend_module"),
    [
        ("elasticsearch", "sigma.backends.elasticsearch"),
        ("sentinel", "sigma.backends.kusto"),
    ],
)
def test_additional_vendor_targets_convert_all_rules(
    all_rule_files, target, backend_module
):
    """Each enabled vendor backend converts every production rule."""
    pytest.importorskip(backend_module)
    backend = build_backend(target)
    failures = []

    for rule_file in all_rule_files:
        try:
            result = convert_rule_file(rule_file, backend, target)
            assert result["queries"], f"Empty {target} output for {rule_file.name}"
        except Exception as exc:
            failures.append(f"{rule_file.name}: {exc}")

    if failures:
        raise AssertionError(
            f"{target} conversion failures:\n" + "\n".join(failures)
        )
