"""Tests for the Sigma rule validator (scripts/validate_rules.py).

All test data is *synthetic* — the fixtures/ directory contains
purpose-built YAML files designed to exercise specific validation checks.
These tests do NOT validate against actual Splunk log data.
"""

from pathlib import Path

from validate_rules import validate_rule, validate_rules_directory, ValidationResult


# -----------------------------------------------------------------------
# Individual rule validation
# -----------------------------------------------------------------------

class TestValidateRule:
    """Tests for validate_rule() on individual fixture files."""

    def test_valid_rule_passes(self, valid_rule_path):
        seen_ids = {}
        findings = validate_rule(valid_rule_path, seen_ids)
        errors = [f for f in findings if f.severity == "error"]
        assert errors == [], f"Expected no errors, got: {errors}"

    def test_invalid_yaml_detected(self, invalid_yaml_path):
        findings = validate_rule(invalid_yaml_path, {})
        errors = [f for f in findings if f.severity == "error"]
        assert len(errors) >= 1
        assert any("YAML parsing error" in e.message for e in errors)

    def test_missing_required_fields(self, missing_fields_path):
        findings = validate_rule(missing_fields_path, {})
        errors = [f for f in findings if f.severity == "error"]
        # Should flag at least id, status, author, date, level
        missing_field_errors = [e for e in errors if "Missing required field" in e.message]
        assert len(missing_field_errors) >= 5, (
            f"Expected >=5 missing-field errors, got {len(missing_field_errors)}: {missing_field_errors}"
        )

    def test_invalid_level_detected(self, invalid_level_path):
        findings = validate_rule(invalid_level_path, {})
        errors = [f for f in findings if f.severity == "error"]
        assert any("Invalid level" in e.message for e in errors)

    def test_invalid_status_detected(self, invalid_status_path):
        findings = validate_rule(invalid_status_path, {})
        errors = [f for f in findings if f.severity == "error"]
        assert any("Invalid status" in e.message for e in errors)

    def test_invalid_uuid_detected(self, invalid_uuid_path):
        findings = validate_rule(invalid_uuid_path, {})
        errors = [f for f in findings if f.severity == "error"]
        assert any("Invalid UUID" in e.message for e in errors)

    def test_missing_condition_detected(self, no_condition_path):
        findings = validate_rule(no_condition_path, {})
        errors = [f for f in findings if f.severity == "error"]
        assert any("condition" in e.message for e in errors)

    def test_duplicate_id_detected(self, valid_rule_path, duplicate_id_path):
        """Validate that two files sharing the same UUID are flagged."""
        seen_ids = {}
        # First file claims the ID
        validate_rule(valid_rule_path, seen_ids)
        # Second file should collide
        findings = validate_rule(duplicate_id_path, seen_ids)
        errors = [f for f in findings if f.severity == "error"]
        assert any("Duplicate rule ID" in e.message for e in errors)


# -----------------------------------------------------------------------
# Directory-level validation
# -----------------------------------------------------------------------

class TestValidateDirectory:
    """Tests for validate_rules_directory() on fixture and production rules."""

    def test_fixtures_directory_has_errors(self, fixtures_dir):
        """The fixtures dir intentionally contains invalid rules."""
        result = validate_rules_directory(fixtures_dir)
        assert isinstance(result, ValidationResult)
        assert result.rules_checked > 0
        assert result.has_errors, "Fixture directory should contain validation errors"

    def test_production_rules_pass(self, rules_dir):
        """Every production rule in rules/ must pass validation."""
        result = validate_rules_directory(rules_dir)
        assert result.rules_checked >= 5, (
            f"Expected >= 5 production rules, found {result.rules_checked}"
        )
        if result.has_errors:
            msgs = "\n".join(str(e) for e in result.errors)
            raise AssertionError(f"Production rules have validation errors:\n{msgs}")

    def test_no_duplicate_ids_in_production(self, rules_dir):
        """Production rules must not share IDs."""
        result = validate_rules_directory(rules_dir)
        dup_errors = [e for e in result.errors if "Duplicate rule ID" in e.message]
        assert dup_errors == [], f"Duplicate IDs found: {dup_errors}"

    def test_nonexistent_directory(self, tmp_path):
        result = validate_rules_directory(tmp_path / "does_not_exist")
        assert result.has_errors
