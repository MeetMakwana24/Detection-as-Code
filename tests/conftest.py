"""Shared pytest fixtures for the Detection-as-Code test suite.

All test data in this project is *synthetic* — fabricated specifically for
testing the validator and converter logic.  No production Splunk logs or
real credentials are used.
"""

import sys
from pathlib import Path

import pytest

# Make scripts/ importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
RULES_DIR = REPO_ROOT / "rules"


@pytest.fixture
def fixtures_dir():
    """Path to the tests/fixtures/ directory."""
    return FIXTURES_DIR


@pytest.fixture
def rules_dir():
    """Path to the production rules/ directory."""
    return RULES_DIR


@pytest.fixture
def valid_rule_path(fixtures_dir):
    return fixtures_dir / "valid_rule.yml"


@pytest.fixture
def invalid_yaml_path(fixtures_dir):
    return fixtures_dir / "invalid_yaml.yml"


@pytest.fixture
def missing_fields_path(fixtures_dir):
    return fixtures_dir / "missing_fields.yml"


@pytest.fixture
def invalid_level_path(fixtures_dir):
    return fixtures_dir / "invalid_level.yml"


@pytest.fixture
def invalid_status_path(fixtures_dir):
    return fixtures_dir / "invalid_status.yml"


@pytest.fixture
def invalid_uuid_path(fixtures_dir):
    return fixtures_dir / "invalid_uuid.yml"


@pytest.fixture
def duplicate_id_path(fixtures_dir):
    return fixtures_dir / "duplicate_id_rule.yml"


@pytest.fixture
def no_condition_path(fixtures_dir):
    return fixtures_dir / "no_condition.yml"
