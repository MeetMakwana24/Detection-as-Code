# Detection-as-Code

A Detection-as-Code pipeline for managing Sigma detection rules, validating them with CI/CD, and converting them to Splunk SPL, Elasticsearch Lucene, and Microsoft Sentinel KQL queries.

Current package version: `1.0.0` (see `pyproject.toml`).

## Requirements

| Tool | Recommended version | Notes |
|---|---|---|
| Python | 3.11 | Python 3.11+ is required; CI runs on Python 3.11. |
| pip | 23.3 to <26 | Upgraded during setup for reliable dependency resolution. |
| Git | 2.40+ | Required to clone and publish the repository. |

Python and Git are installed separately from the project. The supported pip version is installed from `requirements.txt`.

Current package version: `1.0.0` (see `pyproject.toml`).

## Requirements

| Tool | Recommended version | Notes |
|---|---|---|
| Python | 3.11 | Python 3.10+ is supported; CI runs on Python 3.11. |
| pip | 23.3 to <26 | Upgraded during setup for reliable dependency resolution. |
| Git | 2.40+ | Required to clone and publish the repository. |

Python and Git are installed separately from the project. The supported pip version is installed from `requirements.txt`.

## Overview

```
rules/              ← Sigma YAML detection rules
  windows/
    logon/              network logon failures, RDP logon success
    process_access/     LSASS process access
    process_creation/   PowerShell, LSASS, schtasks, LOLBins, WMI, Office, and Defender
    registry/           Run key persistence, Fodhelper UAC bypass
    system/             suspicious service installation
scripts/
  validate_rules.py ← Structural validation (YAML, fields, IDs, ATT&CK tags)
  convert_rules.py  ← Sigma → Splunk, Elasticsearch, and Sentinel queries via pySigma
tests/
  fixtures/         ← Synthetic YAML fixtures (valid + deliberately broken)
  test_validator.py ← Validator unit tests
  test_conversion.py← Conversion integration tests
config/
  splunk_lab.yml    ← Lab-specific index/sourcetype mappings
.github/workflows/
  ci.yml            ← GitHub Actions: validate → test → convert on push/PR
docs/               ← Setup, testing, and false-positive guides
```

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/MeetMakwana24/Detection-as-Code.git
cd Detection-as-Code
python --version                 # recommended: Python 3.11
git --version                    # required: Git 2.40+
python -m venv venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\venv\Scripts\Activate.ps1
```

```bash
# Linux/macOS
source venv/bin/activate
```

Install the dependencies:

```bash
python -m pip install --upgrade "pip>=23.3,<26"
python -m pip install -r requirements-dev.txt
```

### 2. Validate rules

```bash
python scripts/validate_rules.py
```

### 3. Run tests

```bash
pytest tests/ -v
```

### 4. Convert rules to vendor queries

```bash
python scripts/convert_rules.py
python scripts/convert_rules.py --output-dir output/splunk/   # write to files
```

## Multi-vendor Conversion

The converter defaults to Splunk for backward compatibility. Select a target with --target:

    python scripts/convert_rules.py --target elasticsearch --output-dir output/elasticsearch/
    python scripts/convert_rules.py --target sentinel --output-dir output/sentinel/
    python scripts/convert_rules.py --target all --output-dir output/

Elasticsearch output is Lucene syntax mapped to Elastic Common Schema (ECS) Windows fields. Sentinel output is Kusto Query Language (KQL) mapped through Microsoft Sentinel ASIM. Confirm the generated fields and tables against the connectors deployed in your environment before enabling alerts.

The converter supports both current and older optional pySigma pipeline packages. If a pipeline is absent, conversion continues with the available backend mappings.

## Detection Rules

| # | Rule | ATT&CK | Level | Log Source |
|---|------|--------|-------|------------|
| 1 | [PowerShell Encoded Command](rules/windows/process_creation/powershell_encoded_command.yml) | T1059.001, T1027 | High | Process Creation |
| 2 | [LSASS Credential Dumping](rules/windows/process_creation/lsass_credential_dump.yml) | T1003.001 | Critical | Process Creation |
| 3 | [Registry Run Key Persistence](rules/windows/registry/run_key_persistence.yml) | T1547.001 | Medium | Registry Set |
| 4 | [Network Logon Failure](rules/windows/logon/network_logon_failure.yml) | T1110.001, T1110.003 | Medium | Windows Security |
| 5 | [Suspicious Scheduled Task](rules/windows/process_creation/suspicious_schtasks.yml) | T1053.005 | High | Process Creation |
| 6 | [Defender Tampering](rules/windows/process_creation/defender_tampering.yml) | T1562.001 | High | Process Creation |
| 7 | [Event Log Clearing](rules/windows/process_creation/event_log_clearing.yml) | T1070.001 | High | Process Creation |
| 8 | [Office Suspicious Child Process](rules/windows/process_creation/office_child_process.yml) | T1204.002, T1059 | High | Process Creation |
| 9 | [LOLBin Proxy Execution](rules/windows/process_creation/lolbin_proxy_execution.yml) | T1218 | High | Process Creation |
| 10 | [WMI Remote Process Execution](rules/windows/process_creation/wmi_remote_execution.yml) | T1047 | High | Process Creation |
| 11 | [RDP Logon Success](rules/windows/logon/rdp_logon_success.yml) | T1021.001 | Medium | Windows Security |
| 12 | [Suspicious Service Installation](rules/windows/system/service_installation.yml) | T1543.003 | High | Windows System |
| 13 | [Suspicious Process Access to LSASS](rules/windows/process_access/lsass_process_access.yml) | T1003.001 | Critical | Sysmon Process Access |
| 14 | [Fodhelper UAC Bypass](rules/windows/registry/uac_bypass_fodhelper.yml) | T1548.002 | High | Registry Set |

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs automatically on pushes and pull requests:

1. **Validate** — `python scripts/validate_rules.py` checks YAML syntax, required fields, UUID format, duplicates, and ATT&CK tag format.
2. **Test** — `pytest tests/` runs the full test suite (validator + conversion).
3. **Convert** — `python scripts/convert_rules.py` produces Splunk SPL and uploads the output as a CI artifact.

## Publishing an Update to GitHub

Before publishing a new release, update the package version in `pyproject.toml`, run the validation and tests, then commit and tag the release:

```bash
python scripts/validate_rules.py
pytest tests/ -v
git add README.md requirements.txt requirements-dev.txt pyproject.toml
git commit -m "Release vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

Replace `X.Y.Z` with the version set in `pyproject.toml`. GitHub Actions will validate, test, and generate the Splunk SPL artifact for the pushed commit or tag.

This project is provided for educational and home lab use.
