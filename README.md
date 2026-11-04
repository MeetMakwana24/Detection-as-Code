# Detection-as-Code

A Detection-as-Code pipeline for managing Sigma detection rules, validating them with CI/CD, and converting them to Splunk SPL queries for a Home SOC Lab.

## Overview

```
rules/              ← Sigma YAML detection rules
  windows/
    process_creation/   powershell, lsass, schtasks
    registry/           run key persistence
    logon/              network logon failures
scripts/
  validate_rules.py ← Structural validation (YAML, fields, IDs, ATT&CK tags)
  convert_rules.py  ← Sigma → Splunk SPL via pySigma
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
git clone https://github.com/<you>/Detection-as-Code.git
cd Detection-as-Code
python --version                 # recommended: Python 3.11
git --version                    # required: Git 2.40+
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate   # Linux/macOS
python -m pip install --upgrade "pip>=23.3,<26"
pip install -r requirements-dev.txt
```

### 2. Validate rules

```bash
python scripts/validate_rules.py
```

### 3. Run tests

```bash
pytest tests/ -v
```

### 4. Convert rules to Splunk SPL

```bash
python scripts/convert_rules.py
python scripts/convert_rules.py --output-dir output/splunk/   # write to files
```

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

## Splunk Home SOC Lab Integration

Edit `config/splunk_lab.yml` to match your lab's indices and sourcetypes.  The conversion script uses the pySigma `splunk_windows_pipeline` which produces CIM-compatible field names suitable for environments using the Splunk Add-on for Windows (TA-windows).

After conversion, paste the generated SPL queries into Splunk Web → **Search & Reporting** to test them against your collected Windows event logs.

See [docs/SETUP.md](docs/SETUP.md) for detailed setup instructions and [docs/TESTING.md](docs/TESTING.md) for guidance on validating detections in your lab.

## Limitations

- **Synthetic tests only** — The automated test suite validates rule structure and conversion logic.  It does not execute queries against a live Splunk instance.
- **Threshold-based detections** — The network logon failure rule detects individual events; configure alert thresholds in your Splunk saved searches for brute-force detection.
- **Registry rules require Sysmon** — The Run key persistence rule requires Sysmon Event ID 13 or equivalent registry auditing.
- **Field mappings** — If your Splunk environment does not use TA-windows CIM field names, you may need a custom processing pipeline.

## License

This project is provided for educational and home lab use.
