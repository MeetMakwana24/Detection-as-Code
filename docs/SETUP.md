# Setup Guide

## Prerequisites

| Requirement | Minimum Version | Purpose |
|-------------|----------------|---------|
| Python      | 3.11 (recommended; 3.10+ supported) | Validation scripts, pySigma |
| pip         | 23.3+          | Dependency management |
| Git         | 2.40+          | Version control |
| Splunk Free/Dev | 9.x+       | Home SOC Lab (optional for local testing) |
| Sysmon      | 14+            | Enhanced Windows telemetry (recommended) |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Detection-as-Code.git
cd Detection-as-Code
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

For development (includes testing tools):
```bash
pip install -r requirements-dev.txt
```

For CI or production (no test tools):
```bash
pip install -r requirements.txt
```

### 4. Verify installation

```bash
python scripts/validate_rules.py
pytest tests/ -v
python scripts/convert_rules.py
```

All three commands should complete without errors.

## Splunk Home SOC Lab Configuration

### Log Collection

Ensure your Splunk instance is collecting:

1. **Windows Security Logs** — Event IDs 4625 (logon failures), 4624 (logon success), etc.
   - Use the Splunk Universal Forwarder or Splunk Add-on for Windows (TA-windows).
   - Typical index: `wineventlog`
   - Typical sourcetype: `WinEventLog:Security`

2. **Windows System Logs** — Event ID 7045 (service installation).
   - Typical index: wineventlog
   - Typical sourcetype: WinEventLog:System

3. **Sysmon Logs** (recommended) — Event IDs 1 (Process Create), 10 (Process Access), and 13 (Registry Set).
   - Install [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) with a configuration like [SwiftOnSecurity's sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config).
   - Typical index: `sysmon`
   - Typical sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
   - Ensure Event ID 10 collection includes process access to LSASS; restrictive Sysmon configurations may omit it.

### Configuration File

Edit `config/splunk_lab.yml` to match your lab environment:

```yaml
splunk:
  default_index: main
  indices:
    windows_security: wineventlog
    windows_sysmon: sysmon
  sourcetypes:
    windows_security: "WinEventLog:Security"
    windows_sysmon: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  sysmon_deployed: true
```

### Using Converted Queries

After running the converter:

```bash
python scripts/convert_rules.py --output-dir output/splunk/
```

1. Open Splunk Web (typically `http://localhost:8000`).
2. Navigate to **Search & Reporting**.
3. Paste the generated SPL query from `output/splunk/<rule_name>.spl`.
4. Adjust the time range and index as needed.
5. Optionally save as an **Alert** or **Saved Search** for continuous monitoring.

## GitHub Actions Setup

1. Push this repository to GitHub.
2. The `.github/workflows/ci.yml` workflow will run automatically on pushes and PRs.
3. No secrets or external services are required — the CI pipeline uses only free, open-source tools.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: sigma` | Run `pip install -r requirements.txt` |
| Conversion produces unexpected field names | Verify your Splunk uses TA-windows CIM field mappings |
| Registry rule returns no results | Confirm Sysmon Event ID 13 is enabled in your Sysmon config |
| CI fails on `validate_rules.py` | Check the error output — usually a missing field or duplicate ID |
