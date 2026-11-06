# Testing Guide

## Test Categories

This project distinguishes between two types of testing:

### 1. Automated Synthetic Tests (CI/CD)

These tests run in CI and on your local machine without any Splunk instance:

| Test File | What It Tests |
|-----------|--------------|
| `tests/test_validator.py` | YAML parsing, required fields, UUID format, duplicate IDs, status/level values, detection structure, ATT&CK tag format |
| `tests/test_conversion.py` | pySigma conversion produces non-empty SPL, key detection terms survive conversion, metadata is preserved |

**Run locally:**

```bash
pytest tests/ -v
```

**With coverage:**

```bash
pytest tests/ -v --cov=scripts --cov-report=term-missing
```

All fixture data in `tests/fixtures/` is synthetic — purpose-built YAML files designed to exercise specific validation paths.  No production data or credentials are used.

### 2. Manual SIEM Validation (Lab)

Automated tests confirm structural correctness but **cannot** verify that a query returns the expected results against real Windows event logs. Manual validation in each target SIEM is required.

#### Recommended Manual Test Procedure

For each detection rule:

1. **Convert the rule:**
   ```bash
   python scripts/convert_rules.py --output-dir output/splunk/
   ```

2. **Open Splunk Web** → Search & Reporting.

3. **Paste the SPL query** from the corresponding `.spl` file.

4. **Simulate the attack** (in a safe, isolated lab environment):

   | Rule | Simulation Command (run in test VM) |
   |------|-------------------------------------|
   | PowerShell Encoded Command | `powershell -EncodedCommand ZQBjAGgAbwAgACIAdABlAHMAdAAiAA==` |
   | LSASS Credential Dump | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\temp\lsass.dmp full` |
   | Registry Run Key | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v TestEntry /d "C:\temp\test.exe"` |
   | Network Logon Failure | Use `runas /netonly /user:FAKEUSR cmd` or invalid RDP login |
   | Suspicious Scheduled Task | `schtasks /create /tn "TestTask" /tr "C:\Users\Public\test.exe" /sc daily` |

   > **WARNING:** Run these commands only in an isolated lab VM.  The LSASS dump simulation may trigger your antivirus — this is expected.

5. **Check Splunk results** — Verify the query returns the simulated event.

6. **Capture evidence:**
   - Screenshot the Splunk search results showing the detection.
   - Save screenshots to `docs/screenshots/` for documentation.

7. **Clean up** — Remove test registry entries, scheduled tasks, and dump files.

#### What to Capture in Screenshots

- The SPL query in the Splunk search bar.
- At least one matching event in the results.
- The event's key fields (Image, CommandLine, EventID, etc.).
- The time range used.

Save as: `docs/screenshots/<rule_name>_detection.png`

## Adding New Tests

When adding a new Sigma rule:

1. Add the rule to `rules/windows/<category>/`.
2. Run `python scripts/validate_rules.py` to verify it passes.
3. Run `pytest tests/ -v` — the existing tests automatically pick up new production rules.
4. (Optional) Add a specific conversion test in `test_conversion.py` to verify key terms survive conversion.
5. Perform manual validation in your Splunk lab.
