# False Positives Guide

Every detection rule can generate false positives — legitimate activity that matches the detection pattern.  This document lists known false positive sources for each rule and recommended tuning strategies.

## General Tuning Approach

1. **Deploy the rule in "test" status** — Monitor for 1–2 weeks before converting to alerts.
2. **Review the first 50 events** — Identify common legitimate patterns.
3. **Add exclusions** — Use Sigma `filter_*` selections or Splunk `NOT` clauses.
4. **Document exclusions** — Update the rule's `falsepositives` field and this document.
5. **Re-validate** — Ensure the exclusion does not suppress true positives.

---

## Per-Rule False Positives

### 1. PowerShell Encoded Command Execution

| False Positive Source | Frequency | Mitigation |
|----------------------|-----------|------------|
| SCCM / Intune deployments | Common | Filter by parent process (`sccm*.exe`, `intune*.exe`) |
| Packer / Vagrant provisioning | Occasional | Filter by parent process path |
| DSC (Desired State Config) | Occasional | Filter by `-ConfigurationName` in CommandLine |

### 2. LSASS Credential Dumping Tools

| False Positive Source | Frequency | Mitigation |
|----------------------|-----------|------------|
| EDR / AV LSASS scanning | Rare | Filter by known EDR process names/paths |
| Windows Error Reporting | Rare | Filter by `WerFault.exe` parent process |
| ProcDump for app debugging (non-lsass) | Very Rare | Rule already scopes to `lsass` in CommandLine |

### 3. Registry Run Key Persistence

| False Positive Source | Frequency | Mitigation |
|----------------------|-----------|------------|
| Software installers (MSI) | Common | Already filtered: `msiexec.exe` with `Program Files` paths |
| Browser updates (Chrome, Edge) | Occasional | Add filter for known update binaries |
| IT admin tools (e.g., BGInfo) | Occasional | Add filter by specific `Details` value |

### 4. Network Logon Failure

| False Positive Source | Frequency | Mitigation |
|----------------------|-----------|------------|
| Expired service account passwords | Common | Filter by known service account names |
| Password policy enforcement testing | Occasional | Temporarily suppress during testing windows |
| Network discovery / scanning tools | Occasional | Filter by source IP ranges |
| Machine account authentication (`$`) | Common | Already filtered in the rule |

### 5. Suspicious Scheduled Task Creation

| False Positive Source | Frequency | Mitigation |
|----------------------|-----------|------------|
| Application updaters (Chrome, VSCode) | Common | Filter by known updater paths in `AppData` |
| IT automation tools | Occasional | Filter by parent process or specific task names |
| User-created personal tasks | Rare | Review and whitelist on a case-by-case basis |

### 6. New Detection Rules

| Rule | Common false-positive source | Mitigation |
|------|------------------------------|------------|
| Defender Tampering | Authorized security configuration | Allowlist approved management tools and administrators |
| Event Log Clearing | Documented log-retention maintenance | Require a change ticket or approved host group |
| Office Child Process | Approved macros and add-ins | Allowlist signed documents or known parent/child pairs |
| LOLBin Proxy Execution | Legacy installers and applications | Scope exclusions to signed binaries and known paths |
| WMI Remote Execution | Management platforms | Allowlist known management servers and service accounts |
| RDP Logon Success | Helpdesk and jump hosts | Baseline expected source hosts and administrator accounts |
| Service Installation | Updaters and endpoint tools | Allowlist service image paths and publisher names |
| LSASS Process Access | EDR/AV telemetry | Allowlist trusted security-product image paths |
| Fodhelper UAC Bypass | Protocol-handler development | Restrict exclusions to known development systems |

---

## Documenting New False Positives

When you identify a new false positive:

1. Add it to the rule's `falsepositives` list in the YAML file.
2. If applicable, add a `filter_*` selection to the detection logic.
3. Update this document with the source, frequency, and mitigation.
4. Commit the changes and let CI validate the modified rule.
