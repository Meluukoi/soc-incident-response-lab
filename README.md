# SOC Incident Response Lab

Incident response investigations using Splunk, Sysmon, and Windows telemetry to analyze security alerts, reconstruct attack timelines, and document findings.

---

## Overview

This project focuses on incident response investigations using Splunk Enterprise, Sysmon, and Windows Event Logs.

The objective is to analyze security alerts, investigate suspicious activity, reconstruct attack timelines, and document findings using real telemetry collected in a home lab environment.

---

## Lab Environment

### Tools Used

- Splunk Enterprise
- Splunk Universal Forwarder
- Sysmon
- Windows Event Viewer
- PowerShell
- Wireshark

### Data Sources

- Microsoft-Windows-Sysmon/Operational
- Windows Security Logs
- Windows System Logs

---

## Incident Response Scenarios

### Incident 1: Suspicious PowerShell Activity

**Status:** In Progress

### Incident 2: Authentication Investigation

**Status:** Planned

### Incident 3: Unauthorized Account Creation

**Status:** Planned

### Incident 4: Privileged Group Membership Change

**Status:** Planned

### Incident 5: Account Deletion Activity

**Status:** Planned

---

## Investigation Methodology

Each incident follows a structured workflow:

```text
Alert
↓
Investigation
↓
Timeline Reconstruction
↓
Findings
↓
Impact Assessment
↓
MITRE ATT&CK Mapping
↓
Recommendations
```


# Incident 1: Suspicious PowerShell Activity

## Alert

A PowerShell process was observed spawning `whoami.exe`, a command commonly used to identify the current user context on a system.

This behavior may indicate reconnaissance activity performed by an attacker after gaining access to a host.

---

## Investigation Objective

Determine whether PowerShell was used to execute reconnaissance commands and identify the associated user account, process activity, and execution timeline.

---

## Alert Query

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
"WindowsPowerShell" "whoami"
```

---

## Investigation

Process creation events were successfully collected and analyzed using Sysmon Event ID 1.

The investigation identified:

- Parent Process: powershell.exe
- Child Process: whoami.exe
- Executing User Account
- Process Command Line
- Execution Timestamp

Analysis revealed that PowerShell spawned whoami.exe, which is commonly used to identify the current user context on a system.

While this activity may be legitimate administrative behavior, it is also frequently observed during attacker reconnaissance following initial access.

---

## Timeline Reconstruction

| Time | Activity |
|--------|--------|
| T0 | powershell.exe executed |
| T1 | whoami.exe spawned by PowerShell |
| T2 | User context information retrieved |

---

## Findings

The investigation confirmed that PowerShell executed whoami.exe on the endpoint.

No additional suspicious child processes were observed during the investigation.

The activity demonstrates how attackers or administrators may use built-in Windows utilities to gather information about the current user context.

---

## Impact Assessment

- No evidence of persistence observed
- No evidence of privilege escalation observed
- No evidence of malicious payload execution observed

Risk Level: Low

---

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| System Owner/User Discovery | T1033 |
| PowerShell | T1059.001 |

---

## Recommendations

- Monitor PowerShell process activity.
- Investigate unusual parent-child process relationships involving PowerShell.
- Correlate PowerShell execution with additional reconnaissance activity.
- Enable PowerShell logging where possible.

---

## Screenshots

### PowerShell Reconnaissance Activity

PowerShell spawning whoami.exe identified through Sysmon Event ID 1 process creation telemetry.

![PowerShell Investigation](screenshots/powershell-whoami-investigation.png)
