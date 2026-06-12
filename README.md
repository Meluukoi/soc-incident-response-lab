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


# Incident 2: Failed Authentication Investigation

## Alert

Multiple failed authentication attempts were identified through Windows Security Event ID 4625.

Failed logon activity can indicate password guessing, brute-force attempts, misconfigured services, or unauthorized access attempts.

---

## Investigation Objective

Determine the source of the failed authentication attempts, identify the targeted account, analyze the logon type, and assess whether the activity indicates malicious behavior.

---

## Alert Query

```spl
source="WinEventLog:Security"
EventCode=4625
```

---

## Investigation

Failed authentication events were successfully collected and analyzed using Windows Security Event ID 4625.

The investigation identified:

- Targeted user accounts
- Logon types
- Authentication packages
- Failure reasons
- Source workstation information
- Associated status codes

Analysis of Event ID 4625 telemetry provided visibility into unsuccessful authentication activity occurring on the endpoint.

---

## Timeline Reconstruction

| Time | Activity |
|--------|--------|
| T0 | Authentication request initiated |
| T1 | Windows rejected authentication request |
| T2 | Event ID 4625 generated |
| T3 | Failed logon recorded in Splunk |

---

## Findings

The investigation identified failed authentication attempts against local user accounts.

Analysis revealed:

- Failed user authentication
- Audit Failure events
- Logon Type information
- Failure status codes

The activity demonstrates how Windows records unsuccessful authentication attempts and provides valuable context for identifying password attacks and unauthorized access attempts.

---

## Impact Assessment

- No successful authentication observed
- No privilege escalation observed
- No persistence observed

Risk Level: Medium

Repeated failed logons may indicate password spraying or brute-force activity and should be monitored for escalation.

---

## MITRE ATT&CK Mapping

| Technique | ID |
|------------|------------|
| Brute Force | T1110 |

---

## Recommendations

- Monitor for repeated failed authentication attempts.
- Investigate accounts experiencing excessive failures.
- Review source workstation information.
- Correlate failed logons with successful logon events.
- Implement account lockout policies where appropriate.

---

## Screenshots

### Failed Authentication Investigation

Windows Security Event ID 4625 showing failed authentication activity, logon details, and failure information collected through Splunk.

![Failed Authentication Investigation](screenshots/failed-logon-investigation.png)
