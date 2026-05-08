# T1569.002_lab-u9c29x-windows-dc

## Use Case Overview

| Field | Value |
|-------|-------|
| **Name** | `t1569_002_lab_u9c29x_windows_dc` |
| **Description** | Simulation of T1569.002 techniques with detection validation on Splunk Attack Range |
| **Severity** | high |
| **Status** | Done |
| **Assignee** | Detection Engineer |
| **Platform** | Splunk Enterprise |
| **Maturity Level** | Developing |
| **Criticality** | high |
| **Phase** | N/A |
| **Procedure Coverage** | Full Procedure Covered |
| **Device Group** | Cover All Devices |
| **Device Coverage** | Cover All Devices |
| **False Positive** | No |
| **Defined & Working** | Yes |
| **Needs Improvement** | Yes |
| **Start Date** | May 7, 2026 |
| **End Date** | N/A |

---

## Detection Query

```spl
-- Detect Renamed PSExec (not_detected)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE (
        Processes.process_name!=psexec.exe
        AND
        Processes.process_name!=psexec64.exe
    )
    AND Processes.original_file_name=psexec.c
  BY Processes.action Processes.dest Processes.original_file_name
     Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
     Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
     Processes.process Processes.process_exec Processes.process_guid
     Processes.process_hash Processes.process_id Processes.process_integrity_level
     Processes.process_name Processes.process_path Processes.user
     Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `detect_renamed_psexec_filter`

-- Excessive Usage Of SC Service Utility (not_detected)
| tstats `security_content_summariesonly` count as numScExe min(_time) as firstTime max(_time) as lastTime values(Processes.action) as action values(Processes.original_file_name) as original_file_name values(Processes.parent_process_exec) as parent_process_exec values(Processes.parent_process_guid) as parent_process_guid values(Processes.parent_process_name) as parent_process_name values(Processes.parent_process_path) as parent_process_path values(Processes.process) as process values(Processes.process_exec) as process_exec values(Processes.process_guid) as process_guid values(Processes.process_hash) as process_hash values(Processes.process_id) as process_id values(Processes.process_integrity_level) as process_integrity_level values(Processes.process_path) as process_path values(Processes.user_id) as user_id values(Processes.vendor_product) as vendor_product values(Processes.parent_process) as parent_process values(Processes.process_name) as process_name values(Processes.parent_process_id) as parent_process_id values(Processes.user) as user FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name = "sc.exe"
  BY Processes.dest _time span=15m
| `drop_dm_object_name(Processes)`
| eventstats avg(numScExe) as avgScExe, stdev(numScExe) as stdScExe, count as numSlots
  BY dest
| eval upperThreshold=(avgScExe + stdScExe *3)
| eval isOutlier=if(avgScExe > 5 and avgScExe >= upperThreshold, 1, 0)
| search isOutlier=1
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `excessive_usage_of_sc_service_utility_filter`

-- First Time Seen Running Windows Service (not_detected)
`wineventlog_system` EventCode=7036
  | rex field=Message "The (?<service>[-\(\)\s\w]+) service entered the (?<state>\w+) state"
  | where state="running"
  | lookup previously_seen_running_windows_services service as service OUTPUT firstTimeSeen
  | where isnull(firstTimeSeen) OR firstTimeSeen > relative_time(now(), `previously_seen_windows_services_window`)
  | table _time dest service
  | `first_time_seen_running_windows_service_filter`

-- Linux Auditd Service Started (not_detected)
`linux_auditd`  proctitle IN ("*systemctl *", "*service *") AND proctitle IN ("* start*", "* enable*")
  | rename host as dest
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY proctitle dest
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `linux_auditd_service_started_filter`

-- Malicious Powershell Executed As A Service (detected)
`wineventlog_system`
EventCode=7045
| eval l_ImagePath=lower(ImagePath)
| regex l_ImagePath="powershell[.\s]|powershell_ise[.\s]|pwsh[.\s]|psexec[.\s]"
| regex l_ImagePath="-nop[rofile\s]+|-w[indowstyle]*\s+hid[den]*|-noe[xit\s]+|-enc[odedcommand\s]+"
| stats count min(_time) as firstTime max(_time) as lastTime
    by EventCode ImagePath ServiceName StartType
       ServiceType AccountName UserID dest
| rename UserID as user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `malicious_powershell_executed_as_a_service_filter`

-- Windows ScManager Security Descriptor Tampering Via Sc.EXE (not_detected)
| tstats `security_content_summariesonly` values(Processes.process) as process min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE (
        Processes.process_name=sc.exe
        OR
        Processes.original_file_name=sc.exe
    )
    Processes.process="*sdset *" Processes.process="*scmanager*"
  BY Processes.action Processes.dest Processes.original_file_name
     Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
     Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
     Processes.process Processes.process_exec Processes.process_guid
     Processes.process_hash Processes.process_id Processes.process_integrity_level
     Processes.process_name Processes.process_path Processes.user
     Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_scmanager_security_descriptor_tampering_via_sc_exe_filter`

-- Windows Service Create SliverC2 (not_detected)
`wineventlog_system` EventCode=7045 ServiceName="sliver"
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY Computer EventCode ImagePath
       ServiceName ServiceType
  | rename Computer as dest
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `windows_service_create_sliverc2_filter`

-- Windows Service Created with Suspicious Service Name (not_detected)
`wineventlog_system` EventCode=7045
| stats values(ImagePath) as process, count, min(_time) as firstTime, max(_time) as lastTime values(EventCode) as signature by Computer, ServiceName, StartType, ServiceType, UserID
| eval process_name = replace(mvindex(split(process,"\\"),-1), "\"", "")
| rename Computer as dest, ServiceName as object_name, ServiceType as object_type, UserID as user_id
| lookup windows_suspicious_services service_name as object_name
| where isnotnull(tool_name)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_service_created_with_suspicious_service_name_filter`

-- Windows Service Created with Suspicious Service Path (not_detected)
`wineventlog_system` EventCode=7045 ImagePath = "*.exe" NOT (ImagePath IN ("*:\\Windows\\*", "*:\\Program File*", "*:\\Programdata\\*", "*%systemroot%\\*")) | stats count min(_time) as firstTime max(_time) as lastTime by EventCode ImagePath ServiceName ServiceType StartType Computer UserID | rename Computer as dest| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_service_created_with_suspicious_service_path_filter`

-- Windows Service Execution RemCom (not_detected)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=remcom.exe OR Processes.original_file_name=RemCom.exe) Processes.process="*\\*" Processes.process IN ("*/user:*", "*/pwd:*") by Processes.action Processes.dest Processes.original_file_name Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_service_execution_remcom_filter`

-- Windows Snake Malware Service Create (not_detected)
`wineventlog_system` EventCode=7045  ImagePath="*\\windows\\winSxS\\*" ImagePath="*\Werfault.exe" | stats count min(_time) as firstTime max(_time) as lastTime by Computer EventCode ImagePath ServiceName ServiceType | rename Computer as dest | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_snake_malware_service_create_filter`
```

---

## Simulation & Output

### Simulation: 1

**Description:** Atomic Red Team simulation of T1569.002 on lab-u9c29x-windows-dc

**Output and Snapshot of Simulation:**

```
$ /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/venv/bin/python3 /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/attack_range_local.py -a simulate -st T1569.002 -t lab-u9c29x-windows-dc
[cwd] /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar

2026-05-08 06:45:14,137 - INFO - attack_range - INIT - attack_range v1

starting program loaded for B1 battle droid
          ||/__'`.
          |//()'-.:
          |-.||
          |o(o)
          |||\\  .==._
          |||(o)==::'
           `|T  ""
            ()
            |\
            ||\
            ()()
            ||//
            |//
           .'=`=.
    
attack_range is using config at path attack_range_local.conf

PLAY [all] *********************************************************************

TASK [atomic_red_team : Enable strong dotnet crypto] ***************************
ok: [10.0.1.14] => (item=HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319)
ok: [10.0.1.14] => (item=HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319)

TASK [atomic_red_team : Check installed providers] *****************************
ok: [10.0.1.14]

TASK [atomic_red_team : Install NuGet Provider] ********************************
skipping: [10.0.1.14]

TASK [atomic_red_team : Install Atomic Red Team] *******************************
changed: [10.0.1.14]

TASK [atomic_red_team : set_fact] **********************************************
ok: [10.0.1.14]

TASK [atomic_red_team : include_tasks] *****************************************
included: /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/ansible/roles/atomic_red_team/tasks/run_art_test.yml for 10.0.1.14 => (item=T1569.002)

TASK [atomic_red_team : set_fact] **********************************************
ok: [10.0.1.14]

TASK [atomic_red_team : debug] *************************************************
ok: [10.0.1.14] => {
    "technique": "T1569.002"
}

TASK [atomic_red_team : Get requirements for Atomic Red Team Technique] ********
changed: [10.0.1.14]

TASK [atomic_red_team : Run specified Atomic Red Team Technique] ***************
changed: [10.0.1.14]

TASK [atomic_red_team : debug] *************************************************
ok: [10.0.1.14] => {
    "output.stdout_lines": [
        "PathToAtomicsFolder = C:\\AtomicRedTeam\\atomics",
        "",
        "Executing test: T1569.002-1 Execute a Command as a Service",
        "[SC] CreateService SUCCESS",
        "[SC] StartService FAILED 1053:",
        "The service did not respond to the start or control request in a timely fashion.",
        "[SC] DeleteService SUCCESS",
        "Exit code: 0",
        "Done executing test: T1569.002-1 Execute a Command as a Service",
        "Executing test: T1569.002-2 Use PsExec to execute a command on a remote host",
        "The system cannot find the path specified.",
        "Exit code: 1",
        "Done executing test: T1569.002-2 Use PsExec to execute a command on a remote host",
        "ART_EXECUTION_DONE"
    ]
}

TASK [atomic_red_team : Cleanup after execution] *******************************
changed: [10.0.1.14]

TASK [atomic_red_team : include_tasks] *****************************************
skipping: [10.0.1.14]

PLAY RECAP *********************************************************************
10.0.1.14                  : ok=11   changed=4    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   

2026-05-08 06:45:52,073 - INFO - attack_range - successfully executed technique ID T1569.002 against target: lab-u9c29x-windows-dc

[success] Process exited with code 0 (38.5s)

```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 2

**Description:** Detection: Detect Renamed PSExec — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 3

**Description:** Detection: Excessive Usage Of SC Service Utility — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 4

**Description:** Detection: First Time Seen Running Windows Service — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 5

**Description:** Detection: Linux Auditd Service Started — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 6

**Description:** Detection: Malicious Powershell Executed As A Service — DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Malicious Powershell Executed As A Service" validated — 1 match(es) across 1 strategy(ies) | Telemetry: 20 raw events

Splunk returned 1 event(s)
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 7

**Description:** Detection: Windows ScManager Security Descriptor Tampering Via Sc.EXE — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 8

**Description:** Detection: Windows Service Create SliverC2 — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 9

**Description:** Detection: Windows Service Created with Suspicious Service Name — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 10

**Description:** Detection: Windows Service Created with Suspicious Service Path — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 11

**Description:** Detection: Windows Service Execution RemCom — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 12

**Description:** Detection: Windows Snake Malware Service Create — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

## Observations

1 technique(s) simulated. 1 detection(s) triggered, 10 not detected out of 11 rules tested.

---

## Reason for Failure

- Detect Renamed PSExec: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Excessive Usage Of SC Service Utility: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- First Time Seen Running Windows Service: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Linux Auditd Service Started: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows ScManager Security Descriptor Tampering Via Sc.EXE: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows Service Create SliverC2: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows Service Created with Suspicious Service Name: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows Service Created with Suspicious Service Path: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows Service Execution RemCom: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Windows Snake Malware Service Create: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.

---

## Recommendations

- [Detect Renamed PSExec] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Detect Renamed PSExec] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Detect Renamed PSExec] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Detect Renamed PSExec] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Detect Renamed PSExec] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Excessive Usage Of SC Service Utility] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Excessive Usage Of SC Service Utility] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Excessive Usage Of SC Service Utility] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Excessive Usage Of SC Service Utility] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Excessive Usage Of SC Service Utility] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [First Time Seen Running Windows Service] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [First Time Seen Running Windows Service] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [First Time Seen Running Windows Service] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Linux Auditd Service Started] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Linux Auditd Service Started] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Linux Auditd Service Started] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows ScManager Security Descriptor Tampering Via Sc.EXE] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows ScManager Security Descriptor Tampering Via Sc.EXE] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Windows ScManager Security Descriptor Tampering Via Sc.EXE] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Windows ScManager Security Descriptor Tampering Via Sc.EXE] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Service Create SliverC2] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Service Create SliverC2] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Service Create SliverC2] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Service Created with Suspicious Service Name] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Service Created with Suspicious Service Name] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Service Created with Suspicious Service Name] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Service Created with Suspicious Service Path] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Service Created with Suspicious Service Path] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Service Created with Suspicious Service Path] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Service Execution RemCom] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Service Execution RemCom] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Windows Service Execution RemCom] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Windows Service Execution RemCom] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Service Execution RemCom] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Snake Malware Service Create] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Snake Malware Service Create] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Snake Malware Service Create] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.

---

## Checklist

### Requirements
- [x] Validate Device Coverage
- [x] Validate Query Syntax and Logic
- [ ] Check for New UC Recommendation
- [x] Check for False Positives
- [x] Procedure Coverage

### Deliverables
- [x] Observations
- [x] Reason for Failures
- [x] Recommendation Details
- [ ] PR for Detailed Analysis

---

*Report generated by DetectOps on May 8, 2026*
