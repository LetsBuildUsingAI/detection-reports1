# T1003.001_lab-u9c29x-windows-dc

## Use Case Overview

| Field | Value |
|-------|-------|
| **Name** | `t1003_001_lab_u9c29x_windows_dc` |
| **Description** | Simulation of T1003.001 techniques with detection validation on Splunk Attack Range |
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
| **Start Date** | May 5, 2026 |
| **End Date** | N/A |

---

## Detection Query

```spl
-- Access LSASS Memory for Dump Creation (not_detected)
`sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR CallTrace=*dbghelp.dll*
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY CallTrace EventID GrantedAccess
       Guid Opcode ProcessID
       SecurityID SourceImage SourceProcessGUID
       SourceProcessId TargetImage TargetProcessGUID
       TargetProcessId UserID dest
       granted_access parent_process_exec parent_process_guid
       parent_process_id parent_process_name parent_process_path
       process_exec process_guid process_id
       process_name process_path signature
       signature_id user_id vendor_product
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `access_lsass_memory_for_dump_creation_filter`

-- Create Remote Thread into LSASS (not_detected)
`sysmon` EventID=8 TargetImage=*lsass.exe
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY EventID Guid NewThreadId
       ProcessID SecurityID SourceImage
       SourceProcessGuid SourceProcessId StartAddress
       StartFunction StartModule TargetImage
       TargetProcessGuid TargetProcessId UserID
       dest parent_process_exec parent_process_guid
       parent_process_id parent_process_name parent_process_path
       process_exec process_guid process_id
       process_name process_path signature
       signature_id user_id vendor_product
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `create_remote_thread_into_lsass_filter`

-- Creation of lsass Dump with Taskmgr (not_detected)
`sysmon` EventID=11 process_name=taskmgr.exe TargetFilename=*lsass*.dmp
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY action dest file_name
       file_path process_guid process_id
       user_id vendor_product process_name
       TargetFilename
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `creation_of_lsass_dump_with_taskmgr_filter`

-- Detect Credential Dumping through LSASS access (not_detected)
`sysmon` EventCode=10 TargetImage=*lsass.exe (GrantedAccess=0x1010 OR GrantedAccess=0x1410)
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY CallTrace EventID GrantedAccess
       Guid Opcode ProcessID
       SecurityID SourceImage SourceProcessGUID
       SourceProcessId TargetImage TargetProcessGUID
       TargetProcessId UserID dest
       granted_access parent_process_exec parent_process_guid
       parent_process_id parent_process_name parent_process_path
       process_exec process_guid process_id
       process_name process_path signature
       signature_id user_id vendor_product
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `detect_credential_dumping_through_lsass_access_filter`

-- Dump LSASS via comsvcs DLL (detected)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE `process_rundll32` Processes.process=*comsvcs.dll* Processes.process IN ("*MiniDump*", "*#24*")
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
| `dump_lsass_via_comsvcs_dll_filter`

-- Dump LSASS via procdump (detected)
| tstats `security_content_summariesonly`
  count min(_time) as firstTime
        max(_time) as lastTime

from datamodel=Endpoint.Processes where

(
  Processes.process_name IN (
    "procdump.exe",
    "procdump64.exe",
    "procdump64a.exe"
  )
  OR
  Processes.original_file_name=procdump
)
Processes.process IN (*-ma*, *-mm*, "*-mp*", */ma*, */mm*, "*/mp*")
Processes.process IN (* ls*, "* keyiso*", "* samss*")

by Processes.action Processes.dest Processes.original_file_name Processes.parent_process
   Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id
   Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec
   Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level
   Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product

| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `dump_lsass_via_procdump_filter`


-- Windows Credential Dumping LSASS Memory Createdump (not_detected)
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=createdump.exe
    OR
    Processes.original_file_name="FX_VER_INTERNALNAME_STR" Processes.process="*-u *"
    AND
    Processes.process="*-f *"
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
| `windows_credential_dumping_lsass_memory_createdump_filter`

-- Windows Hunting System Account Targeting Lsass (searching)
`sysmon` EventCode=10 TargetImage=*lsass.exe
  | stats count min(_time) as firstTime max(_time) as lastTime
    BY CallTrace EventID GrantedAccess
       Guid Opcode ProcessID
       SecurityID SourceImage SourceProcessGUID
       SourceProcessId TargetImage TargetProcessGUID
       TargetProcessId UserID dest
       granted_access parent_process_exec parent_process_guid
       parent_process_id parent_process_name parent_process_path
       process_exec process_guid process_id
       process_name process_path signature
       signature_id user_id vendor_product
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `windows_hunting_system_account_targeting_lsass_filter`

-- Windows Non-System Account Targeting Lsass (not_detected)
`sysmon` EventCode=10 TargetImage=*lsass.exe NOT (SourceUser="NT AUTHORITY\\*") | stats count min(_time) as firstTime max(_time) as lastTime by CallTrace EventID GrantedAccess Guid Opcode ProcessID SecurityID SourceImage SourceProcessGUID SourceProcessId TargetImage TargetProcessGUID TargetProcessId UserID dest granted_access parent_process_exec parent_process_guid parent_process_id parent_process_name parent_process_path process_exec process_guid process_id process_name process_path signature signature_id user_id vendor_product | `security_content_ctime(firstTime)`| `security_content_ctime(lastTime)` | `windows_non_system_account_targeting_lsass_filter`

-- Windows Possible Credential Dumping (searching)
`sysmon` EventCode=10 TargetImage=*\\lsass.exe granted_access IN ("0x01000", "0x1010", "0x1038", "0x40", "0x1400", "0x1fffff", "0x1410", "0x143a", "0x1438", "0x1000") CallTrace IN ("*dbgcore.dll*", "*dbghelp.dll*", "*ntdll.dll*", "*kernelbase.dll*", "*kernel32.dll*") NOT SourceUser IN ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE") | stats count min(_time) as firstTime max(_time) as lastTime by CallTrace EventID GrantedAccess Guid Opcode ProcessID SecurityID SourceImage SourceProcessGUID SourceProcessId TargetImage TargetProcessGUID TargetProcessId UserID dest granted_access parent_process_exec parent_process_guid parent_process_id parent_process_name parent_process_path process_exec process_guid process_id process_name process_path signature signature_id user_id vendor_product | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `windows_possible_credential_dumping_filter`
```

---

## Simulation & Output

### Simulation: 1

**Description:** Atomic Red Team simulation of T1003.001 on lab-u9c29x-windows-dc

**Output and Snapshot of Simulation:**

```
$ /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/venv/bin/python3 /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/attack_range_local.py -a simulate -st T1003.001 -t lab-u9c29x-windows-dc
[cwd] /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar

2026-05-06 16:08:50,373 - INFO - attack_range - INIT - attack_range v1

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
included: /media/nested/SamsungEvo/detection-labs/sar-goad-minimal/sar/ansible/roles/atomic_red_team/tasks/run_art_test.yml for 10.0.1.14 => (item=T1003.001)

TASK [atomic_red_team : set_fact] **********************************************
ok: [10.0.1.14]

TASK [atomic_red_team : debug] *************************************************
ok: [10.0.1.14] => {
    "technique": "T1003.001"
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
        "Executing test: T1003.001-1 Windows Credential Editor",
        "WCE v1.41beta (X64) (Windows Credentials Editor) - (c) 2010-2013 Amplia Security - by Hernan Ochoa (hernan@ampliasecurity.com)",
        "Use -h for help.",
        "Exit code: 0",
        "Done executing test: T1003.001-1 Windows Credential Editor",
        "Executing test: T1003.001-2 Dump LSASS.exe Memory using ProcDump",
        "ProcDump v11.1 - Sysinternals process dump utility",
        "Copyright (C) 2009-2025 Mark Russinovich and Andrew Richards",
        "Sysinternals - www.sysinternals.com",
        "[21:09:39]Dump 1 info: Available space: 46549987328",
        "[21:09:39]Dump 1 initiated: C:\\Windows\\Temp\\lsass_dump.dmp",
        "[21:09:39]Dump 1 writing: Estimated dump file size is 131 MB.",
        "[21:09:39]Dump 1 complete: 131 MB written in 0.5 seconds",
        "[21:09:39]Dump count reached.",
        "Exit code: -2",
        "Done executing test: T1003.001-2 Dump LSASS.exe Memory using ProcDump",
        "Executing test: T1003.001-3 Dump LSASS.exe Memory using comsvcs.dll",
        "Exit code: 0",
        "Done executing test: T1003.001-3 Dump LSASS.exe Memory using comsvcs.dll",
        "Executing test: T1003.001-4 Dump LSASS.exe Memory using direct system calls and API unhooking",
        "________          __    _____.__                 __\t\t\t\t",
        " \\_____  \\  __ ___/  |__/ ____\\  | _____    ____ |  | __\t\t",
        "  /   |   \\|  |  \\   __\\   __\\|  | \\__  \\  /    \\|  |/ /\t",
        " /    |    \\  |  /|  |  |  |  |  |__/ __ \\|   |  \\    <\t\t",
        " \\_______  /____/ |__|  |__|  |____(____  /___|  /__|_ \\\t\t",
        "         \\/                             \\/     \\/     \\/\t\t",
        "                                  Dumpert\t\t\t\t\t\t\t",
        "                               By Cneeliz @Outflank 2019\t\t    ",
        "[1] Checking OS version details:",
        "\t[+] Operating System is Windows 10 or Server 2016, build number 14393",
        "\t[+] Mapping version specific System calls.",
        "[2] Checking Process details:",
        "\t[+] Process ID of lsass.exe is: 520",
        "\t[+] NtReadVirtualMemory function pointer at: 0x00007FF9EE6362D0",
        "\t[+] NtReadVirtualMemory System call nr is: 0x3f",
        "\t[+] Unhooking NtReadVirtualMemory.",
        "[3] Create memorydump file:",
        "\t[+] Open a process handle.",
        "\t[+] Dump lsass.exe memory to: \\??\\C:\\Windows\\Temp\\dumpert.dmp",
        "\t[+] Dump succesful.",
        "Exit code: 0",
        "Done executing test: T1003.001-4 Dump LSASS.exe Memory using direct system calls and API unhooking",
        "Executing test: T1003.001-6 Offline Credential Theft With Mimikatz",
        "operable program or batch file.",
        "'C:\\AtomicRedTeam\\atomics\\T1003.001\\bin\\mimikatz.exe' is not recognized as an internal or external command,",
        "Exit code: 1",
        "Done executing test: T1003.001-6 Offline Credential Theft With Mimikatz",
        "Executing test: T1003.001-7 LSASS read with pypykatz",
        "operable program or batch file.",
        "'pypykatz' is not recognized as an internal or external command,",
        "Exit code: 1",
        "Done executing test: T1003.001-7 LSASS read with pypykatz",
        "ART_EXECUTION_DONE"
    ]
}

TASK [atomic_red_team : Cleanup after execution] *******************************
changed: [10.0.1.14]

TASK [atomic_red_team : include_tasks] *****************************************
skipping: [10.0.1.14]

PLAY RECAP *********************************************************************
10.0.1.14                  : ok=11   changed=4    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   

2026-05-06 16:09:45,596 - INFO - attack_range - successfully executed technique ID T1003.001 against target: lab-u9c29x-windows-dc

[success] Process exited with code 0 (55.8s)

```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 2

**Description:** Detection: Access LSASS Memory for Dump Creation — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 3

**Description:** Detection: Create Remote Thread into LSASS — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 4

**Description:** Detection: Creation of lsass Dump with Taskmgr — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Creation of lsass Dump with Taskmgr" not triggered — 3 strategies checked | Telemetry: 20 raw events
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 5

**Description:** Detection: Detect Credential Dumping through LSASS access — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Detect Credential Dumping through LSASS access" not triggered — 3 strategies checked | Telemetry: 20 raw events
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 6

**Description:** Detection: Dump LSASS via comsvcs DLL — DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Dump LSASS via comsvcs DLL" validated — 2 match(es) across 1 strategy(ies) | Telemetry: 20 raw events

Splunk returned 2 event(s)
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 7

**Description:** Detection: Dump LSASS via procdump — DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Dump LSASS via procdump" validated — 2 match(es) across 1 strategy(ies) | Telemetry: 20 raw events

Splunk returned 2 event(s)
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 8

**Description:** Detection: Windows Credential Dumping LSASS Memory Createdump — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Windows Credential Dumping LSASS Memory Createdump" not triggered — 3 strategies checked | Telemetry: 20 raw events
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 9

**Description:** Detection: Windows Hunting System Account Targeting Lsass — SEARCHING

**Output and Snapshot of Simulation:**

```
Attempt 64: Checking ESCU saved searches, alerts, and running SPL…
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 10

**Description:** Detection: Windows Non-System Account Targeting Lsass — NOT DETECTED

**Output and Snapshot of Simulation:**

```
Detection "Windows Non-System Account Targeting Lsass" not triggered — 2 strategies checked | Telemetry: 20 raw events
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

### Simulation: 11

**Description:** Detection: Windows Possible Credential Dumping — SEARCHING

**Output and Snapshot of Simulation:**

```
Attempt 49: Checking ESCU saved searches, alerts, and running SPL…
```

**Snapshot of Detection:** *(See Splunk/SIEM dashboard)*

---

## Observations

1 technique(s) simulated. 2 detection(s) triggered, 6 not detected out of 10 rules tested.

---

## Reason for Failure

- Access LSASS Memory for Dump Creation: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Create Remote Thread into LSASS: Not detected after 20 retries (100s). Detection may need tuning or telemetry was not generated.
- Creation of lsass Dump with Taskmgr: Detection "Creation of lsass Dump with Taskmgr" not triggered — 3 strategies checked | Telemetry: 20 raw events
- Detect Credential Dumping through LSASS access: Detection "Detect Credential Dumping through LSASS access" not triggered — 3 strategies checked | Telemetry: 20 raw events
- Windows Credential Dumping LSASS Memory Createdump: Detection "Windows Credential Dumping LSASS Memory Createdump" not triggered — 3 strategies checked | Telemetry: 20 raw events
- Windows Non-System Account Targeting Lsass: Detection "Windows Non-System Account Targeting Lsass" not triggered — 2 strategies checked | Telemetry: 20 raw events

---

## Recommendations

- [Access LSASS Memory for Dump Creation] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Access LSASS Memory for Dump Creation] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Access LSASS Memory for Dump Creation] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Create Remote Thread into LSASS] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Create Remote Thread into LSASS] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Create Remote Thread into LSASS] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Creation of lsass Dump with Taskmgr] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Creation of lsass Dump with Taskmgr] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Creation of lsass Dump with Taskmgr] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Detect Credential Dumping through LSASS access] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Detect Credential Dumping through LSASS access] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Detect Credential Dumping through LSASS access] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Dump LSASS via comsvcs DLL] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Dump LSASS via comsvcs DLL] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Dump LSASS via comsvcs DLL] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Dump LSASS via comsvcs DLL] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Dump LSASS via comsvcs DLL] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Dump LSASS via procdump] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Dump LSASS via procdump] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Dump LSASS via procdump] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Dump LSASS via procdump] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Dump LSASS via procdump] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Credential Dumping LSASS Memory Createdump] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Credential Dumping LSASS Memory Createdump] This detection uses `tstats` with data models. Ensure the Endpoint/Network data models are accelerated in Splunk (Settings > Data Models). In Attack Range, run: `| tstats count from datamodel=Endpoint` to verify.
- [Windows Credential Dumping LSASS Memory Createdump] This detection uses the `security_content_summariesonly` macro. Ensure ESCU app is installed and the macro is defined. Try replacing it with `summariesonly=false` for testing.
- [Windows Credential Dumping LSASS Memory Createdump] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Credential Dumping LSASS Memory Createdump] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Hunting System Account Targeting Lsass] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Hunting System Account Targeting Lsass] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Hunting System Account Targeting Lsass] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.
- [Windows Non-System Account Targeting Lsass] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Non-System Account Targeting Lsass] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Possible Credential Dumping] Raw telemetry IS flowing to Splunk, but the detection SPL didn't match. The search query may use Splunk macros (e.g. `security_content_summariesonly`) or data models that need to be resolved, or the index/sourcetype/host filters may not match your Attack Range.
- [Windows Possible Credential Dumping] This detection uses a filter macro (ending with _filter`). These are typically empty but may need to be defined in Splunk if customized.
- [Windows Possible Credential Dumping] The ESCU saved search exists in Splunk but has 0 triggered alerts. The search may need to be scheduled/run manually, or the simulation telemetry hasn't been indexed yet.

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

*Report generated by DetectOps on May 6, 2026*
