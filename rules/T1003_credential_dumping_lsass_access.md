# Suspicious Access to LSASS Process

**MITRE ATT&CK Technique:** T1003.001 - OS Credential Dumping: LSASS Memory
**Tactic:** Credential Access
**Log Source:** Windows Sysmon (Event ID 10 - ProcessAccess)

## Description
Adversaries often attempt to dump the memory of the Local Security Authority Subsystem Service (`lsass.exe`) to extract plaintext credentials or NT hashes. This rule monitors for processes requesting highly privileged access rights (like `0x1fffff` or `0x1010`) to `lsass.exe`, which is abnormal for standard user applications.

## SPL Query
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" 
(GrantedAccess="0x1fffff" OR GrantedAccess="0x1010" OR GrantedAccess="0x1410" OR GrantedAccess="0x143a")
| eval process_path=lower(SourceImage)
| search NOT 
    [| inputlookup known_legitimate_av_processes.csv | fields process_path]
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, SourceProcessId, TargetImage, TargetProcessId, GrantedAccess
| convert ctime(firstTime) ctime(lastTime)
| rename SourceImage as "Attacking Process", TargetImage as "Target Process", Computer as "Host"
