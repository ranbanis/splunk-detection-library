# Suspicious Remote Thread Creation

**MITRE ATT&CK Technique:** T1055 - Process Injection
**Tactic:** Defense Evasion, Privilege Escalation
**Log Source:** Windows Sysmon (Event ID 8 - CreateRemoteThread)

## Description
Adversaries often inject malicious code into legitimate, running processes (like `explorer.exe` or `svchost.exe`) to evade process-based defenses and hide their activity. This rule detects when an unusual or untrusted process attempts to create a remote thread inside a common Windows system process.

## SPL Query
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
(TargetImage="*\\svchost.exe" OR TargetImage="*\\explorer.exe" OR TargetImage="*\\notepad.exe" OR TargetImage="*\\winlogon.exe")
| eval SourcePath=lower(SourceImage)
| search NOT 
    (SourcePath="*\\windows\\system32\\*" OR SourcePath="*\\program files\\*")
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, SourceImage, SourceProcessId, TargetImage, TargetProcessId, StartAddress
| convert ctime(firstTime) ctime(lastTime)
| rename SourceImage as "Injecting Process", TargetImage as "Target Process", Computer as "Host"
