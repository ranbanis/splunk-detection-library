# High-Frequency DNS Beaconing

**MITRE ATT&CK Technique:** T1071.004 - Application Layer Protocol: DNS
**Tactic:** Command and Control
**Log Source:** Windows Sysmon (Event ID 22 - DNSEvent) or Network DNS Logs

## Description
Once a machine is compromised, the malware must communicate with its Command and Control (C2) infrastructure. Often, this is done via DNS queries at regular intervals (beaconing). This rule identifies hosts making an abnormally high volume of DNS requests to a single domain over a specific time window.

## SPL Query
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, QueryName
| eval duration_seconds = lastTime - firstTime
| eval query_rate_per_second = count / duration_seconds
| search count > 150 AND duration_seconds > 600
| sort - count
| convert ctime(firstTime) ctime(lastTime)
| rename QueryName as "Queried Domain", count as "Total Queries", duration_seconds as "Time Window (s)"
