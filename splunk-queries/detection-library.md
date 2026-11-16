
# SPL Security Detection Library

This library documents security monitoring and investigation searches for the Splunk SOC Home Lab.

## 1. Windows Failed Login Detection

Purpose: Identify unsuccessful Windows authentication attempts.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count as FailedAttempts by _time host
| sort - _time
```

## 2. Potential Brute Force Detection

Purpose: Identify repeated failed authentication attempts.

```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count as FailedAttempts by _time host
| where FailedAttempts >= 5
```

Status: Proposed detection rule requiring threshold testing.

## 3. Microsoft Defender Threat Detection

Purpose: Monitor malware detection and remediation activity.

```spl
index=main source="*Defender*" (EventCode=1116 OR EventCode=1117 OR EventCode=1118)
| table _time host EventCode Message
| sort - _time
```

## 4. Ubuntu Authentication Monitoring

Purpose: Monitor Linux authentication events.

```spl
index=main source="/var/log/auth.log"
| table _time host _raw
| sort - _time
```

## 5. Linux Privileged Command Monitoring

Purpose: Identify commands executed with sudo privileges.

```spl
index=main source="/var/log/auth.log" "sudo:" "COMMAND="
| table _time host _raw
| sort - _time
```

## 6. Application Execution Monitoring

Purpose: Identify executed Windows applications using Sysmon Event ID 1.

```spl
index=main source="*Sysmon*"
| rex field=_raw "<EventID[^>]*>(?<sysmon_id>\d+)</EventID>"
| where sysmon_id="1"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Application>[^<]*)</Data>"
| stats count as Launches latest(_time) as LastLaunch by Application
| convert ctime(LastLaunch)
| sort - Launches
```

## 7. DNS Activity Monitoring

Purpose: Monitor domains queried by endpoint applications.

```spl
index=main source="*Sysmon*"
| rex field=_raw "<EventID[^>]*>(?<sysmon_id>\d+)</EventID>"
| where sysmon_id="22"
| rex field=_raw "<Data Name=['\"]QueryName['\"]>(?<Domain>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Application>[^<]*)</Data>"
| stats count as DNS_Queries by Application Domain
| sort - DNS_Queries
```

## 8. Network Connection Monitoring

Purpose: Identify application network connections.

```spl
index=main source="*Sysmon*"
| rex field=_raw "<EventID[^>]*>(?<sysmon_id>\d+)</EventID>"
| where sysmon_id="3"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Application>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationIp['\"]>(?<DestinationIP>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationPort['\"]>(?<DestinationPort>[^<]*)</Data>"
| stats count as Connections by Application DestinationIP DestinationPort
| sort - Connections
```

## 9. URLhaus Threat Intelligence Detection

Purpose: Compare observed DNS queries against a threat intelligence lookup.

```spl
index=main source="*Sysmon*"
| rex field=_raw "<EventID[^>]*>(?<sysmon_id>\d+)</EventID>"
| where sysmon_id="22"
| rex field=_raw "<Data Name=['\"]QueryName['\"]>(?<Domain>[^<]*)</Data>"
| eval Domain=lower(replace(Domain,"\.$",""))
| lookup urlhaus_domains.csv Domain OUTPUT ThreatLevel Source
| where isnotnull(ThreatLevel)
| table _time host Domain ThreatLevel Source
| sort - _time
```

Dependency: urlhaus_domains.csv lookup file.

Threat intelligence matches require investigation before classification as confirmed threats.

## 10. Centralized Windows and Linux Monitoring

Purpose: Compare event collection across monitored endpoints.

```spl
index=main (sourcetype="WinEventLog:Security" OR host="Ubuntu-Splunk-Forwarder")
| stats count by host
| sort - count
```

## Validation and Limitations

The portfolio screenshots demonstrate the underlying monitoring capabilities. Adapted queries and proposed detection thresholds require testing before production deployment.

DNS requests do not establish confirmed website visits or malicious activity.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
