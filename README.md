# Splunk SOC Home Lab

## Project overview
A hands-on Security Operations Center (SOC) lab using Splunk Enterprise, Windows security logs, Microsoft Defender, Sysmon and Ubuntu logs. It demonstrates centralized monitoring, SPL analysis, endpoint telemetry, security dashboards and threat intelligence triage.

## Validated lab observations
- Two Windows failed logon events (Event ID 4625) in a seven-day search.
- EICAR antivirus test file detected and quarantined by Microsoft Defender (Event IDs 1116 and 1117).
- 5,347 Ubuntu authentication and system log events in the displayed search.
- 9,104 events from two hosts in a combined search.
- 8,633 Sysmon events in a 30-minute window.
- 11 URLhaus lookup matches involving two shared-hosting domains, classified for manual review rather than confirmed as malicious.

These figures are historical lab search results, not production metrics. EICAR is a benign antivirus test file. DNS requests are not proof of website visits or compromise.

## Example SPL: Failed authentication
```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin _time span=10m
| stats count as FailedAttempts by _time host
| sort - _time
```

## Example SPL: Linux logs
```spl
index=main (source="/var/log/auth.log" OR source="/var/log/syslog")
```

## Practical evidence
Screenshots are cropped and selected identifiers masked for public portfolio presentation. Review before publishing.

### Windows failed authentication
![Windows failed authentication](screenshots/01-windows-failed-login.png)

### Seven-day failed authentication search
![Seven-day failed authentication search](screenshots/02-failed-logins-seven-days.png)

### Microsoft Defender EICAR detection and remediation
![Microsoft Defender EICAR detection and remediation](screenshots/03-defender-eicar-quarantine.png)

### Windows security monitoring dashboard
![Windows security monitoring dashboard](screenshots/04-windows-security-dashboard.png)

### Ubuntu log ingestion
![Ubuntu log ingestion](screenshots/05-ubuntu-log-ingestion.png)

### Linux sudo command monitoring
![Linux sudo command monitoring](screenshots/06-linux-privileged-command.png)

### Combined Windows and Ubuntu event collection
![Combined Windows and Ubuntu event collection](screenshots/07-cross-platform-log-ingestion.png)

### Event volume comparison by host
![Event volume comparison by host](screenshots/08-cross-platform-event-chart.png)

### Security event investigation
![Security event investigation](screenshots/09-security-event-investigation.png)

### Sysmon telemetry collection
![Sysmon telemetry collection](screenshots/10-sysmon-event-collection.png)

### Process creation and application monitoring
![Process creation and application monitoring](screenshots/11-sysmon-process-creation.png)

### Application-specific process search
![Application-specific process search](screenshots/12-application-process-investigation.png)

### Splunk Audit Trail user monitoring (app dashboard)
![Splunk Audit Trail user monitoring (app dashboard)](screenshots/13-splunk-audit-dashboard.png)

### Application execution summary
![Application execution summary](screenshots/14-application-execution-summary.png)

### DNS query analysis
![DNS query analysis](screenshots/15-dns-activity-monitoring.png)

### Network connection monitoring (destination IPs masked)
![Network connection monitoring (destination IPs masked)](screenshots/16-network-connection-monitoring.png)

### Windows host monitoring dashboard
![Windows host monitoring dashboard](screenshots/17-windows-host-security-dashboard.png)

### URLhaus lookup enrichment
![URLhaus lookup enrichment](screenshots/18-urlhaus-threat-intelligence.png)

### Shared-hosting domain manual triage
![Shared-hosting domain manual triage](screenshots/19-urlhaus-manual-triage.png)

## Skills demonstrated
SIEM deployment, log collection, SPL, Windows and Linux security monitoring, endpoint analysis, dashboard development and threat intelligence triage.
