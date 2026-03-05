# SSH Auth Log Analyzer (Brute-force Detection)

A Python CLI tool that parses SSH authentication logs and detects brute-force style patterns
based on failed login counts within a sliding time window.

## Features
- Parses common `sshd` FAIL/ACCEPT syslog lines
- Reports top source IPs by failed logins
- Alerts when an IP exceeds a configurable threshold within a time window
- Optional CSV export of alerts

## Usage
```bash
python3 analyzer.py sample_auth.log --window 5 --threshold 4 --csv alerts.csv