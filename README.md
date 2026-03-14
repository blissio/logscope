# logscope

Lightweight SIEM for local log monitoring.

Parses Linux auth and system logs, detects suspicious patterns, and outputs a threat report in your terminal or as JSON.

---

## Features

- Brute force SSH detection
- Successful root login alerts
- Off-hours login flagging
- New user creation detection
- Port scan detection via firewall logs
- Severity scoring — `LOW` `MEDIUM` `HIGH` `CRITICAL`
- Rich terminal output + JSON export

---

## Usage

```bash
python logscope.py --file /var/log/auth.log --report
python logscope.py --file auth.log --json --output report.json
python logscope.py --file auth.log --severity HIGH
```

---

## Status

🚧 Active development

---

*by [blissio](https://github.com/blissio)*
