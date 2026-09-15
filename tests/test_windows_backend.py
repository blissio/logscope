import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"
spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)

from windows_events import WindowsEvent, findings_from_event


def test_failed_logon_preserves_windows_metadata():
    findings = findings_from_event(WindowsEvent(
        channel="Security",
        event_id=4625,
        record_id=42,
        timestamp="2026-09-15T10:00:00",
        data={
            "TargetUserName": "alice",
            "TargetDomainName": "WORKGROUP",
            "IpAddress": "203.0.113.5",
            "LogonType": "10",
        },
    ))

    assert findings[0].rule == "WINDOWS_FAILED_LOGON"
    assert findings[0].extra["ip"] == "203.0.113.5"
    assert findings[0].extra["logon_type"] == "10"
    assert findings[0].line_number == 42


def test_audit_log_clear_is_critical():
    finding = findings_from_event(WindowsEvent(
        channel="Security", event_id=1102, record_id=7
    ))[0]

    assert finding.rule == "WINDOWS_AUDIT_LOG_CLEARED"
    assert finding.severity == "CRITICAL"


def test_suspicious_powershell_is_high():
    finding = findings_from_event(WindowsEvent(
        channel="Microsoft-Windows-PowerShell/Operational",
        event_id=4104,
        record_id=8,
        data={"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('x')"},
    ))[0]

    assert finding.rule == "WINDOWS_POWERSHELL_ACTIVITY"
    assert finding.severity == "HIGH"
    assert finding.extra["suspicious"] is True
