"""Native Windows Event Log collection and security finding normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Optional


class WindowsEventLogUnavailable(RuntimeError):
    """Raised when native Windows event collection cannot be used."""


@dataclass
class WindowsEvent:
    channel: str
    event_id: int
    record_id: int
    timestamp: Optional[str] = None
    provider: Optional[str] = None
    computer: Optional[str] = None
    data: dict[str, Any] = field(default_factory=dict)
    message: str = ""


SUPPORTED_CHANNELS = (
    "Security",
    "System",
    "Windows PowerShell",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
)


def _event_data(event: WindowsEvent, *names: str) -> Optional[str]:
    for name in names:
        value = event.data.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _severity_for_logon(logon_type: Optional[str], privileged: bool = False) -> str:
    if privileged:
        return "HIGH"
    if logon_type in {"2", "10", "12", "13"}:
        return "MEDIUM"
    return "LOW"


def _finding(
    event: WindowsEvent,
    rule: str,
    severity: str,
    description: str,
    *,
    extra: Optional[dict[str, Any]] = None,
) -> Any:
    # Imported lazily so this module can be unit-tested without importing the CLI.
    from logscope import Finding

    metadata = {
        "channel": event.channel,
        "event_id": event.event_id,
        "record_id": event.record_id,
        "provider": event.provider,
        "computer": event.computer,
    }
    metadata.update({key: value for key, value in (extra or {}).items() if value is not None})
    return Finding(
        rule=rule,
        severity=severity,
        description=description,
        source_file=f"Windows Event Log: {event.channel}",
        line_number=event.record_id,
        raw_line=event.message or repr(event.data),
        timestamp=event.timestamp,
        extra=metadata,
    )


def findings_from_event(event: WindowsEvent) -> list[Any]:
    """Convert one native Windows event into zero or more LogScope findings."""
    account = _event_data(event, "TargetUserName", "SubjectUserName", "AccountName")
    domain = _event_data(event, "TargetDomainName", "SubjectDomainName", "AccountDomain")
    source_ip = _event_data(event, "IpAddress", "SourceAddress", "ClientAddress")
    logon_type = _event_data(event, "LogonType")
    account_label = f"{domain}\\{account}" if domain and account else account or "unknown"

    if event.event_id == 4625:
        return [_finding(
            event,
            "WINDOWS_FAILED_LOGON",
            "LOW",
            f"Failed Windows logon for {account_label}" + (f" from {source_ip}" if source_ip else ""),
            extra={"user": account, "domain": domain, "ip": source_ip, "logon_type": logon_type},
        )]

    if event.event_id == 4624:
        privileged = (account or "").lower() in {"administrator", "admin"}
        severity = _severity_for_logon(logon_type, privileged=privileged)
        return [_finding(
            event,
            "WINDOWS_SUCCESSFUL_LOGON",
            severity,
            f"Successful Windows logon for {account_label}" + (f" from {source_ip}" if source_ip else ""),
            extra={"user": account, "domain": domain, "ip": source_ip, "logon_type": logon_type},
        )]

    if event.event_id == 4672:
        return [_finding(
            event,
            "WINDOWS_SPECIAL_PRIVILEGES",
            "HIGH",
            f"Special privileges assigned to {account_label}",
            extra={"user": account, "domain": domain},
        )]

    if event.event_id == 4720:
        created = _event_data(event, "TargetUserName", "AccountName") or "unknown"
        return [_finding(
            event,
            "WINDOWS_USER_CREATED",
            "HIGH",
            f"Windows user account created: {created}",
            extra={"user": created, "domain": domain},
        )]

    if event.event_id in {4728, 4732, 4756}:
        group = _event_data(event, "TargetUserName", "TargetGroupName") or "unknown"
        member = _event_data(event, "MemberName", "MemberSid") or "unknown"
        return [_finding(
            event,
            "WINDOWS_PRIVILEGED_GROUP_CHANGE",
            "HIGH",
            f"Account {member} added to Windows group {group}",
            extra={"user": member, "group": group},
        )]

    if event.event_id == 1102:
        return [_finding(
            event,
            "WINDOWS_AUDIT_LOG_CLEARED",
            "CRITICAL",
            "Windows Security audit log was cleared",
            extra={"user": account, "domain": domain},
        )]

    if event.event_id == 7045:
        service = _event_data(event, "ServiceName", "param1") or "unknown"
        image = _event_data(event, "ImagePath", "param2")
        return [_finding(
            event,
            "WINDOWS_SERVICE_INSTALLED",
            "HIGH",
            f"Windows service installed: {service}" + (f" ({image})" if image else ""),
            extra={"service": service, "image_path": image, "user": account},
        )]

    if event.event_id in {4103, 4104}:
        script = _event_data(event, "ScriptBlockText", "Command", "Payload", "Message") or event.message
        lowered = script.lower()
        suspicious = any(token in lowered for token in (
            "invoke-expression", "downloadstring", "encodedcommand", "frombase64string",
            "-nop", "-w hidden", "mimikatz", "invoke-webrequest",
        ))
        severity = "HIGH" if suspicious else "LOW"
        return [_finding(
            event,
            "WINDOWS_POWERSHELL_ACTIVITY",
            severity,
            f"PowerShell activity detected: {script[:160]}",
            extra={"command": script, "suspicious": suspicious, "user": account},
        )]

    if event.event_id in {1116, 1117}:
        threat = _event_data(event, "ThreatName", "Threat", "Name") or "unknown threat"
        action = "detected" if event.event_id == 1116 else "remediated"
        return [_finding(
            event,
            "WINDOWS_DEFENDER_DETECTION",
            "CRITICAL" if event.event_id == 1116 else "HIGH",
            f"Windows Defender {action}: {threat}",
            extra={"threat": threat, "action": action},
        )]

    return []


def findings_from_events(events: Iterable[WindowsEvent]) -> list[Any]:
    findings: list[Any] = []
    for event in events:
        findings.extend(findings_from_event(event))
    return findings


def _timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "Format"):
        value = value.Format()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _record_to_event(record: Any, channel: str) -> WindowsEvent:
    event_id = int(getattr(record, "EventID", 0)) & 0xFFFF
    inserts = list(getattr(record, "StringInserts", None) or [])
    data = {f"data_{index}": value for index, value in enumerate(inserts)}
    field_indexes = {
        4624: {
            "SubjectUserName": 1, "SubjectDomainName": 2,
            "TargetUserName": 5, "TargetDomainName": 6,
            "LogonType": 8, "IpAddress": 18,
        },
        4625: {
            "SubjectUserName": 1, "SubjectDomainName": 2,
            "TargetUserName": 5, "TargetDomainName": 6,
            "LogonType": 10, "IpAddress": 19,
        },
        4672: {"SubjectUserName": 1, "SubjectDomainName": 2},
        4720: {
            "SubjectUserName": 1, "SubjectDomainName": 2,
            "TargetUserName": 5, "TargetDomainName": 6,
        },
        4728: {"TargetUserName": 1, "MemberName": 5},
        4732: {"TargetUserName": 1, "MemberName": 5},
        4756: {"TargetUserName": 1, "MemberName": 5},
        7045: {"ServiceName": 0, "ImagePath": 1, "AccountName": 4},
    }
    for name, index in field_indexes.get(event_id, {}).items():
        if index < len(inserts):
            data[name] = inserts[index]
    if event_id in {4103, 4104} and inserts:
        data["ScriptBlockText"] = inserts[-1]
    if event_id in {1116, 1117} and inserts:
        data["ThreatName"] = inserts[0]
    return WindowsEvent(
        channel=channel,
        event_id=event_id,
        record_id=int(getattr(record, "RecordNumber", 0)),
        timestamp=_timestamp(getattr(record, "TimeGenerated", None)),
        provider=getattr(record, "SourceName", None),
        computer=getattr(record, "ComputerName", None),
        data=data,
        message=" | ".join(str(value) for value in inserts),
    )


def _xml_to_event(xml_text: str, channel: str) -> WindowsEvent:
    root = ET.fromstring(xml_text)
    system = root.find("{*}System")
    if system is None:
        raise ValueError("Windows event XML has no System section")
    event_id = int(system.findtext("{*}EventID", "0"))
    record_id = int(system.findtext("{*}EventRecordID", "0"))
    provider = system.find("{*}Provider")
    time_created = system.find("{*}TimeCreated")
    computer = system.findtext("{*}Computer")
    data: dict[str, Any] = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name") or f"data_{len(data)}"
        data[name] = item.text or ""
    message = " | ".join(f"{key}={value}" for key, value in data.items())
    return WindowsEvent(
        channel=channel,
        event_id=event_id,
        record_id=record_id,
        timestamp=time_created.attrib.get("SystemTime") if time_created is not None else None,
        provider=provider.attrib.get("Name") if provider is not None else None,
        computer=computer,
        data=data,
        message=message,
    )


def collect_events(
    channels: Iterable[str] = SUPPORTED_CHANNELS,
    *,
    max_events: int = 1000,
    after_record_ids: Optional[dict[str, int]] = None,
) -> list[WindowsEvent]:
    """Read recent events through the native Windows Event Log API."""
    if __import__("sys").platform != "win32":
        raise WindowsEventLogUnavailable("Native Windows event collection requires Windows.")
    try:
        import win32evtlog  # type: ignore[import-not-found]
    except ImportError as exc:
        raise WindowsEventLogUnavailable(
            "pywin32 is required for native Windows Event Log collection; install it with 'pip install pywin32'."
        ) from exc

    if not hasattr(win32evtlog, "EvtQuery"):
        raise WindowsEventLogUnavailable(
            "This pywin32 build lacks the modern Windows Event Log API (EvtQuery)."
        )
    events: list[WindowsEvent] = []
    cursors = after_record_ids or {}
    for channel in channels:
        try:
            query = win32evtlog.EvtQuery(
                channel,
                win32evtlog.EvtQueryReverseDirection,
                "*[System[EventRecordID > 0]]",
            )
        except Exception as exc:
            raise WindowsEventLogUnavailable(f"Cannot open Windows event channel '{channel}': {exc}") from exc
        try:
            for handle in win32evtlog.EvtNext(query, max_events, 0):
                converted = _xml_to_event(
                    win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml),
                    channel,
                )
                if converted.record_id <= cursors.get(channel, 0):
                    break
                events.append(converted)
        finally:
            win32evtlog.EvtClose(query)
    return sorted(events, key=lambda event: (event.timestamp or "", event.record_id))
