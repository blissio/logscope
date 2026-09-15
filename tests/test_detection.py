import importlib.util
from datetime import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_custom_business_hours_control_login_severity(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Jan 01 07:30:00 host sshd[1]: Accepted password for alice from 10.0.0.5\n",
        encoding="utf-8",
    )

    scanner = logscope.LogScope(
        log_paths=[str(log_file)],
        off_hours_start=time(7, 0),
        off_hours_end=time(19, 0),
    )

    result = scanner.scan()

    finding = next(f for f in result.findings if f.rule == "SSH_ACCEPTED_LOGIN")
    assert finding.severity == "LOW"
    assert finding.extra["off_hours"] is False


def test_port_scan_finding_keeps_firewall_source(tmp_path):
    log_file = tmp_path / "kern.log"
    log_line = (
        "Jan 01 08:30:00 host kernel: [UFW BLOCK] IN=eth0 OUT= "
        "SRC=172.16.0.99 DST=10.0.0.1 DPT=22 DROP\n"
    )
    log_file.write_text(log_line, encoding="utf-8")

    scanner = logscope.LogScope(
        log_paths=[str(log_file)],
        port_scan_threshold=1,
    )

    result = scanner.scan()

    finding = next(f for f in result.findings if f.rule == "PORT_SCAN_DETECTED")
    assert finding.source_file == str(log_file)
    assert finding.line_number == 1
    assert finding.raw_line == log_line.rstrip()
