import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_load_config_from_toml(tmp_path):
    config_path = tmp_path / "logscope.toml"
    config_path.write_text(
        """
[logscope]
logs = [\"/tmp/auth.log\", \"/tmp/syslog\"]
brute_threshold = 7
severity = \"HIGH\"
        """.strip(),
        encoding="utf-8",
    )

    config = logscope.load_config(config_path)

    assert config["logs"] == ["/tmp/auth.log", "/tmp/syslog"]
    assert config["brute_threshold"] == 7
    assert config["severity"] == "HIGH"


def test_load_config_defaults_when_file_missing(tmp_path):
    missing = tmp_path / "missing.toml"

    config = logscope.load_config(missing)

    assert config["logs"] == logscope.DEFAULT_LOG_PATHS
    assert config["brute_threshold"] == logscope.BRUTE_FORCE_THRESHOLD
    assert config["severity"] is None


def test_filter_findings_by_allowlist_and_ignorelist():
    finding = logscope.Finding(
        rule="SSH_ACCEPTED_LOGIN",
        severity="LOW",
        description="Successful SSH login",
        source_file="/tmp/auth.log",
        line_number=1,
        raw_line="Accepted password for root from 10.0.0.5",
        extra={"ip": "10.0.0.5", "user": "root"},
    )

    filtered = logscope.filter_findings([finding], allowlist=["10.0.0.5"], ignorelist=["root"])

    assert filtered == []


def test_event_store_persists_scan_and_findings(tmp_path):
    result = logscope.ScanResult(
        scan_time="2026-09-15T12:00:00Z",
        files_parsed=["/tmp/auth.log"],
        total_lines=1,
        findings=[
            logscope.Finding(
                rule="SSH_FAILED_LOGIN",
                severity="LOW",
                description="Failed SSH login attempt",
                source_file="/tmp/auth.log",
                line_number=1,
                raw_line="Failed password for admin from 10.0.0.5",
                extra={"ip": "10.0.0.5", "user": "admin"},
            )
        ],
    )

    database = tmp_path / "logscope.db"
    with logscope.EventStore(database) as store:
        scan_id = store.save_result(result)
        assert scan_id == 1

    import sqlite3
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
        row = connection.execute(
            "SELECT rule, severity, extra_json FROM findings"
        ).fetchone()

    assert row[0:2] == ("SSH_FAILED_LOGIN", "LOW")
    assert "10.0.0.5" in row[2]
