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
