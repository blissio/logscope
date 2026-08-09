import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_windows_log_lines_are_parsed_as_findings(tmp_path):
    log_file = tmp_path / "Security.log"
    log_file.write_text(
        "2024-08-09 10:22:15 ERROR Failed password for admin from 10.0.0.5\n",
        encoding="utf-8",
    )

    scanner = logscope.LogScope(log_paths=[str(log_file)], brute_threshold=1)
    result = scanner.scan()

    assert any(f.rule == "SSH_FAILED_LOGIN" for f in result.findings)
