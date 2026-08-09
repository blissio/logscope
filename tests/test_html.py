import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_render_html_writes_report(tmp_path):
    result = logscope.ScanResult(
        scan_time="now",
        files_parsed=["/tmp/auth.log"],
        total_lines=1,
        findings=[
            logscope.Finding(
                rule="SSH_FAILED_LOGIN",
                severity="LOW",
                description="Failed login",
                source_file="/tmp/auth.log",
                line_number=1,
                raw_line="failed password",
            )
        ],
    )

    output = tmp_path / "report.html"
    logscope.render_html(result, output=str(output))

    assert output.exists()
    assert "SSH_FAILED_LOGIN" in output.read_text(encoding="utf-8")
