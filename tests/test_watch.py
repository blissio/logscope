import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_watch_mode_uses_polling_interval(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jan 01 00:00:00 host sshd[1]: Failed password for root from 1.2.3.4\n", encoding="utf-8")

    watcher = logscope.LogScope(log_paths=[str(log_file)], brute_threshold=1)
    state = watcher.watch_once(interval=0.01)

    assert state["file_exists"] is True
    assert state["path"] == str(log_file)
