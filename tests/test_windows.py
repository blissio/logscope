import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_windows_default_log_paths_are_selected():
    paths = logscope.get_default_log_paths(platform_name="Windows")
    assert paths[0].endswith("WindowsPowerShell") or paths[0].startswith("C:")
