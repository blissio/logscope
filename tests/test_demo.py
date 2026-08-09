import importlib.util
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"

spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)


def test_run_demo_uses_default_threshold_when_none():
    args = SimpleNamespace(brute_threshold=None)
    result = logscope.run_demo(args, brute_threshold=None)

    assert result.findings
