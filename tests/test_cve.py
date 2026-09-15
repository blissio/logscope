import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "logscope.py"
spec = importlib.util.spec_from_file_location("logscope", MODULE_PATH)
logscope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logscope)

from cve_client import CVECache, match_records
from software_inventory import inventory_from_records


def test_inventory_normalizes_and_deduplicates_products():
    products = inventory_from_records([
        {"DisplayName": "Example App", "DisplayVersion": "1.2.3", "Publisher": "Acme"},
        {"DisplayName": "Example App", "DisplayVersion": "1.2.3", "Publisher": "Acme"},
        {"DisplayName": "", "DisplayVersion": "9.9"},
    ])

    assert len(products) == 1
    assert products[0].name == "Example App"


def test_cve_cache_round_trip(tmp_path):
    database = tmp_path / "cve.db"
    record = {
        "id": "CVE-2026-0001",
        "lastModified": "2026-09-15T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Example App vulnerability."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
    }

    with CVECache(database) as cache:
        assert cache.put([record]) == 1
        assert cache.records()[0]["id"] == "CVE-2026-0001"
        cache.set_sync_value("last_sync", "now")
        assert cache.get_sync_value("last_sync") == "now"


def test_heuristic_match_is_marked_low_confidence():
    products = inventory_from_records([
        {"DisplayName": "Example App", "DisplayVersion": "1.2.3"},
    ])
    matches = match_records(products, [{
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "en", "value": "Example App vulnerability."}],
    }])

    assert matches[0].confidence == "heuristic"
    assert matches[0].cve_id == "CVE-2026-0001"
