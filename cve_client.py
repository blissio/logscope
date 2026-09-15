"""Small, cache-aware NVD CVE client and conservative product matching."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlencode

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass(frozen=True)
class VulnerabilityMatch:
    cve_id: str
    product_name: str
    product_version: str | None
    severity: str | None
    cvss_score: float | None
    confidence: str
    kev: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "kev": self.kev,
            "description": self.description,
        }


class CVECache:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(path)
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                modified TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cve_sync (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "CVECache":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def put(self, records: Iterable[dict[str, Any]]) -> int:
        count = 0
        for record in records:
            cve = record.get("cve", record)
            cve_id = cve.get("id")
            modified = cve.get("lastModified") or cve.get("published") or ""
            if not cve_id:
                continue
            self.connection.execute(
                "INSERT OR REPLACE INTO cve_records (cve_id, modified, payload) VALUES (?, ?, ?)",
                (cve_id, modified, json.dumps(cve, sort_keys=True)),
            )
            count += 1
        self.connection.commit()
        return count

    def records(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM cve_records ORDER BY cve_id").fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_sync_value(self, name: str) -> str | None:
        row = self.connection.execute("SELECT value FROM cve_sync WHERE name = ?", (name,)).fetchone()
        return row[0] if row else None

    def set_sync_value(self, name: str, value: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO cve_sync (name, value) VALUES (?, ?)", (name, value)
        )
        self.connection.commit()


def _request_json(url: str, api_key: str | None = None, retries: int = 3) -> dict[str, Any]:
    headers = {"User-Agent": "LogScope/1.1"}
    if api_key:
        headers["apiKey"] = api_key
    for attempt in range(retries):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == retries - 1:
                raise
        except URLError:
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)
    raise RuntimeError("NVD request failed")


def sync_nvd(
    cache: CVECache,
    *,
    api_key: str | None = None,
    modified_since: str | None = None,
    page_size: int = 2000,
    max_pages: int | None = None,
) -> int:
    """Fetch modified NVD records into the local cache."""
    start_index = 0
    total = 0
    pages = 0
    while True:
        params = {"startIndex": str(start_index), "resultsPerPage": str(page_size)}
        if modified_since:
            params["lastModStartDate"] = modified_since
        query = urlencode(params)
        payload = _request_json(f"{NVD_CVE_URL}?{query}", api_key=api_key)
        vulnerabilities = payload.get("vulnerabilities", [])
        total += cache.put(vulnerabilities)
        pages += 1
        start_index += len(vulnerabilities)
        if not vulnerabilities or start_index >= int(payload.get("totalResults", 0)):
            break
        if max_pages is not None and pages >= max_pages:
            break
    cache.set_sync_value("last_sync", datetime.now(timezone.utc).isoformat())
    return total


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def _cvss(cve: dict[str, Any]) -> tuple[str | None, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0].get("cvssData", {})
            return metric.get("baseSeverity"), metric.get("baseScore")
    return None, None


def match_records(software: Iterable[Any], records: Iterable[dict[str, Any]]) -> list[VulnerabilityMatch]:
    """Match only records whose CVE description names the installed product.

    This is intentionally a low-confidence fallback until curated CPE mappings exist.
    """
    matches: list[VulnerabilityMatch] = []
    for product in software:
        product_name = getattr(product, "name", "")
        product_version = getattr(product, "version", None)
        product_token = _normalized(product_name)
        if not product_token:
            continue
        for cve in records:
            description = _description(cve)
            if product_token not in _normalized(description):
                continue
            severity, score = _cvss(cve)
            matches.append(VulnerabilityMatch(
                cve_id=cve.get("id", "unknown"),
                product_name=product_name,
                product_version=product_version,
                severity=severity,
                cvss_score=score,
                confidence="heuristic",
                description=description,
            ))
    return matches
