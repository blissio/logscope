"""Installed Windows software inventory from uninstall registry keys."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Iterable


@dataclass(frozen=True)
class InstalledSoftware:
    name: str
    version: str | None = None
    publisher: str | None = None
    install_location: str | None = None
    registry_path: str | None = None
    registry_view: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


UNINSTALL_PATHS = (
    (r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit"),
    (r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "32-bit"),
)


def _deduplicate(items: Iterable[InstalledSoftware]) -> list[InstalledSoftware]:
    seen: set[tuple[str, str | None, str | None]] = set()
    result: list[InstalledSoftware] = []
    for item in items:
        key = (item.name.casefold(), item.version, item.publisher)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (item.name.casefold(), item.version or ""))


def inventory_from_records(records: Iterable[dict[str, Any]]) -> list[InstalledSoftware]:
    """Normalize registry-shaped records; useful for tests and alternate providers."""
    items: list[InstalledSoftware] = []
    for record in records:
        name = str(record.get("DisplayName") or "").strip()
        if not name:
            continue
        items.append(InstalledSoftware(
            name=name,
            version=str(record["DisplayVersion"]).strip() if record.get("DisplayVersion") else None,
            publisher=str(record["Publisher"]).strip() if record.get("Publisher") else None,
            install_location=str(record["InstallLocation"]).strip() if record.get("InstallLocation") else None,
            registry_path=record.get("registry_path"),
            registry_view=record.get("registry_view"),
        ))
    return _deduplicate(items)


def collect_installed_software() -> list[InstalledSoftware]:
    """Read machine and current-user uninstall keys on Windows."""
    import sys
    if sys.platform != "win32":
        raise RuntimeError("Windows software inventory requires Windows.")
    try:
        import winreg
    except ImportError as exc:
        raise RuntimeError("Windows registry access is unavailable in this Python installation.") from exc

    roots = ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU"))
    items: list[InstalledSoftware] = []
    for root, root_name in roots:
        for subkey, view_name in UNINSTALL_PATHS:
            try:
                key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
            except OSError:
                continue
            with key:
                for index in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        child_name = winreg.EnumKey(key, index)
                        child_path = f"{subkey}\\{child_name}"
                        child = winreg.OpenKey(key, child_name, 0, winreg.KEY_READ)
                    except OSError:
                        continue
                    with child:
                        values: dict[str, Any] = {}
                        for value_name in ("DisplayName", "DisplayVersion", "Publisher", "InstallLocation"):
                            try:
                                values[value_name] = winreg.QueryValueEx(child, value_name)[0]
                            except OSError:
                                pass
                        values.update({
                            "registry_path": f"{root_name}\\{child_path}",
                            "registry_view": view_name,
                        })
                        items.extend(inventory_from_records([values]))
    return _deduplicate(items)
