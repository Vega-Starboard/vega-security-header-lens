#!/usr/bin/env python3
"""Static verification for Vega Security Header Lens."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PERMISSIONS = {"activeTab", "storage", "webRequest"}
FORBIDDEN_PERMISSIONS = {
    "<all_urls>",
    "cookies",
    "downloads",
    "history",
    "tabs",
    "webRequestBlocking",
}
EXPECTED_OPTIONAL_HOSTS = {"http://*/*", "https://*/*"}


def fail(message: str) -> None:
    print(f"verify_extension: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_manifest() -> dict:
    try:
        return json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"manifest.json is invalid JSON: {error}")


def assert_manifest(manifest: dict) -> None:
    if manifest.get("manifest_version") != 3:
        fail("manifest_version must be 3")

    permissions = set(manifest.get("permissions", []))
    missing = EXPECTED_PERMISSIONS - permissions
    forbidden = FORBIDDEN_PERMISSIONS & permissions
    if missing:
        fail(f"missing expected permissions: {sorted(missing)}")
    if forbidden:
        fail(f"forbidden permissions present: {sorted(forbidden)}")

    optional_hosts = set(manifest.get("optional_host_permissions", []))
    if optional_hosts != EXPECTED_OPTIONAL_HOSTS:
        fail(f"optional_host_permissions must be {sorted(EXPECTED_OPTIONAL_HOSTS)}")
    if manifest.get("host_permissions"):
        fail("host_permissions must not be requested at install time")

    gecko = manifest.get("browser_specific_settings", {}).get("gecko", {})
    data_permissions = gecko.get("data_collection_permissions", {})
    if data_permissions.get("required") != ["none"]:
        fail("manifest must declare no data collection for Firefox")

    background = manifest.get("background", {})
    if background.get("service_worker"):
        fail("Firefox-first manifest must not use background.service_worker")
    if background.get("scripts") != ["src/background.js"]:
        fail("background script must be src/background.js")

    for icon_path in manifest.get("icons", {}).values():
        if not (ROOT / icon_path).exists():
            fail(f"missing icon: {icon_path}")
    popup = manifest.get("action", {}).get("default_popup")
    if not popup or not (ROOT / popup).exists():
        fail("default popup is missing")


def assert_sources() -> None:
    for relative in ["src/background.js", "src/analyzer.js", "src/popup.js"]:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if re.search(r"\b(fetch|XMLHttpRequest|sendBeacon)\s*\(", text):
            fail(f"network API call found in {relative}")
        if "document.cookie" in text:
            fail(f"cookie access found in {relative}")
        if "webRequestBlocking" in text:
            fail(f"webRequestBlocking reference found in {relative}")
        if "filterResponseData" in text:
            fail(f"response body filtering found in {relative}")
        if "requestBody" in text:
            fail(f"request body access found in {relative}")

    background = (ROOT / "src/background.js").read_text(encoding="utf-8")
    for required in [
        "webRequest.onHeadersReceived",
        '"responseHeaders"',
        "permissions.request",
    ]:
        if required not in background:
            fail(f"background missing required marker: {required}")

    if re.search(r'"blocking"|\'blocking\'', background):
        fail("background must not request blocking webRequest mode")


def assert_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required_phrases = [
        "Lawful Use Only",
        "Permissions",
        "webRequest",
        "optional host permissions",
        "No request bodies",
        "No response bodies",
        "No cookie values",
        "shields.io",
    ]
    for phrase in required_phrases:
        if phrase not in readme:
            fail(f"README missing phrase: {phrase}")


def main() -> int:
    manifest = read_manifest()
    assert_manifest(manifest)
    assert_sources()
    assert_docs()
    print("security header lens static verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
