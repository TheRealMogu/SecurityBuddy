#!/usr/bin/env python3
"""Verify the vendored third-party JavaScript against static/vendor/VENDOR.json.

Vendoring buys a tight CSP and privacy, but it costs automatic updates on
libraries that parse untrusted files. This script is the counterweight: it
proves the committed bytes are exactly what the manifest claims, and (with
--check-registry) tells you when upstream has moved on.

Usage:
    python3 tools/verify_vendor.py                  # offline: hashes only
    python3 tools/verify_vendor.py --check-registry # also ask npm for newer versions

Exit code 0 = everything matches. Non-zero = a file was modified, is missing,
or (with --check-registry) a pinned package is behind upstream.

No third-party imports — runs on a bare Python 3.11.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_DIR = REPO_ROOT / "static" / "vendor"
MANIFEST = VENDOR_DIR / "VENDOR.json"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def latest_version(package: str) -> str | None:
    """Ask the npm registry for the current 'latest' dist-tag."""
    # Imported lazily so the offline path needs no network stack at all.
    import urllib.request

    url = f"https://registry.npmjs.org/{package}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.load(response)
    except Exception as exc:  # noqa: BLE001 - offline is a normal outcome here
        print(f"    ! could not reach the npm registry: {exc}")
        return None
    return payload.get("dist-tags", {}).get("latest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check-registry", action="store_true",
                        help="also query npm for newer upstream versions")
    args = parser.parse_args()

    if not MANIFEST.exists():
        print(f"FAIL: manifest not found at {MANIFEST}")
        return 2

    manifest = json.loads(MANIFEST.read_text())
    failures: list[str] = []
    outdated: list[str] = []

    for package in manifest["packages"]:
        name = package["name"]
        version = package["version"]
        print(f"\n{name} @ {version}  ({package['license']}, pinned {package['pinned_on']})")
        print(f"  {package['role']}")

        for entry in package["files"]:
            path = VENDOR_DIR / entry["path"]
            if not path.exists():
                print(f"  MISSING  {entry['path']}")
                failures.append(f"{name}: {entry['path']} is missing")
                continue

            actual = sha256_of(path)
            if actual == entry["sha256"]:
                size_kb = path.stat().st_size / 1024
                print(f"  ok       {entry['path']}  ({size_kb:,.0f} KB)")
            else:
                print(f"  MODIFIED {entry['path']}")
                print(f"             expected {entry['sha256']}")
                print(f"             actual   {actual}")
                failures.append(f"{name}: {entry['path']} does not match the manifest")

        if args.check_registry:
            upstream = latest_version(name)
            if upstream is None:
                pass
            elif upstream == version:
                print(f"  ok       up to date with npm 'latest' ({upstream})")
            else:
                print(f"  BEHIND   npm 'latest' is {upstream}, pinned is {version}")
                outdated.append(f"{name}: {version} -> {upstream}")

    print("\n" + "=" * 68)
    if failures:
        print("FAIL — the vendored files do not match the manifest:")
        for failure in failures:
            print(f"  - {failure}")
        print("\nEither restore the files or, if the change is intentional, follow the")
        print("update procedure in DEVELOPMENT.md and refresh VENDOR.json.")
        return 1

    print("All vendored files match VENDOR.json.")

    if outdated:
        print("\nUpstream has newer releases:")
        for item in outdated:
            print(f"  - {item}")
        print("\nThese libraries parse untrusted input, so a new release may carry")
        print("security fixes. Review the upstream changelog and follow the update")
        print("procedure in DEVELOPMENT.md -> 'Dipendenze vendorizzate'.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
