#!/usr/bin/env python3
"""
MalwareBazaar APK Signature Fetcher
====================================
Pulls Android APK malware signatures from multiple MalwareBazaar API
endpoints, enriches them with metadata, classifies severity intelligently,
and merges everything into a local signatures JSON database.

Usage:
    python ms.py                          # defaults: 24h, signatures.json
    python ms.py --timeframe 1h           # last 1 hour only
    python ms.py --output my_sigs.json    # custom output file
    python ms.py --tags banker rat        # extra tag queries
    python ms.py --api-key YOUR_KEY       # provide API key
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

import requests

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ms")

# ── Constants ────────────────────────────────────────────────────────────────
API_URL = "https://mb-api.abuse.ch/api/v1/"

# Tags commonly associated with Android malware — queried individually
DEFAULT_TAGS = ["android", "banker", "spyware", "trojan", "rat", "sms", "adware"]

# Families that bump severity to CRITICAL regardless of VT ratio
CRITICAL_FAMILIES = {
    "banker", "ransomware", "rat", "keylogger", "rootkit",
    "cerberus", "anubis", "hydra", "ermac", "hook",
    "sharkbot", "xenomorph", "godfather", "coper", "octo",
}

# Families that bump severity to at least HIGH
HIGH_FAMILIES = {
    "trojan", "spyware", "sms", "dropper", "downloader",
    "joker", "harly", "facestealer", "fleckpe",
}

MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds, doubled on each retry
API_KEY = os.environ.get("MALWAREBAZAAR_API_KEY")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _api_post(payload: dict, retries: int = MAX_RETRIES) -> dict | None:
    """POST to MalwareBazaar with retry + backoff. Returns JSON or None."""
    headers = {}
    if API_KEY:
        headers["API-KEY"] = API_KEY

    delay = RETRY_BACKOFF
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(API_URL, data=payload, headers=headers, timeout=30)
            if resp.status_code == 429:
                log.warning("Rate-limited (429). Waiting %ds …", delay)
                time.sleep(delay)
                delay *= 2
                continue
            
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("query_status") == "ok":
                return data
            
            error = data.get("error")
            if error == "Unauthorized":
                log.error("API Error: Unauthorized. Please provide a valid MalwareBazaar API key.")
                log.error("Obtain one at: https://abuse.ch/account/")
                return None
            
            # API returned a valid JSON but no results/other error
            log.debug("query_status=%s for payload %s", data.get("query_status"), payload)
            return None
        except requests.RequestException as exc:
            log.warning("Attempt %d/%d failed: %s", attempt, retries, exc)
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
    log.error("All %d attempts failed for payload %s", retries, payload)
    return None


def _parse_vt_ratio(uploads: str | None) -> float:
    """Parse VirusTotal-style 'X/Y' string into a 0-1 ratio."""
    if not uploads:
        return 0.0
    try:
        parts = uploads.split("/")
        if len(parts) == 2:
            return int(parts[0]) / max(int(parts[1]), 1)
    except (ValueError, ZeroDivisionError):
        pass
    return 0.0


def classify_severity(
    tags: list[str],
    signature: str,
    vt_ratio: float,
    clamav: list[str] | None,
) -> str:
    """Derive severity from multiple signals instead of hard-coding 'critical'."""
    all_labels = {t.lower() for t in tags}
    if signature:
        all_labels.add(signature.lower())

    # ── Critical ─────────────────────────────────────────────────────────
    if vt_ratio >= 0.50 or all_labels & CRITICAL_FAMILIES:
        return "critical"

    # ── High ─────────────────────────────────────────────────────────────
    if vt_ratio >= 0.25 or all_labels & HIGH_FAMILIES:
        return "high"

    # ── Medium ───────────────────────────────────────────────────────────
    if clamav or vt_ratio >= 0.10:
        return "medium"

    # ── Low ──────────────────────────────────────────────────────────────
    return "low"


def build_entry(item: dict) -> dict:
    """Build a rich signature entry from a raw MalwareBazaar item."""
    tags = item.get("tags") or []
    signature = item.get("signature") or "Unknown"
    intel = item.get("intelligence") or {}
    clamav = intel.get("clamav") or []
    vt_uploads = intel.get("uploads") if isinstance(intel.get("uploads"), str) else None
    vt_ratio = _parse_vt_ratio(vt_uploads)

    return {
        "name": signature,
        "severity": classify_severity(tags, signature, vt_ratio, clamav),
        "family": tags[0] if tags else "unknown",
        "tags": tags,
        "description": f"Detected by MalwareBazaar on {item.get('first_seen', 'N/A')}",
        "md5": item.get("md5_hash"),
        "sha1": item.get("sha1_hash"),
        "sha256": item.get("sha256_hash"),
        "file_size": item.get("file_size"),
        "first_seen": item.get("first_seen"),
        "last_seen": item.get("last_seen"),
        "reporter": item.get("reporter"),
        "delivery_method": item.get("delivery_method"),
        "clamav": clamav,
        "vt_ratio": vt_uploads,
        "vt_percent": round(vt_ratio * 100, 1),
    }


# ── Data collection ─────────────────────────────────────────────────────────

def fetch_recent_apks(timeframe: str) -> dict[str, dict]:
    """Query get_recent and filter for APK file type."""
    log.info("Fetching recent submissions (%s) …", timeframe)
    data = _api_post({"query": "get_recent", "selector": timeframe})
    if not data:
        return {}

    results = {}
    for item in data.get("data", []):
        if (item.get("file_type") or "").lower() == "apk":
            sha = item["sha256_hash"]
            results[sha] = build_entry(item)
    log.info("  → %d APK samples from get_recent", len(results))
    return results


def fetch_by_filetype() -> dict[str, dict]:
    """Query get_file_type directly for APKs (returns latest 100)."""
    log.info("Fetching by file_type=apk …")
    data = _api_post({"query": "get_file_type", "file_type": "apk", "limit": "100"})
    if not data:
        return {}

    results = {}
    for item in data.get("data", []):
        sha = item["sha256_hash"]
        results[sha] = build_entry(item)
    log.info("  → %d APK samples from get_file_type", len(results))
    return results


def fetch_by_tags(tags: list[str]) -> dict[str, dict]:
    """Query get_taginfo for each tag and keep APK results."""
    results = {}
    for tag in tags:
        log.info("Fetching tag '%s' …", tag)
        data = _api_post({"query": "get_taginfo", "tag": tag, "limit": "100"})
        if not data:
            continue
        count = 0
        for item in data.get("data", []):
            if (item.get("file_type") or "").lower() == "apk":
                sha = item["sha256_hash"]
                if sha not in results:
                    results[sha] = build_entry(item)
                    count += 1
        log.info("  → %d new APK samples from tag '%s'", count, tag)
        time.sleep(0.5)  # polite rate-limit between tag queries
    return results


# ── Merge & persist ─────────────────────────────────────────────────────────

def load_existing(path: str) -> dict:
    """Load existing signatures file; create skeleton if missing."""
    if not os.path.exists(path):
        log.info("No existing file at %s — starting fresh.", path)
        return {"version": "0.0.0", "signatures": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_signatures(data: dict, path: str) -> None:
    """Atomically write signatures JSON."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    os.replace(tmp, path)
    log.info("Saved to %s", path)


def print_summary(
    total_found: int,
    new_count: int,
    dup_count: int,
    severity_counts: Counter,
    family_counts: Counter,
) -> None:
    """Print a human-readable stats summary."""
    print("\n" + "=" * 60)
    print("  MALWAREBAZAAR APK SIGNATURE UPDATE SUMMARY")
    print("=" * 60)
    print(f"  Total APK samples found : {total_found}")
    print(f"  New signatures added    : {new_count}")
    print(f"  Duplicates skipped      : {dup_count}")
    print()
    print("  Severity breakdown (new):")
    for sev in ("critical", "high", "medium", "low"):
        cnt = severity_counts.get(sev, 0)
        bar = "█" * cnt
        print(f"    {sev:<9s}  {cnt:>4d}  {bar}")
    print()
    print("  Top 10 families (new):")
    for family, cnt in family_counts.most_common(10):
        print(f"    {family:<24s}  {cnt}")
    print("=" * 60 + "\n")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch & merge Android APK malware signatures from MalwareBazaar."
    )
    parser.add_argument(
        "--timeframe", default="24h", choices=["1h", "3h", "24h"],
        help="Time window for 'get_recent' query (default: 24h)",
    )
    parser.add_argument(
        "--output", default="signatures_updated.json",
        help="Output file path (default: signatures_updated.json)",
    )
    parser.add_argument(
        "--input", default="signatures.json",
        help="Existing signatures file to merge into (default: signatures.json)",
    )
    parser.add_argument(
        "--tags", nargs="*", default=None,
        help="Extra tags to query (defaults: android, banker, spyware, …)",
    )
    parser.add_argument(
        "--api-key", help="MalwareBazaar API key (overrides environment variable)",
    )
    args = parser.parse_args()

    if args.api_key:
        global API_KEY
        API_KEY = args.api_key

    tags = args.tags if args.tags is not None else DEFAULT_TAGS

    # ── Collect from all sources ─────────────────────────────────────────
    all_samples: dict[str, dict] = {}

    recent = fetch_recent_apks(args.timeframe)
    all_samples.update(recent)

    by_type = fetch_by_filetype()
    all_samples.update(by_type)

    by_tags = fetch_by_tags(tags)
    all_samples.update(by_tags)

    total_found = len(all_samples)
    log.info("Total unique APK samples collected: %d", total_found)

    if total_found == 0:
        log.warning("No APK samples found. Exiting.")
        sys.exit(0)

    # ── Merge with existing DB ───────────────────────────────────────────
    existing = load_existing(args.input)
    existing_sigs = existing.get("signatures", {})

    new_count = 0
    dup_count = 0
    severity_counts: Counter = Counter()
    family_counts: Counter = Counter()

    for sha, entry in all_samples.items():
        if sha in existing_sigs:
            dup_count += 1
            continue
        existing_sigs[sha] = entry
        new_count += 1
        severity_counts[entry["severity"]] += 1
        family_counts[entry["family"]] += 1

    existing["signatures"] = existing_sigs
    existing["version"] = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    existing["last_updated"] = datetime.now(timezone.utc).isoformat()
    existing["total_signatures"] = len(existing_sigs)

    # ── Save & summarise ─────────────────────────────────────────────────
    save_signatures(existing, args.output)
    print_summary(total_found, new_count, dup_count, severity_counts, family_counts)


if __name__ == "__main__":
    main()