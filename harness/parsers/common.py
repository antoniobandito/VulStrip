from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from urllib.parse import urlsplit, urlunsplit

from harness.models.finding import Finding, SeverityLevel


SUPPORTED_RECON_EXTENSIONS = {
    ".json",
    ".jsonl",
    ".ndjson",
    ".xml",
    ".txt",
    ".text",
    ".log",
}


def normalize_host(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.strip()

    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.hostname or value

    return value.strip().lower().rstrip(".") or "unknown"


def normalize_url(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()
    parsed = urlsplit(value)

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
    ):
        return value.rstrip("/") or "/"

    hostname = normalize_host(parsed.hostname)
    netloc = hostname

    if parsed.port is not None:
        default_port = (
            parsed.scheme.lower() == "http"
            and parsed.port == 80
        ) or (
            parsed.scheme.lower() == "https"
            and parsed.port == 443
        )

        if not default_port:
            netloc = f"{hostname}:{parsed.port}"

    original_path = parsed.path or "/"
    had_trailing_slash = original_path.endswith("/")

    path = re.sub(r"/{2,}", "/", original_path)

    if had_trailing_slash:
        path = path.rstrip("/") + "/"
    else:
        path = path.rstrip("/") or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            "",
        )
    )


def normalize_asset(value: str | None) -> str:
    if not value:
        return "unknown"

    value = value.strip()
    normalized_url = normalize_url(value)

    if normalized_url and normalized_url != value.rstrip("/"):
        return normalized_url

    return normalize_host(value)


def normalize_path(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()
    if not value.startswith("/"):
        value = "/" + value

    return re.sub(r"/{2,}", "/", value)


def normalize_cves(values: Iterable[str] | str | None) -> list[str]:
    if isinstance(values, str):
        values = [values]

    if not values:
        return []

    result = set()
    for value in values:
        if not isinstance(value, str):
            continue
        match = re.fullmatch(r"CVE-\d{4}-\d{4,7}", value.strip(), re.IGNORECASE)
        if match:
            result.add(value.upper())

    return sorted(result)


def canonical_fingerprint(
    *,
    asset: str,
    asset_type: str,
    port: int | None,
    protocol: str | None,
    service: str | None,
    title: str,
    path: str | None = None,
    cve_ids: Iterable[str] | None = None,
) -> str:
    payload = {
        "asset": normalize_asset(asset),
        "asset_type": (asset_type or "").strip().lower(),
        "port": port,
        "protocol": (protocol or "").strip().lower(),
        "service": (service or "").strip().lower(),
        "title": re.sub(r"\s+", " ", (title or "").strip().lower()),
        "path": normalize_path(path),
        "cve_ids": normalize_cves(cve_ids),
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """
    Deduplicate canonical findings using a stable fingerprint.

    Findings are considered duplicates when they share:
    - asset_id
    - scanner
    - title
    - CWE IDs
    """

    merged: dict[str, Finding] = {}

    for finding in findings:
        key = finding.metadata.get("fingerprint")
        if not key:
            key = canonical_fingerprint(
                asset=finding.asset_id,
                asset_type=finding.scanner,
                port=None,
                protocol=None,
                service=None,
                title=finding.title or "untitled finding",
                cve_ids=[],
            )

        existing = merged.get(key)

        if existing is None:
            merged[key] = finding
            continue

        # Merge evidence without duplication by evidence_id
        existing_ids = {e.evidence_id for e in existing.evidence}
        for e in finding.evidence:
            if e.evidence_id not in existing_ids:
                existing.evidence.append(e)
                existing_ids.add(e.evidence_id)

        # Merge other fields as needed
        existing.cwe_ids = sorted(set(existing.cwe_ids + finding.cwe_ids))
        existing.references = sorted(set(existing.references + finding.references))

        if not existing.description and finding.description:
            existing.description = finding.description

        if not existing.remediation and finding.remediation:
            existing.remediation = finding.remediation

        if finding.last_seen > existing.last_seen:
            existing.last_seen = finding.last_seen

    return sorted(merged.values(), key=lambda f: f.finding_id)

def load_recon_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SUPPORTED_RECON_EXTENSIONS
    )

def normalize_severity(raw: str | None) -> SeverityLevel:
    """
    Normalize scanner severity to the canonical SeverityLevel enum.
    """

    if raw is None:
        return SeverityLevel.UNKNOWN

    value = str(raw).strip().lower()

    mapping = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "informational": SeverityLevel.INFO,
    }

    return mapping.get(value, SeverityLevel.UNKNOWN)


def parse_cwe(raw: str | Iterable[str] | None) -> list[str]:
    """
    Normalize CWE values into canonical IDs such as:
    ["CWE-79", "CWE-200"].
    """

    if raw is None:
        return []

    if isinstance(raw, str):
        values = re.split(r"[,;]", raw)
    else:
        values = list(raw)

    result: list[str] = []

    for value in values:
        if not isinstance(value, str):
            continue

        match = re.search(r"\b(?:CWE[-\s]*)?(\d+)\b", value, re.IGNORECASE)

        if match:
            result.append(f"CWE-{match.group(1)}")

    return result


def merge_metadata(base: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge two metadata dictionaries, preferring `extra` on conflicts.

    This is useful when combining scanner-specific metadata with pipeline-level metadata.
    """
    merged: Dict[str, Any] = {}
    merged.update(base)
    merged.update(extra)
    return merged


def extract_asset_id(host: Optional[str], ip: Optional[str], domain: Optional[str]) -> str:
    """
    Resolve a canonical asset_id from various host-like fields.

    Priority:
      1. host (if present)
      2. domain (if present)
      3. ip (if present)
      4. "unknown" fallback
    """
    if host:
        return host
    if domain:
        return domain
    if ip:
        return ip
    return "unknown"


def safe_iter_items(items: Optional[Iterable[Any]]) -> Iterable[Any]:
    """
    Safely iterate over an optional iterable, treating None as empty.
    """
    if items is None:
        return []
    return items


def safe_list(value: Optional[Any]) -> List[Any]:
    """
    Convert a possibly-null value to a list:
      - None -> []
      - list -> as-is
      - other -> [value]
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]