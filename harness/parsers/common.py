from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from harness.models.finding import Evidence, Finding


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
        "asset_type": asset_type.lower(),
        "port": port,
        "protocol": (protocol or "").lower(),
        "service": (service or "").lower(),
        "title": re.sub(r"\s+", " ", title.strip().lower()),
        "path": normalize_path(path),
        "cve_ids": normalize_cves(cve_ids),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}

    for finding in findings:
        fingerprint = finding.fingerprint or canonical_fingerprint(
            asset=finding.asset,
            asset_type=finding.asset_type,
            port=finding.port,
            protocol=finding.protocol,
            service=finding.service,
            title=finding.title,
            cve_ids=finding.cve_ids,
        )

        existing = merged.get(fingerprint)
        if existing is None:
            finding.fingerprint = fingerprint
            finding.finding_id = f"f-{fingerprint}"
            finding.source_tools = sorted(set(finding.source_tools))
            merged[fingerprint] = finding
            continue

        existing.source_tools = sorted(
            set(existing.source_tools + finding.source_tools)
        )
        existing.tags = sorted(set(existing.tags + finding.tags))
        existing.cve_ids = normalize_cves(existing.cve_ids + finding.cve_ids)

        known_evidence = {
            evidence.evidence_id
            for evidence in existing.evidence
        }
        existing.evidence.extend(
            evidence
            for evidence in finding.evidence
            if evidence.evidence_id not in known_evidence
        )

        if not existing.description and finding.description:
            existing.description = finding.description

    return sorted(merged.values(), key=lambda item: item.finding_id)


def load_recon_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]

    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SUPPORTED_RECON_EXTENSIONS
    )