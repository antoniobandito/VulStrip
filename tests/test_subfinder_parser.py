from pathlib import Path

import pytest

from harness.models.finding import Finding, SeverityLevel
from harness.parsers.subfinder import parse_subfinder_jsonl

RECON_DIR = Path(__file__).resolve().parent.parent / "recon"


def load_subfinder_lines(name: str) -> list[str]:
    path = RECON_DIR / name
    with path.open("r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def test_subfinder_sample_parses_to_canonical_findings():
    lines = load_subfinder_lines("sample-subfinder.jsonl")
    findings = list(parse_subfinder_jsonl(lines))

    assert len(findings) > 0
    for f in findings:
        assert isinstance(f, Finding)
        assert f.scanner == "subfinder"
        assert f.asset_id  # domain/host
        assert f.normalized_severity in {s.value for s in SeverityLevel}
        assert isinstance(f.cwe_ids, list)
        assert isinstance(f.references, list)
        assert f.finding_id


def test_subfinder_severity_normalization():
    lines = [
        '{"host": "api.example.com", "severity": "high"}',
        '{"host": "api.example.com", "severity": "MEDIUM"}',
        '{"host": "api.example.com", "severity": "low"}',
        '{"host": "api.example.com", "severity": "weird"}',
    ]

    findings = list(parse_subfinder_jsonl(lines))
    severities = [f.normalized_severity for f in findings]

    expected = [
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.UNKNOWN,
    ]

    assert severities == expected


def test_subfinder_asset_resolution():
    lines = [
        '{"host": "api.example.com"}',
        '{"host": "cdn.example.com"}',
    ]

    findings = list(parse_subfinder_jsonl(lines))
    asset_ids = [f.asset_id for f in findings]

    assert asset_ids == ["api.example.com", "cdn.example.com"]