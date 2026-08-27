import json
from pathlib import Path

import pytest

from harness.models.finding import Finding, SeverityLevel
from harness.parsers.nikto import parse_nikto_json

RECON_DIR = Path(__file__).resolve().parent.parent / "recon"


def load_nikto_sample(name: str) -> list[dict]:
    path = RECON_DIR / name
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Assume top-level list or dict with "vulnerabilities"/"findings" key
    if isinstance(data, list):
        return data
    for key in ("vulnerabilities", "findings", "results"):
        if key in data and isinstance(data[key], list):
            return data[key]
    # Fallback: treat whole object as a single finding wrapped in a list
    return [data]


def test_nikto_sample_parses_to_canonical_findings():
    records = load_nikto_sample("sample-nikto.json")
    findings = list(parse_nikto_json(records))

    assert len(findings) > 0
    for f in findings:
        assert isinstance(f, Finding)
        assert f.scanner == "nikto"
        assert f.asset_id
        assert f.normalized_severity in {s.value for s in SeverityLevel}
        assert isinstance(f.cwe_ids, list)
        assert isinstance(f.references, list)
        assert f.finding_id


def test_nikto_severity_normalization():
    # Synthetic records to test severity mapping
    raw_records = [
        {
            "host": "example.com",
            "severity": "Critical",
            "description": "Critical issue",
        },
        {
            "host": "example.com",
            "severity": "high",
            "description": "High issue",
        },
        {
            "host": "example.com",
            "severity": "Medium",
            "description": "Medium issue",
        },
        {
            "host": "example.com",
            "severity": "low",
            "description": "Low issue",
        },
        {
            "host": "example.com",
            "severity": "Info",
            "description": "Info issue",
        },
        {
            "host": "example.com",
            "severity": "weird",
            "description": "Unknown severity",
        },
    ]

    findings = list(parse_nikto_json(raw_records))
    severities = [f.normalized_severity for f in findings]

    expected = [
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
        SeverityLevel.LOW,
        SeverityLevel.INFO,
        SeverityLevel.UNKNOWN,
    ]

    assert severities == expected


def test_nikto_cwe_parsing():
    raw_records = [
        {
            "host": "example.com",
            "severity": "Medium",
            "description": "CWE test",
            "cwe": "CWE-79",
        },
        {
            "host": "example.com",
            "severity": "Medium",
            "description": "Multiple CWEs",
            "cwe": "CWE-79,CWE-200",
        },
        {
            "host": "example.com",
            "severity": "Medium",
            "description": "CWE without prefix",
            "cwe": "79",
        },
    ]

    findings = list(parse_nikto_json(raw_records))
    cwe_results = [f.cwe_ids for f in findings]

    assert cwe_results[0] == ["CWE-79"]
    assert set(cwe_results[1]) == {"CWE-79", "CWE-200"}
    assert cwe_results[2] == ["CWE-79"]