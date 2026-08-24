from pathlib import Path

from harness.models.finding import Evidence, Finding
from harness.parsers.common import (
    canonical_fingerprint,
    merge_findings,
    normalize_asset,
    normalize_cves,
    normalize_url,
)


def make_finding(
    *,
    asset: str,
    title: str,
    source_tool: str,
    evidence_id: str,
    fingerprint: str,
) -> Finding:
    return Finding(
        finding_id=f"f-{fingerprint}",
        asset=asset,
        asset_type="domain",
        title=title,
        source_tools=[source_tool],
        fingerprint=fingerprint,
        evidence=[
            Evidence(
                evidence_id=evidence_id,
                source_tool=source_tool,
                source_file=f"{source_tool}.json",
                raw_text=asset,
            )
        ],
    )


def test_normalize_asset_and_url():
    assert normalize_asset("Example.TEST.") == "example.test"
    assert normalize_url("HTTPS://Example.TEST/") == "https://example.test/"
    assert normalize_url("http://example.test:80/") == "http://example.test/"
    assert normalize_url("https://example.test:8443//admin/") == "https://example.test:8443/admin/"


def test_normalize_cves():
    assert normalize_cves(["cve-2024-1234", "CVE-2024-1234", "not-a-cve"]) == [
        "CVE-2024-1234"
    ]


def test_canonical_fingerprint_is_stable():
    first = canonical_fingerprint(
        asset="Example.TEST.",
        asset_type="domain",
        port=None,
        protocol=None,
        service=None,
        title="Subdomain   discovered",
    )
    second = canonical_fingerprint(
        asset="example.test",
        asset_type="domain",
        port=None,
        protocol=None,
        service=None,
        title="subdomain discovered",
    )

    assert first == second


def test_merge_findings_combines_sources_and_evidence():
    fingerprint = "same-finding"
    first = make_finding(
        asset="example.test",
        title="Observation",
        source_tool="nmap",
        evidence_id="e-nmap",
        fingerprint=fingerprint,
    )
    second = make_finding(
        asset="example.test",
        title="Observation",
        source_tool="nikto",
        evidence_id="e-nikto",
        fingerprint=fingerprint,
    )

    merged = merge_findings([second, first])

    assert len(merged) == 1
    assert merged[0].source_tools == ["nikto", "nmap"]
    assert {item.evidence_id for item in merged[0].evidence} == {
        "e-nmap",
        "e-nikto",
    }


def test_merge_findings_does_not_duplicate_evidence():
    fingerprint = "same-finding"
    first = make_finding(
        asset="example.test",
        title="Observation",
        source_tool="nmap",
        evidence_id="e-same",
        fingerprint=fingerprint,
    )
    second = make_finding(
        asset="example.test",
        title="Observation",
        source_tool="nmap",
        evidence_id="e-same",
        fingerprint=fingerprint,
    )

    merged = merge_findings([first, second])

    assert len(merged) == 1
    assert len(merged[0].evidence) == 1