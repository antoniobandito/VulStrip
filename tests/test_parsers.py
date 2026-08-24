import json
from pathlib import Path

import pytest

from harness.cli import parse_input
from harness.parsers.nmap_xml import NmapXMLParser


NMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Example HTTPS" version="1.0"/>
        <script id="ssl-cert" output="certificate observed"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parser_detects_xml(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)

    parser = NmapXMLParser()

    assert parser.can_parse(path, NMAP_XML) is True


def test_nmap_parser_rejects_non_nmap_xml(tmp_path: Path):
    path = tmp_path / "other.xml"
    content = "<root><item>not nmap</item></root>"
    path.write_text(content)

    parser = NmapXMLParser()

    assert parser.can_parse(path, content) is False


def test_nmap_parser_extracts_ports_and_services(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)

    findings = NmapXMLParser().parse(path, NMAP_XML)

    assert len(findings) == 2

    first = findings[0]

    assert first.asset == "192.0.2.10"
    assert first.port == 22 or first.port == 443
    assert first.protocol == "tcp"
    assert first.service in {"ssh", "https"}
    assert first.source_tools == ["nmap"]


def test_nmap_parser_preserves_evidence(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)

    findings = NmapXMLParser().parse(path, NMAP_XML)

    https_finding = next(
        finding for finding in findings
        if finding.port == 443
    )

    assert len(https_finding.evidence) == 1

    evidence = https_finding.evidence[0]

    assert evidence.source_tool == "nmap"
    assert evidence.source_file == str(path)
    assert "<port" in evidence.raw_text
    assert evidence.structured_data["port_state"] == "open"
    assert evidence.structured_data["scripts"][0]["id"] == "ssl-cert"


def test_nmap_parser_is_deterministic(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML)

    parser = NmapXMLParser()

    first_run = parser.parse(path, NMAP_XML)
    second_run = parser.parse(path, NMAP_XML)

    first_ids = [finding.finding_id for finding in first_run]
    second_ids = [finding.finding_id for finding in second_run]

    first_fingerprints = [
        finding.fingerprint for finding in first_run
    ]
    second_fingerprints = [
        finding.fingerprint for finding in second_run
    ]

    assert first_ids == second_ids
    assert first_fingerprints == second_fingerprints


def test_nmap_parser_rejects_malformed_xml(tmp_path: Path):
    path = tmp_path / "broken.xml"
    content = "<nmaprun><host>"
    path.write_text(content)

    parser = NmapXMLParser()

    with pytest.raises(Exception):
        parser.parse(path, content)


def test_generic_json_parser_extracts_finding(tmp_path: Path):
    path = tmp_path / "scanner.json"

    data = [
        {
            "host": "app.example.test",
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "title": "TLS service detected",
            "description": "HTTPS service observed",
            "tags": ["tls"],
        }
    ]

    content = json.dumps(data)
    path.write_text(content)

    findings = parse_input(path)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.asset == "app.example.test"
    assert finding.port == 443
    assert finding.service == "https"
    assert finding.title == "TLS service detected"
    assert finding.source_tools == ["generic_json"]
    assert finding.evidence[0].source_tool == "generic_json"


def test_generic_json_parser_accepts_findings_object(tmp_path: Path):
    path = tmp_path / "scanner.json"

    data = {
        "findings": [
            {
                "asset": "api.example.test",
                "title": "Exposed API service",
            }
        ]
    }

    content = json.dumps(data)
    path.write_text(content)

    findings = parse_input(path)

    assert len(findings) == 1
    assert findings[0].asset == "api.example.test"


def test_cli_ingestion_deduplicates_findings(tmp_path: Path):
    recon_dir = tmp_path / "recon"
    recon_dir.mkdir()

    first = recon_dir / "first.json"
    second = recon_dir / "second.json"

    row = {
        "host": "app.example.test",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "title": "TLS service detected",
    }

    first.write_text(json.dumps([row]))
    second.write_text(json.dumps([row]))

    findings = []

    for path in sorted(recon_dir.glob("*.json")):
        findings.extend(parse_input(path))

    deduplicated = {}

    for finding in findings:
        if finding.fingerprint not in deduplicated:
            deduplicated[finding.fingerprint] = finding
        else:
            existing = deduplicated[finding.fingerprint]
            existing.evidence.extend(finding.evidence)

    assert len(findings) == 2
    assert len(deduplicated) == 1

    result = next(iter(deduplicated.values()))

    assert len(result.evidence) == 2