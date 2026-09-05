from pathlib import Path

from harness.parsers.nmap_xml import NmapXMLParser


NMAP_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parser_detects_xml(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML, encoding="utf-8")

    parser = NmapXMLParser()

    assert parser.can_parse(path, NMAP_XML) is True


def test_nmap_parser_rejects_non_nmap_xml(tmp_path: Path):
    path = tmp_path / "other.xml"
    content = "<root>not nmap</root>"
    path.write_text(content, encoding="utf-8")

    parser = NmapXMLParser()

    assert parser.can_parse(path, content) is False


def test_nmap_parser_extracts_ports_and_services(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML, encoding="utf-8")

    findings = NmapXMLParser().parse(path, NMAP_XML)

    assert len(findings) == 2

    first = findings[0]

    assert first.asset_id == "192.0.2.10"
    assert first.scanner == "nmap"
    assert first.evidence[0].structured_data["port"] in {22, 443}
    assert first.evidence[0].structured_data["protocol"] == "tcp"


def test_nmap_parser_preserves_evidence(tmp_path: Path):
    path = tmp_path / "scan.xml"
    path.write_text(NMAP_XML, encoding="utf-8")

    findings = NmapXMLParser().parse(path, NMAP_XML)

    https_finding = next(
        finding
        for finding in findings
        if finding.evidence[0].structured_data["port"] == 443
    )

    evidence = https_finding.evidence[0]

    
    assert evidence.source_tool == "nmap"
    assert evidence.source_file == str(path)
    assert evidence.raw_text is not None
    assert "port" in evidence.structured_data
    assert "protocol" in evidence.structured_data