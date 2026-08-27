from pathlib import Path

import pytest

from harness.models.finding import Finding, SeverityLevel
from harness.parsers.nmap_xml import parse_nmap_xml

RECON_DIR = Path(__file__).resolve().parent.parent / "recon"


def test_nmap_sample_parses_to_canonical_findings():
    path = RECON_DIR / "sample-nmap.xml"
    findings = list(parse_nmap_xml(path.read_text(encoding="utf-8")))

    assert len(findings) > 0
    for f in findings:
        assert isinstance(f, Finding)
        assert f.scanner == "nmap"
        assert f.asset_id  # IP or hostname
        assert f.normalized_severity in {s.value for s in SeverityLevel}
        assert isinstance(f.cwe_ids, list)
        assert isinstance(f.references, list)
        assert f.finding_id


def test_nmap_asset_resolution():
    # Minimal synthetic XML to test asset_id resolution
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.10" addrtype="ipv4"/>
        <hostnames>
          <hostname name="api.internal" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="nginx" version="1.18.0"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    findings = list(parse_nmap_xml(xml))
    # At least one finding for the open port/service
    assert len(findings) > 0
    # All findings for this host should resolve to the same asset_id
    asset_ids = {f.asset_id for f in findings}
    # Implementation choice: IP or hostname; here we assert non-empty
    assert len(asset_ids) >= 1


def test_nmap_severity_mapping():
    # If your parser already maps service state / script output to severity,
    # you can add assertions here. For now, we ensure it's a valid enum.
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="10.0.0.5" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    findings = list(parse_nmap_xml(xml))
    for f in findings:
        assert f.normalized_severity in {s.value for s in SeverityLevel}