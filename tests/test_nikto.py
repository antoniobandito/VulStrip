import json
from pathlib import Path

from harness.parsers.nikto import NiktoParser


NIKTO_JSON = {
    "host": "https://app.example.test",
    "vulnerabilities": [
        {
            "id": "999962",
            "method": "GET",
            "url": "/.env",
            "msg": "/.env: Environment file may be exposed",
            "osvdb": 123456,
        },
        {
            "method": "GET",
            "url": "/old.php",
            "msg": "/old.php: CVE-2024-1234 may apply; verify version",
        },
    ],
}


NIKTO_TEXT = """\
- Nikto v2.5.0
+ Target Host: app.example.test
+ Target Port: 443
+ Target Hostname: app.example.test
+ Start Time: 2026-08-24 00:00:00
+ /.env: Environment file may be exposed
+ OSVDB-3092: /admin/: This might be interesting
+ /old.php: CVE-2024-1234 may apply; verify version
+ End Time: 2026-08-24 00:00:05
"""


def test_nikto_json_detection(tmp_path: Path):
    path = tmp_path / "nikto.json"
    content = json.dumps(NIKTO_JSON)
    path.write_text(content, encoding="utf-8")

    assert NiktoParser().can_parse(path, content) is True


def test_non_nikto_json_is_not_detected(tmp_path: Path):
    path = tmp_path / "generic.json"
    content = json.dumps({"findings": [{"asset": "example.test"}]})
    path.write_text(content, encoding="utf-8")

    assert NiktoParser().can_parse(path, content) is False


def test_nikto_json_maps_to_findings(tmp_path: Path):
    path = tmp_path / "nikto.json"
    content = json.dumps(NIKTO_JSON)
    path.write_text(content, encoding="utf-8")

    findings = NiktoParser().parse(path, content)

    assert len(findings) == 2
    assert all(finding.scanner == "nikto" for finding in findings)
    assert findings[0].asset_id == "https://app.example.test"
    assert findings[0].finding_id
    assert findings[0].evidence[0].source_tool == "nikto"
    assert findings[0].evidence[0].source_file == str(path)


def test_nikto_json_preserves_cve_as_lead(tmp_path: Path):
    path = tmp_path / "nikto.json"
    content = json.dumps(NIKTO_JSON)
    path.write_text(content, encoding="utf-8")

    findings = NiktoParser().parse(path, content)

    cve_finding = next(
        finding
        for finding in findings
        if any("CVE-2024-1234" in ref for ref in finding.references)
    )

    assert "CVE-2024-1234" in cve_finding.references[0]
    assert "verify version" in cve_finding.description


def test_nikto_text_detection(tmp_path: Path):
    path = tmp_path / "nikto.txt"
    path.write_text(NIKTO_TEXT, encoding="utf-8")

    assert NiktoParser().can_parse(path, NIKTO_TEXT) is True


def test_nikto_text_maps_findings_and_evidence(tmp_path: Path):
    path = tmp_path / "nikto.txt"
    path.write_text(NIKTO_TEXT, encoding="utf-8")

    findings = NiktoParser().parse(path, NIKTO_TEXT)

    assert len(findings) == 3
    assert all(
        finding.asset_id == "app.example.test"
        for finding in findings
    )
    assert all(finding.scanner == "nikto" for finding in findings)
    assert any(
        finding.evidence[0].structured_data["osvdb"] == "3092"
        for finding in findings
    )


def test_nikto_text_extracts_cve(tmp_path: Path):
    path = tmp_path / "nikto.txt"
    path.write_text(NIKTO_TEXT, encoding="utf-8")

    findings = NiktoParser().parse(path, NIKTO_TEXT)

    assert any(
        "CVE-2024-1234" in reference
        for finding in findings
        for reference in finding.references
    )


def test_nikto_parser_is_deterministic(tmp_path: Path):
    path = tmp_path / "nikto.json"
    content = json.dumps(NIKTO_JSON)
    path.write_text(content, encoding="utf-8")

    parser = NiktoParser()
    first = parser.parse(path, content)
    second = parser.parse(path, content)

    assert [item.finding_id for item in first] == [
        item.finding_id for item in second
    ]