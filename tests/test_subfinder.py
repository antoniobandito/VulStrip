import json
from pathlib import Path

from harness.parsers.subfinder import SubfinderParser


SUBFINDER_JSONL = """\
{"host":"api.example.test","source":"crtsh"}
{"host":"mail.example.test","source":"alienvault","ip":"192.0.2.20"}
{"host":"WWW.Example.Test.","sources":["crtsh","github"]}
"""


def test_subfinder_jsonl_detection(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    assert SubfinderParser().can_parse(path, SUBFINDER_JSONL) is True


def test_unrelated_jsonl_is_not_detected(tmp_path: Path):
    path = tmp_path / "other.jsonl"
    content = '{"message":"hello"}\n'
    path.write_text(content)

    assert SubfinderParser().can_parse(path, content) is False


def test_subfinder_maps_hosts_to_findings(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    findings = SubfinderParser().parse(path, SUBFINDER_JSONL)

    assert len(findings) == 3
    assert findings[0].asset == "api.example.test"
    assert findings[0].asset_type == "domain"
    assert findings[0].source_tools == ["subfinder"]
    assert findings[0].title == "Subdomain discovered"


def test_subfinder_normalizes_hostname(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    findings = SubfinderParser().parse(path, SUBFINDER_JSONL)

    assert findings[2].asset == "www.example.test"
    assert findings[2].evidence[0].structured_data["source"] == "crtsh,github"


def test_subfinder_preserves_evidence(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    findings = SubfinderParser().parse(path, SUBFINDER_JSONL)
    evidence = findings[1].evidence[0]

    assert evidence.source_tool == "subfinder"
    assert evidence.source_file == str(path)
    assert evidence.raw_text == '{"host":"mail.example.test","source":"alienvault","ip":"192.0.2.20"}'
    assert evidence.structured_data["ip"] == "192.0.2.20"


def test_subfinder_skips_malformed_lines(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    content = (
        '{"host":"valid.example.test","source":"crtsh"}\n'
        'not valid json\n'
        '{"source":"missing-host"}\n'
    )
    path.write_text(content)

    findings = SubfinderParser().parse(path, content)

    assert len(findings) == 1
    assert findings[0].asset == "valid.example.test"


def test_subfinder_is_deterministic(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    parser = SubfinderParser()
    first = parser.parse(path, SUBFINDER_JSONL)
    second = parser.parse(path, SUBFINDER_JSONL)

    assert [item.finding_id for item in first] == [item.finding_id for item in second]
    assert [item.fingerprint for item in first] == [item.fingerprint for item in second]


def test_duplicate_hosts_have_same_fingerprint(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    content = (
        '{"host":"api.example.test","source":"crtsh"}\n'
        '{"host":"API.EXAMPLE.TEST.","source":"github"}\n'
    )
    path.write_text(content)

    findings = SubfinderParser().parse(path, content)

    assert len(findings) == 2
    assert findings[0].fingerprint == findings[1].fingerprint