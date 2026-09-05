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
    assert findings[0].asset_id == "api.example.test"
    assert findings[0].scanner == "subfinder"


def test_subfinder_normalizes_hostname(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    findings = SubfinderParser().parse(path, SUBFINDER_JSONL)

    assert findings[2].asset_id == "www.example.test"
    assert findings[2].evidence[0].structured_data["source"] == "crtsh,github"


def test_subfinder_preserves_evidence(tmp_path: Path):
    path = tmp_path / "subfinder.jsonl"
    path.write_text(SUBFINDER_JSONL)

    findings = SubfinderParser().parse(path, SUBFINDER_JSONL)
    
    evidence = findings[1].evidence[0]

    assert evidence.source_tool == "subfinder"
    assert evidence.source_file == str(path)
    assert evidence.raw_text is not None
    assert "host" in evidence.structured_data
    assert "source" in evidence.structured_data


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
    assert findings[0].asset_id == "valid.example.test"