from pathlib import Path
import hashlib
import json
from typing import Any

from harness.models.finding import Finding, Evidence
from harness.parsers.common import (
    canonical_fingerprint,
    normalize_severity,
)


class SubfinderParser:
    tool_name = "subfinder"

    def can_parse(self, path: Path, content: str) -> bool:
        if path.suffix.lower() not in {".jsonl", ".ndjson", ".json"}:
            return False

        saw_record = False

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(row, dict) and self._host_from_row(row):
                saw_record = True
                break

        return saw_record

    def parse(self, path: Path, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for index, line in enumerate(content.splitlines()):
            raw_line = line
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(row, dict):
                continue

            host = self._host_from_row(row)
            if not host:
                continue

            source = self._source_from_row(row)
            ip = self._ip_from_row(row)

            # Use row here, inside the loop
            raw_sev = row.get("severity") or row.get("risk") or "info"
            
            fingerprint = canonical_fingerprint(
                asset=host,
                asset_type="domain",
                port=None,
                protocol=None,
                service=None,
                title="Subdomain discovered",
            )
            evidence_id = hashlib.sha256(
                f"{path}:{index}:{raw_line}".encode()
            ).hexdigest()[:16]

            findings.append(
                Finding(
                    finding_id=f"f-{fingerprint}",
                    asset_id=host,
                    scanner=self.tool_name,
                    raw_severity=raw_sev,
                    normalized_severity=normalize_severity(raw_sev),
                    cwe_ids=[],
                    title="Subdomain discovered",
                    description=(
                        f"Subfinder reported the hostname {host}."
                    ),
                    evidence=[
                        Evidence(
                            evidence_id=f"e-{evidence_id}",
                            source_tool=self.tool_name,
                            source_file=str(path),
                            raw_text=raw_line,
                            structured_data={
                                "host": host,
                                "source": source,
                                "ip": ip,
                            },
                        )
                    ],
                )
            )

        return findings

    @staticmethod
    def _host_from_row(row: dict[str, Any]) -> str | None:
        value = row.get("host") or row.get("hostname") or row.get("name")
        if not isinstance(value, str):
            return None

        host = value.strip().lower().rstrip(".")
        return host or None

    @staticmethod
    def _source_from_row(row: dict[str, Any]) -> str | None:
        value = row.get("source") or row.get("sources")
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        return str(value) if value is not None else None

    @staticmethod
    def _ip_from_row(row: dict[str, Any]) -> str | None:
        value = row.get("ip") or row.get("ip_address")
        return str(value) if value is not None else None

    @staticmethod
    def _fingerprint(host: str) -> str:
        return hashlib.sha256(host.encode()).hexdigest()[:16]
    
  

def parse_subfinder_jsonl(
    lines: list[str] | str,
) -> list["Finding"]:
    """
    Convenience wrapper for tests: parse Subfinder JSONL into Findings.

    Accepts either a list of lines or a single JSONL string.
    """
    from pathlib import Path

    content = "\n".join(lines) if isinstance(lines, list) else lines
    return SubfinderParser().parse(Path("subfinder.jsonl"), content)