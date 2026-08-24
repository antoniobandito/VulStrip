from pathlib import Path
import hashlib
import json
import re
from typing import Any

from harness.parsers.common import canonical_fingerprint
from harness.models.finding import Evidence, Finding


class NiktoParser:
    tool_name = "nikto"

    def can_parse(self, path: Path, content: str) -> bool:
        suffix = path.suffix.lower()

        if suffix == ".json":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return False
            return self._looks_like_nikto_json(data)

        if suffix in {".txt", ".text", ".log"}:
            return (
                "Nikto v" in content
                or "Nikto scan" in content
                or bool(
                    re.search(
                        r"^\s*\+\s+(?:OSVDB|CVE-|/)",
                        content,
                        re.MULTILINE,
                    )
                )
            )

        return False

    def parse(self, path: Path, content: str) -> list[Finding]:
        if path.suffix.lower() == ".json":
            return self._parse_json(path, content)
        return self._parse_text(path, content)

    def _looks_like_nikto_json(self, data: Any) -> bool:
        if isinstance(data, list):
            return any(
                isinstance(item, dict) and self._has_nikto_fields(item)
                for item in data
            )

        if isinstance(data, dict):
            if any(key in data for key in ("vulnerabilities", "items")):
                return True
            return self._has_nikto_fields(data)

        return False

    @staticmethod
    def _has_nikto_fields(item: dict[str, Any]) -> bool:
        keys = {str(key).lower() for key in item}
        return bool(
            keys & {"msg", "message", "osvdb", "url", "method", "nikto"}
        )

    def _parse_json(self, path: Path, content: str) -> list[Finding]:
        data = json.loads(content)
        host = "unknown"

        if isinstance(data, list):
            rows = data
        else:
            host = str(
                data.get("host")
                or data.get("hostname")
                or data.get("target")
                or "unknown"
            )
            rows = (
                data.get("vulnerabilities")
                or data.get("items")
                or data.get("findings")
                or [data]
            )

        return [
            self._finding_from_row(path, host, row, index)
            for index, row in enumerate(rows)
            if isinstance(row, dict)
        ]

    def _finding_from_row(
        self,
        path: Path,
        host: str,
        row: dict[str, Any],
        index: int,
    ) -> Finding:
        url = str(
            row.get("url")
            or row.get("uri")
            or row.get("path")
            or ""
        )
        message = str(
            row.get("msg")
            or row.get("message")
            or row.get("description")
            or "Nikto observation"
        )
        method = row.get("method")
        osvdb = row.get("osvdb") or row.get("OSVDB")
        cve_ids = self._extract_cves(row, message)
        asset = self._asset_from_host(host, url)
        port = self._port_from_url(host, url)
        protocol = self._protocol(host, url)
        raw = json.dumps(row, sort_keys=True)
        fingerprint = canonical_fingerprint(
            asset=asset,
            asset_type=(
            "url"
            if self._is_absolute_url(asset)
            else "endpoint"
        ),
        port=port,
        protocol=protocol,
        service=(
            "http"
            if protocol == "http"
            else "https"
            if protocol == "https"
            else None
        ),
        title=message,
        path=url,
        cve_ids=cve_ids,
        )
        evidence_id = hashlib.sha256(
        f"{path}:{index}:{raw}".encode()
        ).hexdigest()[:16]

        return Finding(
            finding_id=f"f-{fingerprint}",
            asset=asset,
            asset_type=(
                "url"
                if self._is_absolute_url(asset)
                else "endpoint"
            ),
            port=port,
            protocol=protocol,
            service=(
                "http"
                if protocol == "http"
                else "https"
                if protocol == "https"
                else None
            ),
            title=message[:160],
            description=message,
            cve_ids=cve_ids,
            tags=["nikto", "scanner_observation"],
            source_tools=[self.tool_name],
            fingerprint=fingerprint,
            evidence=[
                Evidence(
                    evidence_id=f"e-{evidence_id}",
                    source_tool=self.tool_name,
                    source_file=str(path),
                    raw_text=raw,
                    structured_data={
                        "url": url or None,
                        "method": method,
                        "osvdb": osvdb,
                    },
                )
            ],
        )

    def _parse_text(self, path: Path, content: str) -> list[Finding]:
        host = self._text_host(content)
        findings: list[Finding] = []

        metadata_prefixes = (
            "Target Host:",
            "Target IP:",
            "Target Hostname:",
            "Target Port:",
            "Start Time:",
            "End Time:",
            "Server:",
            "Retrieved:",
            "Scan terminated:",
            "Host(s) tested:",
        )

        for index, line in enumerate(content.splitlines()):
            match = re.match(r"^\s*\+\s+(.*)$", line)
            if not match:
                continue

            message = match.group(1).strip()
            if message.startswith(metadata_prefixes):
                continue

            url_match = re.search(r"https?://[^\s]+", message)
            url = (
                url_match.group(0).rstrip(".,)")
                if url_match
                else self._path_from_message(message)
            )
            osvdb_match = re.search(
                r"OSVDB[- ]?(\d+)",
                message,
                re.IGNORECASE,
            )
            cve_ids = self._extract_cves({}, message)
            asset = self._asset_from_host(host, url)
            port = self._port_from_url(host, url)
            protocol = self._protocol(host, url)
            fingerprint = canonical_fingerprint(
                asset=asset,
                asset_type=(
                    "url"
                    if self._is_absolute_url(asset)
                    else "endpoint"
            ),
            port=port,
            protocol=protocol,
            service=(
                "http"
                if protocol == "http"
                else "https"
                if protocol == "https"
                else None
            ),
            title=message,
            path=url,
            cve_ids=cve_ids,
            )
            evidence_id = (
                "e-"
                + hashlib.sha256(
                    f"{path}:{index}:{line}".encode()
                ).hexdigest()[:16]
            )

            findings.append(
                Finding(
                    finding_id=f"f-{fingerprint}",
                    asset=asset,
                    asset_type=(
                        "url"
                        if self._is_absolute_url(asset)
                        else "endpoint"
                    ),
                    port=port,
                    protocol=protocol,
                    service=(
                        "http"
                        if protocol == "http"
                        else "https"
                        if protocol == "https"
                        else None
                    ),
                    title=message[:160],
                    description=message,
                    cve_ids=cve_ids,
                    tags=["nikto", "scanner_observation"],
                    source_tools=[self.tool_name],
                    fingerprint=fingerprint,
                    evidence=[
                        Evidence(
                            evidence_id=evidence_id,
                            source_tool=self.tool_name,
                            source_file=str(path),
                            raw_text=line,
                            structured_data={
                                "osvdb": (
                                    osvdb_match.group(1)
                                    if osvdb_match
                                    else None
                                ),
                                "url": url or None,
                            },
                        )
                    ],
                )
            )

        return findings

    @staticmethod
    def _is_absolute_url(value: str) -> bool:
        return value.startswith(("http://", "https://"))

    @staticmethod
    def _text_host(content: str) -> str:
        patterns = (
            r"^\+\s+Target Hostname:\s*(.+)$",
            r"^\+\s+Target Host:\s*(.+)$",
            r"^\+\s+Target IP:\s*(.+)$",
        )

        for pattern in patterns:
            match = re.search(
                pattern,
                content,
                re.MULTILINE | re.IGNORECASE,
            )
            if match:
                return match.group(1).strip()

        return "unknown"

    @staticmethod
    def _path_from_message(message: str) -> str:
        match = re.search(r"(?:^|\s)(/[^\s:]*)", message)
        return match.group(1).rstrip(".,)") if match else ""

    @staticmethod
    def _asset_from_host(host: str, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        return host

    @staticmethod
    def _protocol(host: str, url: str) -> str | None:
        value = url or host
        match = re.match(r"^(https?)://", value, re.IGNORECASE)
        return match.group(1).lower() if match else None

    @staticmethod
    def _port_from_url(host: str, url: str) -> int | None:
        value = url or host
        match = re.match(
            r"^https?://[^/:]+:(\d+)",
            value,
            re.IGNORECASE,
        )
        return int(match.group(1)) if match else None

    @staticmethod
    def _extract_cves(
        row: dict[str, Any],
        message: str,
    ) -> list[str]:
        values = row.get("cves") or row.get("cve_ids") or []

        if isinstance(values, str):
            values = [values]

        found = list(values) if isinstance(values, list) else []
        found.extend(
            re.findall(
                r"CVE-\d{4}-\d{4,7}",
                message,
                re.IGNORECASE,
            )
        )

        normalized = {
            value.upper()
            for value in found
            if isinstance(value, str)
            and re.fullmatch(
                r"CVE-\d{4}-\d{4,7}",
                value.upper(),
            )
        }

        return sorted(normalized)

    @staticmethod
    def _fingerprint(
        asset: str,
        port: int | None,
        method: Any,
        message: str,
        url: str,
    ) -> str:
        value = f"{asset}|{port}|{method}|{url}|{message}".lower()
        return hashlib.sha256(value.encode()).hexdigest()[:16]