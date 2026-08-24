from pathlib import Path
import hashlib
import json

import typer
import yaml

from harness.models.finding import Evidence, Finding
from harness.parsers.nmap_xml import NmapXMLParser


app = typer.Typer(no_args_is_help=True)


def make_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def parse_json(path: Path, text: str) -> list[Finding]:
    rows = json.loads(text)

    if isinstance(rows, dict):
        rows = rows.get("findings", rows.get("results", [rows]))

    findings: list[Finding] = []

    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            continue

        asset = str(
            row.get("asset")
            or row.get("host")
            or row.get("hostname")
            or row.get("url")
            or "unknown"
        )

        title = str(
            row.get("title")
            or row.get("name")
            or row.get("issue")
            or "Unclassified scanner observation"
        )

        raw_row = json.dumps(row, sort_keys=True)

        evidence_id = f"e-{make_id(f'{path}:{i}:{raw_row}')}"
        fingerprint = make_id(
            f"{asset}|{row.get('port')}|{title}".lower()
        )

        findings.append(
            Finding(
                finding_id=f"f-{fingerprint}",
                asset=asset,
                asset_type=(
                    "url"
                    if asset.startswith(("http://", "https://"))
                    else "unknown"
                ),
                port=row.get("port"),
                protocol=row.get("protocol"),
                service=row.get("service"),
                title=title,
                description=row.get("description"),
                cve_ids=row.get("cve_ids", row.get("cves", [])),
                tags=row.get("tags", []),
                source_tools=["generic_json"],
                fingerprint=fingerprint,
                evidence=[
                    Evidence(
                        evidence_id=evidence_id,
                        source_tool="generic_json",
                        source_file=str(path),
                        raw_text=raw_row,
                        structured_data=row,
                    )
                ],
            )
        )

    return findings


def parse_input(path: Path) -> list[Finding]:
    content = path.read_text()

    nmap_parser = NmapXMLParser()

    if nmap_parser.can_parse(path, content):
        return nmap_parser.parse(path, content)

    if path.suffix.lower() == ".json":
        return parse_json(path, content)

    return []


@app.command()
def ingest(
    input: Path = typer.Option(..., "--input"),
    scope: Path = typer.Option(..., "--scope"),
    output: Path = typer.Option(..., "--output"),
):
    """Normalize JSON and Nmap XML reconnaissance into canonical findings."""

    if not input.exists():
        raise typer.BadParameter(f"Input path does not exist: {input}")

    if not scope.exists():
        raise typer.BadParameter(f"Scope file does not exist: {scope}")

    scope_data = yaml.safe_load(scope.read_text()) or {}

    if not scope_data.get("engagement_id"):
        raise typer.BadParameter(
            "scope.yaml must define engagement_id"
        )

    if not scope_data.get("authorized_assets"):
        raise typer.BadParameter(
            "scope.yaml must define authorized_assets"
        )

    if input.is_file():
        paths = [input]
    else:
        paths = sorted(
            path
            for path in input.rglob("*")
            if path.is_file()
            and path.suffix.lower() in {".json", ".xml"}
        )

    if not paths:
        raise typer.BadParameter(
            f"No .json or .xml files found under: {input}"
        )

    findings_by_fingerprint: dict[str, Finding] = {}

    for path in paths:
        for finding in parse_input(path):
            existing = findings_by_fingerprint.get(finding.fingerprint)

            if existing is None:
                findings_by_fingerprint[finding.fingerprint] = finding
                continue

            existing.evidence.extend(finding.evidence)
            existing.source_tools = sorted(
                set(existing.source_tools + finding.source_tools)
            )

    payload = {
        "report_version": "1.0",
        "run_id": make_id(str(output.resolve())),
        "scope": scope_data,
        "input_files": [str(path) for path in paths],
        "findings": [
            finding.model_dump(mode="json")
            for finding in findings_by_fingerprint.values()
        ],
    }

    output.write_text(json.dumps(payload, indent=2))

    typer.echo(
        f"Wrote {len(findings_by_fingerprint)} findings to {output}"
    )


if __name__ == "__main__":
    app()