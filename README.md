# VulStrip — Step 1

A passive, evidence-grounded vulnerability-analysis harness. Step 1 implements the project skeleton, a scope manifest, generic JSON ingestion, canonical Pydantic findings, deterministic IDs, and basic deduplication.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Run

```bash
vulstrip ingest --input ./recon --scope ./scope.yaml --output ./normalized-findings.json
```

## Parsers

VulStrip includes parsers for:

- **Nikto** (`harness/parsers/nikto.py`): Consumes Nikto JSON output and emits `Finding` objects with:

  - `asset_id`: from `host`/`site`
  - `scanner`: `"nikto"`
  - `normalized_severity`: via `normalize_severity()`
  - `cwe_ids`: via `parse_cwe()`

- **Nmap XML** (`harness/parsers/nmap_xml.py`): Parses Nmap XML and emits findings per open port/service.
- **Subfinder** (`harness/parsers/subfinder.py`): Consumes JSONL lines with `host` and optional `severity`.

All parsers emit canonical `Finding` models defined in `harness/models/finding.py`.
