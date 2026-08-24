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

The first milestone intentionally performs no active scanning, exploitation, shell execution, or model calls.
