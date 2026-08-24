from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

class Evidence(BaseModel):
    evidence_id: str
    source_tool: str
    source_file: str | None = None
    raw_text: str | None = None
    structured_data: dict[str, Any] | None = None
    observed_at: datetime | None = None

class Finding(BaseModel):
    finding_id: str
    asset: str
    asset_type: Literal["host", "service", "url", "domain", "endpoint", "unknown"] = "unknown"
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    title: str
    description: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwes: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    fingerprint: str
