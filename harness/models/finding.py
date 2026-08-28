from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import re
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    WONT_FIX = "wont_fix"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class CVSSv3(BaseModel):
    """Optional CVSS v3.1 vector and base score."""

    vector: str = Field(..., description="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    base_score: float = Field(..., ge=0.0, le=10.0, description="CVSS base score [0.0–10.0]")

    @field_validator("vector")
    @classmethod
    def validate_vector(cls, v: str) -> str:
        if not v.startswith("CVSS:3."):
            raise ValueError("CVSS vector must start with 'CVSS:3.'")
        return v


class Finding(BaseModel):
    """
    Canonical vulnerability finding for VulStrip.

    All fields are designed to be scanner-agnostic and suitable for
    normalization, deduplication, and downstream AI analysis.
    """
    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
    )

    # Identity & asset linkage
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for this finding")
    asset_id: str = Field(..., description="Logical asset identifier (e.g., hostname, IP, service key)")

    # Source & severity
    scanner: str = Field(..., description="Scanner/tool that produced this finding (e.g., nikto, nmap, subfinder)")
    raw_severity: Optional[str] = Field(None, description="Original severity string from scanner")
    normalized_severity: SeverityLevel = Field(SeverityLevel.UNKNOWN, description="Normalized severity level")

    # Classification
    cwe_ids: List[str] = Field(default_factory=list, description="Associated CWE IDs, e.g. ['CWE-79']")
    cvss_v3: Optional[CVSSv3] = Field(None, description="Optional CVSS v3.1 details")

    # Description & evidence
    title: Optional[str] = Field(None, description="Short human-readable title")
    description: Optional[str] = Field(None, description="Detailed description of the finding")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Scanner-specific evidence (raw fields, snippets, etc.)")

    # Remediation & references
    remediation: Optional[str] = Field(None, description="Recommended remediation steps")
    references: List[str] = Field(default_factory=list, description="URLs or IDs to external references (CVE, advisories, etc.)")

    # Lifecycle
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc),
                                 description="First time this finding was observed")
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc),
                                description="Last time this finding was observed/updated")
    status: FindingStatus = Field(FindingStatus.OPEN, description="Current lifecycle status")

    # Free-form metadata for future extension
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional scanner or pipeline metadata")

    @field_validator("cwe_ids")
    @classmethod
    def validate_cwe_ids(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []

        for value in values:
            if not isinstance(value, str):
                continue

            match = re.fullmatch(
                r"(?:CWE-)?(\d+)",
                value.strip(),
                re.IGNORECASE,
            )

            if match:
                normalized.append(f"CWE-{match.group(1)}")

        return normalized

    @model_validator(mode="after")
    def ensure_consistent_severity(self) -> "Finding":
        if (
            self.raw_severity
            and self.normalized_severity == SeverityLevel.UNKNOWN.value
        ):
            raw = self.raw_severity.strip().lower()

            mapping = {
                "critical": SeverityLevel.CRITICAL.value,
                "high": SeverityLevel.HIGH.value,
                "medium": SeverityLevel.MEDIUM.value,
                "low": SeverityLevel.LOW.value,
                "info": SeverityLevel.INFO.value,
                "informational": SeverityLevel.INFO.value,
            }

            value = mapping.get(raw, SeverityLevel.UNKNOWN.value)

            # Bypass pydantic validation to avoid recursion
            object.__setattr__(self, "normalized_severity", value)
            
        return self

def upgrade_legacy_finding(legacy: Dict[str, Any]) -> Finding:
    """
    Upgrade a legacy finding dict to the current canonical Finding model.

    This helper is intentionally permissive and maps common legacy field names
    to the new schema. Unknown fields are stored in `metadata`.
    """
    known_keys = {
        "finding_id",
        "asset_id",
        "scanner",
        "raw_severity",
        "normalized_severity",
        "cwe_ids",
        "cvss_v3",
        "title",
        "description",
        "evidence",
        "remediation",
        "references",
        "first_seen",
        "last_seen",
        "status",
        "metadata",
    }

    data: Dict[str, Any] = {}
    extra: Dict[str, Any] = {}

    # Basic identity & asset
    data["finding_id"] = legacy.get("finding_id", legacy.get("id", str(uuid.uuid4())))
    data["asset_id"] = legacy.get("asset_id", legacy.get("asset", legacy.get("host", "unknown")))

    # Scanner & severity
    data["scanner"] = legacy.get("scanner", legacy.get("source", "unknown"))
    data["raw_severity"] = legacy.get("raw_severity", legacy.get("severity", legacy.get("risk")))

    # Try to map legacy severity to normalized_severity if present
    raw = data["raw_severity"]
    if raw:
        raw_lower = str(raw).lower()
        mapping = {
            "critical": SeverityLevel.CRITICAL.value,
            "high": SeverityLevel.HIGH.value,
            "medium": SeverityLevel.MEDIUM.value,
            "low": SeverityLevel.LOW.value,
            "info": SeverityLevel.INFO.value,
            "informational": SeverityLevel.INFO.value,
        }
        data["normalized_severity"] = mapping.get(raw_lower, SeverityLevel.UNKNOWN.value)
    else:
        data["normalized_severity"] = SeverityLevel.UNKNOWN.value

    # CWE
    cwe_raw = legacy.get("cwe_ids", legacy.get("cwe", []))
    if isinstance(cwe_raw, str):
        cwe_raw = [cwe_raw]
    data["cwe_ids"] = cwe_raw or []

    # CVSS
    cvss = legacy.get("cvss_v3")
    if cvss and isinstance(cvss, dict):
        data["cvss_v3"] = cvss

    # Description fields
    data["title"] = legacy.get("title", legacy.get("name"))
    data["description"] = legacy.get("description", legacy.get("details"))

    # Evidence & remediation
    data["evidence"] = legacy.get("evidence", {})
    data["remediation"] = legacy.get("remediation", legacy.get("solution", legacy.get("fix")))

    # References
    refs = legacy.get("references", legacy.get("refs", []))
    if isinstance(refs, str):
        refs = [refs]
    data["references"] = refs or []

    # Lifecycle
    def _parse_dt(key: str) -> Optional[datetime]:
        val = legacy.get(key)
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        if isinstance(val, (int, float)):
            return datetime.utcfromtimestamp(val)
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except Exception:
            return None

    first = _parse_dt("first_seen") or _parse_dt("created_at") or datetime.utcnow()
    last = _parse_dt("last_seen") or _parse_dt("updated_at") or first
    data["first_seen"] = first
    data["last_seen"] = last

    # Status
    status_raw = legacy.get("status", "open")
    status_map = {
        "open": FindingStatus.OPEN,
        "triaged": FindingStatus.TRIAGED,
        "false_positive": FindingStatus.FALSE_POSITIVE,
        "remediated": FindingStatus.REMEDIATED,
        "wont_fix": FindingStatus.WONT_FIX,
    }
    data["status"] = status_map.get(str(status_raw).lower(), FindingStatus.OPEN)

    # Metadata: everything else
    for k, v in legacy.items():
        if k not in known_keys:
            extra[k] = v
    if extra:
        data["metadata"] = extra

    return Finding(**data)