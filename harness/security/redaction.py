from __future__ import annotations

from dataclasses import dataclass
import re

from harness.models.finding import Finding


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redactions: list[str]
    injection_flags: list[str]


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "password_assignment",
        re.compile(
            r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]+"
        ),
    ),
)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|override)\s+"
            r"(all\s+)?(previous|prior|above|system)\s+instructions\b"
        ),
    ),
    (
        "role_impersonation",
        re.compile(
            r"(?i)\b(system message|developer message|assistant message)\s*:"
        ),
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"(?i)\b(reveal|print|send|leak|exfiltrate)\b.{0,60}"
            r"\b(api key|token|password|secret|credential)\b"
        ),
    ),
    (
        "tool_execution_request",
        re.compile(
            r"(?i)\b(run|execute|invoke)\b.{0,40}"
            r"\b(shell|bash|powershell|command|exploit)\b"
        ),
    ),
)


def redact_text(text: str) -> RedactionResult:
    redactions: list[str] = []
    injection_flags: list[str] = []
    result = text

    for name, pattern in SECRET_PATTERNS:
        if pattern.search(result):
            redactions.append(name)
            result = pattern.sub(f"[REDACTED:{name}]", result)

    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(result):
            injection_flags.append(name)

    return RedactionResult(
        text=result,
        redactions=sorted(set(redactions)),
        injection_flags=sorted(set(injection_flags)),
    )


def redact_finding(finding: Finding) -> tuple[Finding, list[str], list[str]]:
    redactions: set[str] = set()
    injection_flags: set[str] = set()

    if finding.description:
        result = redact_text(finding.description)
        finding.description = result.text
        redactions.update(result.redactions)
        injection_flags.update(result.injection_flags)

    for evidence in finding.evidence:
        if evidence.raw_text:
            result = redact_text(evidence.raw_text)
            evidence.raw_text = result.text
            redactions.update(result.redactions)
            injection_flags.update(result.injection_flags)

        if evidence.structured_data:
            for key, value in list(evidence.structured_data.items()):
                if isinstance(value, str):
                    result = redact_text(value)
                    evidence.structured_data[key] = result.text
                    redactions.update(result.redactions)
                    injection_flags.update(result.injection_flags)

    return finding, sorted(redactions), sorted(injection_flags)