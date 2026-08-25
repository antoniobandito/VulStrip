from __future__ import annotations

from dataclasses import dataclass

from harness.models.finding import Finding, ModelAssessment


@dataclass(frozen=True)
class AssessmentValidation:
    valid: bool
    warnings: list[str]


def validate_assessment(
    finding: Finding,
    assessment: ModelAssessment,
) -> AssessmentValidation:
    warnings: list[str] = []

    evidence_ids = {
        evidence.evidence_id
        for evidence in finding.evidence
    }

    unknown_citations = sorted(
        set(assessment.cited_evidence) - evidence_ids
    )

    if unknown_citations:
        warnings.append(
            "Assessment cites unknown evidence IDs: "
            + ", ".join(unknown_citations)
        )

    if not assessment.cited_evidence:
        warnings.append(
            "Assessment contains no evidence citations."
        )

    if assessment.finding_id != finding.finding_id:
        warnings.append(
            "Assessment finding_id does not match the supplied finding."
        )

    if assessment.exploitability == "confirmed":
        warnings.append(
            "Exploitability is marked confirmed; passive evidence cannot "
            "establish successful exploitation."
        )

    return AssessmentValidation(
        valid=not warnings,
        warnings=warnings,
    )