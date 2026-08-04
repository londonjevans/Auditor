"""Concise Corrovera client report with source-bound inline evidence."""

from __future__ import annotations

import hashlib
import html
import json
from collections.abc import Mapping, Sequence

from mmaudit.models.schemas import (
    AuditReport,
    AuditRunStatus,
    CandidateFinding,
    CandidateReproductionResolution,
    Finding,
    FindingStatus,
    Location,
    Severity,
)
from mmaudit.models.usage import is_structurally_creditable_usage_record
from mmaudit.reporting.bundle import (
    FindingsArtifact,
    ForensicDisposition,
    ForensicFindingRecord,
    SourceExcerptEvidence,
    build_findings_artifact,
    source_symbol_is_present,
)
from mmaudit.reporting.markdown import _inline, _text
from mmaudit.reporting.status import effective_report_status
from mmaudit.repository.chunking import line_range_hash

_MAX_RENDERED_EXCERPT_LINES = 24
_MAX_RENDERED_CODE_LINE_CHARACTERS = 1_000
_MAX_EXCERPT_EVIDENCE_BYTES = 1_000_000
_EXCERPT_CONTEXT_LINES = 2

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}


def _repository_sources(report: AuditReport) -> dict[str, tuple[str, int]]:
    return {item.path: (item.sha256, item.lines) for item in report.repository.files}


def _source_tree_sha256(report: AuditReport) -> str:
    """Hash the exact sorted source identity projection used by run manifests."""

    projection = [
        {"path": item.path, "sha256": item.sha256, "size": item.size}
        for item in sorted(report.repository.files, key=lambda candidate: candidate.path)
    ]
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_location_hash(
    *,
    report: AuditReport,
    location: Location,
    source_contents: Mapping[str, str],
) -> tuple[str, str, int]:
    repository_sources = _repository_sources(report)
    source_binding = repository_sources.get(location.path)
    if source_binding is None:
        raise ValueError(f"source path is absent from the audited repository map: {location.path}")
    try:
        content = source_contents[location.path]
    except KeyError:
        raise ValueError(f"source content is unavailable for cited path: {location.path}") from None
    file_sha256 = hashlib.sha256(content.encode()).hexdigest()
    if file_sha256 != source_binding[0]:
        raise ValueError(f"source hash differs from the audited repository map: {location.path}")
    lines = content.splitlines(keepends=True)
    if (
        location.start_line < 1
        or location.end_line < location.start_line
        or location.end_line > len(lines)
    ):
        raise ValueError(f"source line range is outside the audited file: {location.path}")
    observed_range_hash = line_range_hash(content, location.start_line, location.end_line)
    if location.content_hash is not None and location.content_hash != observed_range_hash:
        raise ValueError(f"source range hash differs from the final finding: {location.path}")
    selected = "".join(lines[location.start_line - 1 : location.end_line])
    if location.symbol is not None and not source_symbol_is_present(location.symbol, selected):
        raise ValueError(f"source symbol is absent from the final cited range: {location.path}")
    return observed_range_hash, content, len(lines)


def _source_excerpt(
    report: AuditReport,
    finding: Finding,
    source_contents: Mapping[str, str],
) -> SourceExcerptEvidence:
    if not finding.location_validation.valid:
        raise ValueError(f"active finding lacks valid source-location evidence: {finding.id}")
    if not finding.locations:
        raise ValueError(f"active finding lacks a source location: {finding.id}")
    validated: dict[tuple[str, int, int, str], tuple[str, str, int]] = {}
    for location in finding.locations:
        if location.content_hash is None:
            raise ValueError(
                f"active finding location lacks an authoritative source range hash: {location.path}"
            )
        key = (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
        )
        observed = _validated_location_hash(
            report=report,
            location=location,
            source_contents=source_contents,
        )
        validated[key] = observed

    primary = min(
        finding.locations,
        key=lambda item: (item.path, item.start_line, item.end_line, item.symbol or ""),
    )
    key = (primary.path, primary.start_line, primary.end_line, primary.symbol or "")
    cited_sha256, content, total_lines = validated[key]
    excerpt_start = max(1, primary.start_line - _EXCERPT_CONTEXT_LINES)
    excerpt_end = min(total_lines, primary.end_line + _EXCERPT_CONTEXT_LINES)
    lines = content.splitlines(keepends=True)
    excerpt_content = "".join(lines[excerpt_start - 1 : excerpt_end])
    if len(excerpt_content.encode()) > _MAX_EXCERPT_EVIDENCE_BYTES:
        excerpt_start = primary.start_line
        excerpt_end = primary.end_line
        excerpt_content = "".join(lines[excerpt_start - 1 : excerpt_end])
    if len(excerpt_content.encode()) > _MAX_EXCERPT_EVIDENCE_BYTES:
        raise ValueError(f"cited source range exceeds the forensic evidence limit: {finding.id}")
    file_sha256 = _repository_sources(report)[primary.path][0]
    return SourceExcerptEvidence(
        path=primary.path,
        symbol=primary.symbol,
        file_sha256=file_sha256,
        cited_start_line=primary.start_line,
        cited_end_line=primary.end_line,
        cited_content_sha256=cited_sha256,
        excerpt_start_line=excerpt_start,
        excerpt_end_line=excerpt_end,
        content=excerpt_content,
        content_sha256=hashlib.sha256(excerpt_content.encode()).hexdigest(),
        omitted_before=excerpt_start > 1,
        omitted_after=excerpt_end < total_lines,
    )


def bind_active_finding_source_locations(
    report: AuditReport,
    source_contents: Mapping[str, str],
) -> AuditReport:
    """Bind reportable and threshold-filtered locations to the audited source snapshot.

    Candidate and scanner observations remain untouched. Only the canonical final
    finding projections receive host-observed per-range hashes.
    """

    report = AuditReport.model_validate(report.model_dump(mode="python"))

    def bind(findings: Sequence[Finding], *, label: str) -> list[Finding]:
        bound: list[Finding] = []
        for finding in findings:
            if not finding.location_validation.valid:
                raise ValueError(
                    f"{label} finding lacks valid source-location evidence: {finding.id}"
                )
            if not finding.locations:
                raise ValueError(f"{label} finding lacks a source location: {finding.id}")
            bound_locations: list[Location] = []
            for location in finding.locations:
                observed_range_hash, _content, _total_lines = _validated_location_hash(
                    report=report,
                    location=location,
                    source_contents=source_contents,
                )
                bound_locations.append(
                    location.model_copy(update={"content_hash": observed_range_hash})
                )
            bound.append(finding.model_copy(update={"locations": bound_locations}))
        return bound

    bound_findings = bind(report.findings, label="active")
    bound_filtered_findings = bind(
        report.filtered_findings,
        label="reporting-filtered",
    )
    return AuditReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "findings": [finding.model_dump(mode="python") for finding in bound_findings],
            "filtered_findings": [
                finding.model_dump(mode="python") for finding in bound_filtered_findings
            ],
        }
    )


def build_client_source_excerpts(
    report: AuditReport,
    source_contents: Mapping[str, str],
) -> dict[str, SourceExcerptEvidence]:
    """Build one deterministic excerpt for every valid retained non-rejected finding."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    excerpts: dict[str, SourceExcerptEvidence] = {}
    for finding in [*report.findings, *report.filtered_findings]:
        excerpts[finding.id] = _source_excerpt(report, finding, source_contents)
    return excerpts


def _code_line(value: str) -> str:
    retained = "".join(
        character for character in value if character == "\t" or ord(character) >= 32
    )
    if len(retained) > _MAX_RENDERED_CODE_LINE_CHARACTERS:
        retained = retained[:_MAX_RENDERED_CODE_LINE_CHARACTERS] + "… [line truncated]"
    return html.escape(retained, quote=False)


def _render_excerpt(excerpt: SourceExcerptEvidence) -> list[str]:
    all_lines = excerpt.content.splitlines()
    selected_start = 0
    if len(all_lines) > _MAX_RENDERED_EXCERPT_LINES:
        cited_start = excerpt.cited_start_line - excerpt.excerpt_start_line
        cited_end = excerpt.cited_end_line - excerpt.excerpt_start_line
        symbol_index = next(
            (
                index
                for index in range(cited_start, cited_end + 1)
                if excerpt.symbol is not None
                and source_symbol_is_present(excerpt.symbol, all_lines[index])
            ),
            cited_start,
        )
        selected_start = max(
            0,
            min(
                symbol_index - _EXCERPT_CONTEXT_LINES,
                len(all_lines) - _MAX_RENDERED_EXCERPT_LINES,
            ),
        )
    selected_end = min(len(all_lines), selected_start + _MAX_RENDERED_EXCERPT_LINES)
    lines = all_lines[selected_start:selected_end]
    rendered = [
        f"    {line_number:04d} | {_code_line(line)}"
        for line_number, line in enumerate(
            lines,
            excerpt.excerpt_start_line + selected_start,
        )
    ]
    omitted_before = selected_start
    omitted_after = len(all_lines) - selected_end
    if omitted_before:
        rendered.insert(0, f"    … {omitted_before} bound source line(s) omitted before …")
    if omitted_after:
        rendered.append(f"    … {omitted_after} bound source line(s) omitted after …")
    return [
        "Source excerpt — "
        + _inline(f"{excerpt.path}:{excerpt.cited_start_line}-{excerpt.cited_end_line}"),
        "",
        *rendered,
        "",
        (
            "The displayed excerpt is a bounded window; the cited range hash covers the full "
            "retained range."
            if omitted_before or omitted_after
            else "The displayed excerpt contains the complete cited range plus bounded context."
        ),
        "",
        "Cited range SHA-256: " + _inline(excerpt.cited_content_sha256),
        "",
    ]


def _record_label(record: ForensicFindingRecord) -> str:
    if record.disposition in {
        ForensicDisposition.DISPUTED,
        ForensicDisposition.INCONCLUSIVE,
    }:
        return record.disposition.value
    return {
        FindingStatus.CONFIRMED: "CONFIRMED",
        FindingStatus.STRONGLY_SUPPORTED: "STRONGLY SUPPORTED",
        FindingStatus.HIGH_CONFIDENCE: "HIGH CONFIDENCE",
        FindingStatus.PLAUSIBLE: "SUPPORTED WITH MATERIAL ASSUMPTIONS",
        FindingStatus.NEEDS_REVIEW: "INCONCLUSIVE",
        FindingStatus.INFORMATIONAL: "INFORMATIONAL",
        FindingStatus.INSUFFICIENT_CONTEXT: "INCONCLUSIVE",
        FindingStatus.UNSUPPORTED: "INCONCLUSIVE",
        FindingStatus.REJECTED: "REJECTED",
    }[record.finding.status]


def _affected_component(finding: Finding) -> str:
    location = min(
        finding.locations,
        key=lambda item: (item.path, item.start_line, item.end_line, item.symbol or ""),
    )
    return location.symbol or location.path


def _host_derived_safety_property(finding: Finding) -> str:
    preconditions = "; ".join(finding.preconditions)
    return (
        f"Host-derived safety property: under the recorded preconditions ({preconditions}), "
        f'the unsafe condition "{finding.title}" must not occur.'
    )


def _violated_property(finding: Finding) -> tuple[str, str]:
    host_statement = _host_derived_safety_property(finding)
    if finding.execution_provenance:
        identifiers = sorted({item.invariant_id for item in finding.execution_provenance})
        return (
            f"{host_statement} Bound deterministic invariant ID(s): {', '.join(identifiers)}.",
            "bound deterministic invariant identity with host-derived explanatory wording",
        )
    evidence_identifiers = sorted(
        {
            item.rule_id
            for item in finding.evidence
            if item.type in {"execution", "formal", "invariant"} and item.rule_id is not None
        }
    )
    if evidence_identifiers:
        return (
            f"{host_statement} Bound deterministic/formal property ID(s): "
            f"{', '.join(evidence_identifiers)}.",
            "bound deterministic/formal evidence identity with host-derived explanatory wording",
        )
    return (
        host_statement,
        "host-derived from the unsafe-condition title and recorded preconditions; "
        "not independent deterministic evidence",
    )


def _detail_items(label: str, items: Sequence[str]) -> list[str]:
    if not items:
        return []
    return [f"  - {label}:", *[f"    - {_text(item)}" for item in items]]


def _finding_detail(record: ForensicFindingRecord) -> list[str]:
    finding = record.finding
    excerpt = record.source_excerpt
    if excerpt is None:
        raise ValueError(f"client finding lacks a validated source excerpt: {finding.id}")
    property_statement, property_basis = _violated_property(finding)
    lines = [
        f"### {_text(finding.title)} ({_inline(finding.id)})",
        "",
        f"> **{_record_label(record)}** · Severity **{finding.severity.value.upper()}** · "
        f"Confidence **{finding.confidence:.2f}** · Evidence tier "
        f"**{_text(finding.evidence_strength.value)}**",
        "",
        f"Affected component: **{_text(_affected_component(finding))}**",
        "",
        "Exact line range: "
        + _inline(f"{excerpt.path}:{excerpt.cited_start_line}-{excerpt.cited_end_line}"),
        "",
        f"Violated property: {_text(property_statement)}",
        "",
        f"Property basis: {_text(property_basis)}.",
        "",
        *_render_excerpt(excerpt),
        f"Impact: {_text(finding.impact)}",
        "",
        "Preconditions:",
        "",
        *[f"- {_text(item)}" for item in finding.preconditions],
        "",
        "Reachable path:",
        "",
        *[f"{index}. {_text(item)}" for index, item in enumerate(finding.attack_path, start=1)],
        "",
        "Supporting evidence:",
        "",
        *[
            f"- {_inline(item.type)} {_text(item.source)}: {_text(item.description)}"
            for item in finding.evidence
        ],
        "",
        "Dispute and falsifier outcome:",
        "",
    ]
    if record.cross_examination_decisions:
        for cross_decision in record.cross_examination_decisions:
            lines.append(
                f"- Cross-exam reviewer {cross_decision.reviewer_index}: "
                f"**{cross_decision.verdict.value.upper()}** — "
                f"{_text(cross_decision.rationale)}"
            )
            lines.extend(_detail_items("Contradictions", cross_decision.contradictions))
            lines.extend(_detail_items("Missing evidence", cross_decision.missing_evidence))
    if record.verification_decisions:
        for verifier_decision in record.verification_decisions:
            lines.extend(
                [
                    f"- Verifier: **{verifier_decision.verdict.value.upper()}** — "
                    f"{_text(verifier_decision.rationale)}",
                    f"  - Source-to-sink: {_text(verifier_decision.source_to_sink)}",
                    f"  - Reachability: {_text(verifier_decision.reachability)}",
                    f"  - Authentication: {_text(verifier_decision.authentication)}",
                    "  - Privilege requirements: "
                    + _text(verifier_decision.privilege_requirements),
                    f"  - Confidence: {verifier_decision.confidence:.2f}",
                    "  - Safe verification: "
                    + _text(verifier_decision.safe_verification_test.description),
                ]
            )
            lines.extend(
                _detail_items(
                    "Environmental assumptions",
                    verifier_decision.environmental_assumptions,
                )
            )
            lines.extend(
                _detail_items("Guards and controls", verifier_decision.guards_and_controls)
            )
            lines.extend(
                _detail_items(
                    "False-positive conditions",
                    verifier_decision.false_positive_conditions,
                )
            )
    if record.falsification_decisions:
        for falsifier_decision in record.falsification_decisions:
            lines.extend(
                [
                    f"- {_inline(falsifier_decision.test_name)}: "
                    f"**{falsifier_decision.verdict.value.upper()}** — "
                    f"{_text(falsifier_decision.rationale)}",
                    "  - Test matches claim: " + str(falsifier_decision.test_matches_claim).lower(),
                    "  - Assumptions validated: "
                    + str(falsifier_decision.assumptions_validated).lower(),
                ]
            )
            lines.extend(_detail_items("Contradictions", falsifier_decision.contradictions))
    if (
        not record.cross_examination_decisions
        and not record.verification_decisions
        and not record.falsification_decisions
    ):
        lines.append("- No evidence-backed dispute or falsifier decision was recorded.")
    if record.disposition in {
        ForensicDisposition.DISPUTED,
        ForensicDisposition.INCONCLUSIVE,
    }:
        lines.extend(
            [
                "",
                "This matter is not established as a confirmed vulnerability; "
                "the retained evidence requires human resolution.",
            ]
        )
    if record.reproduction_resolutions:
        lines.extend(["", "Reproduction resolution:", ""])
        lines.extend(
            f"- **{resolution.kind.value.upper()}** — {_text(resolution.detail)}"
            for resolution in record.reproduction_resolutions
        )
    if record.reproductions:
        lines.extend(["", "Reproduction execution:", ""])
        lines.extend(
            f"- {_inline(result.test_name)}: **{result.state.value.upper()}** · "
            f"evidence {_inline(result.execution_evidence.value)} · attempts {result.attempts}"
            for result in record.reproductions
        )
    lines.extend(
        [
            "",
            f"Remediation: {_text(finding.recommendation)}",
            "",
            "Safe verification test: "
            + _text(
                finding.verification_test.description
                if finding.verification_test is not None
                else "No safe verification test was retained."
            ),
            "",
            "Residual uncertainty:",
            "",
            *[f"- {_text(item)}" for item in finding.false_positive_conditions],
        ]
    )
    if finding.disagreement:
        lines.append(f"- {_text(finding.disagreement)}")
    lines.append("")
    return lines


def _executive_summary(report: AuditReport, status: AuditRunStatus) -> str:
    if not report.findings and status is not AuditRunStatus.COMPLETE:
        return (
            "No reportable findings were identified by the analyses that completed. "
            "This run is incomplete and does not support a conclusion about repository safety."
        )
    if not report.findings:
        return (
            "No reportable findings were identified within the analyses that completed. "
            "This does not prove that the repository is secure."
        )
    highest = max(report.findings, key=lambda item: _SEVERITY_ORDER[item.severity]).severity
    return (
        f"The audit retained {len(report.findings)} reportable finding(s); the highest severity "
        f"is {highest.value.upper()}. Prioritize deterministic remediation and local regression "
        "validation before relying on affected components."
    )


def _completed_analysis_summary(report: AuditReport) -> list[str]:
    # Imported lazily because the assurance module imports the manifest layer,
    # which in turn needs this deterministic report regenerator.
    from mmaudit.orchestration.assurance import (
        is_qualifying_real_scanner_run,
        is_structurally_qualifying_real_formal_run,
        is_structurally_qualifying_real_invariant_execution,
        is_structurally_qualifying_real_reproduction,
    )

    real_scanners = sorted(
        run.scanner for run in report.scanner_runs if is_qualifying_real_scanner_run(run)
    )
    real_model_requests = [
        item
        for item in report.usage
        if is_structurally_creditable_usage_record(item, require_real=True)
    ]
    real_invariants = [
        item
        for item in report.invariant_executions
        if is_structurally_qualifying_real_invariant_execution(item)
    ]
    real_formal = [
        item for item in report.formal_runs if is_structurally_qualifying_real_formal_run(item)
    ]
    real_reproductions = [
        item for item in report.reproductions if is_structurally_qualifying_real_reproduction(item)
    ]
    retained_total = (
        len(report.scanner_runs)
        + len(report.usage)
        + len(report.invariant_executions)
        + len(report.formal_runs)
        + len(report.reproductions)
    )
    credited_total = (
        len(real_scanners)
        + len(real_model_requests)
        + len(real_invariants)
        + len(real_formal)
        + len(real_reproductions)
    )
    return [
        "- Qualifying REAL static analyzers: "
        + _text(", ".join(real_scanners) if real_scanners else "none"),
        f"- Creditable REAL completed model requests: {len(real_model_requests)}",
        f"- REAL terminal invariant records: {len(real_invariants)} "
        f"of {len(report.invariant_executions)} retained",
        f"- REAL successful formal-engine records: {len(real_formal)} "
        f"of {len(report.formal_runs)} retained",
        f"- REAL terminal reproduction records: {len(real_reproductions)} "
        f"of {len(report.reproductions)} retained",
        "- Non-REAL, unavailable, failed, or nonterminal records retained for custody only: "
        f"{retained_total - credited_total}",
    ]


def _render_client_markdown_from_artifact(
    report: AuditReport,
    artifact: FindingsArtifact,
) -> str:
    report = AuditReport.model_validate(report.model_dump(mode="python"))
    artifact = FindingsArtifact.model_validate(artifact.model_dump(mode="python"))
    projection = effective_report_status(report)
    status = projection.run_status
    active_records = artifact.records[: len(report.findings)]
    ordered_records = sorted(
        active_records,
        key=lambda item: (-_SEVERITY_ORDER[item.finding.severity], item.finding.id),
    )
    lines = [
        "# Corrovera Security Assurance Report",
        "",
        "*Independent minds. Corroborated truth.*",
        "",
        "Prepared by Corrovera Security · corrovera.com",
        "",
        "Generated by `mmaudit` · corrovera.ai",
        "",
        f"> **RUN STATUS: {status.value}**",
        "",
        f"Quality status: **{projection.quality_status.value}**.",
        "",
        _executive_summary(report, status),
        "",
        "## Executive risk narrative",
        "",
        f"This evidence-derived {_text(report.audit_profile.value)} audit reached "
        f"**{status.value}** with {len(report.findings)} reportable and "
        f"{len(report.rejected_findings)} rejected finding record(s).",
        "",
    ]
    if status is not AuditRunStatus.COMPLETE:
        lines.extend(
            [
                "> **PROMINENT LIMITATION:** the run did not complete every required analysis. "
                "Do not interpret missing findings as evidence of safety.",
                "",
                *[f"- {_text(reason)}" for reason in projection.limitations],
                "",
            ]
        )
    lines.extend(
        [
            "## Scope and source identity",
            "",
            f"- Repository: {_inline(report.repository.root_name)}",
            f"- Source commit: {_inline(report.repository.git_commit or 'not available')}",
            f"- Source-tree SHA-256: {_inline(_source_tree_sha256(report))}",
            f"- Run ID: {_inline(report.run_id)}",
            f"- Files mapped: {len(report.repository.files)}",
            f"- Languages: {_text(', '.join(sorted(report.repository.languages)) or 'none')}",
            "",
            "## Methodology summary",
            "",
            "mmaudit combines deterministic source identity and location validation with bounded "
            "static, dynamic, formal, and independent model evidence. Model agreement cannot by "
            "itself create a confirmed finding, and the report preserves material dissent.",
            "",
            "## Analysis actually completed",
            "",
            *_completed_analysis_summary(report),
            "",
            "## Finding summary",
            "",
        ]
    )
    if ordered_records:
        lines.extend(
            [
                "| ID | Severity | Disposition | Affected component |",
                "| --- | --- | --- | --- |",
                *[
                    f"| {_inline(record.finding.id)} | "
                    f"{record.finding.severity.value.upper()} | {_record_label(record)} | "
                    f"{_text(_affected_component(record.finding))} |"
                    for record in ordered_records
                ],
                "",
            ]
        )
    else:
        lines.extend(["No reportable findings survived the configured evidence gates.", ""])
    lines.extend(["## Priority remediation roadmap", ""])
    if ordered_records:
        lines.extend(
            f"{index}. **{record.finding.severity.value.upper()} — "
            f"{_text(record.finding.title)}:** {_text(record.finding.recommendation)}"
            for index, record in enumerate(ordered_records, start=1)
        )
    else:
        lines.append(
            "1. Resolve any incomplete analysis prerequisites and repeat the audit after material changes."
        )
    lines.extend(["", "## Detailed findings", ""])
    for record in ordered_records:
        lines.extend(_finding_detail(record))
    if report.rejected_findings:
        lines.extend(
            [
                "Rejected proposals are excluded from reportable totals and SARIF. Their complete "
                "evidence and dissent remain in `findings.json` and `forensic-report.md`.",
                "",
            ]
        )
    lines.extend(
        [
            "## Residual risk and limitations",
            "",
            "- This audit is bounded evidence, not proof that the repository is secure.",
            "- Runtime configuration, integrations, unavailable engines, and omitted source can "
            "materially change risk.",
            "- Disputed and inconclusive matters require maintainers to resolve the recorded "
            "assumptions and controls.",
            *[f"- {_text(reason)}" for reason in projection.limitations],
            "",
            "## Conclusion",
            "",
            (
                "The completed scope produced the findings and limitations above. Remediate in "
                "severity order and rerun the bound regression suite; absence of further findings "
                "must not be represented as proof of safety."
                if status is AuditRunStatus.COMPLETE
                else "This run is incomplete. Resolve the prominent limitations and repeat the "
                "audit before drawing a repository-wide security conclusion."
            ),
            "",
            "## Forensic bundle index",
            "",
            "The run evidence manifest hash-binds every emitted leaf artifact. It intentionally "
            "does not hash itself recursively.",
            "",
            "- `client-report.md`",
            "- `forensic-report.md`",
            "- `findings.json`",
            "- `audit-results.sarif`",
            "- `coverage.json`",
            "- `model-execution.json`",
            "- `run-evidence-manifest.json`",
            "",
        ]
    )
    return "\n".join(lines)


def render_client_markdown_from_artifact(
    report: AuditReport,
    artifact: FindingsArtifact,
) -> str:
    """Regenerate the client report from the exact typed forensic finding projection."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    artifact = FindingsArtifact.model_validate(artifact.model_dump(mode="python"))
    excerpts = {
        record.finding_id: record.source_excerpt
        for record in artifact.records
        if record.source_excerpt is not None
    }
    expected = build_findings_artifact(
        report,
        candidates=artifact.candidate_findings,
        reproduction_resolutions=artifact.reproduction_resolutions,
        source_excerpts=excerpts,
    )
    if artifact != expected:
        raise ValueError("client report findings artifact differs from the bound audit report")
    return _render_client_markdown_from_artifact(report, artifact)


def render_client_markdown(
    report: AuditReport,
    source_contents: Mapping[str, str],
    *,
    candidates: Sequence[CandidateFinding] = (),
    reproduction_resolutions: Sequence[CandidateReproductionResolution] = (),
) -> str:
    """Render a concise, deterministic client report from validated runtime evidence."""

    report = AuditReport.model_validate(report.model_dump(mode="python"))
    excerpts = build_client_source_excerpts(report, source_contents)
    artifact = build_findings_artifact(
        report,
        candidates=candidates,
        reproduction_resolutions=reproduction_resolutions,
        source_excerpts=excerpts,
    )
    return render_client_markdown_from_artifact(report, artifact)
