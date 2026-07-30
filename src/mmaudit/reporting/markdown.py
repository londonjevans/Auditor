"""Human-readable report rendering with untrusted text neutralization."""

from __future__ import annotations

import html
import re
from collections import Counter

from mmaudit.constants import ALL_MODEL_ROLES
from mmaudit.models.schemas import (
    AttackerCapabilityPolicy,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    EconomicMetrics,
    ExecutionOriginDispositionKind,
    Finding,
    FindingStatus,
    ReproductionIntegrityStatus,
    ReproductionState,
    ScannerStatus,
    Severity,
)
from mmaudit.solidity.formal import compare_dynamic_engine_outcomes

_MAX_EXECUTION_ORIGIN_DISPOSITION_ROWS = 20
_MAX_AUDITED_SUITE_COVERAGE_GAP_ROWS = 20


def _clean(value: str) -> str:
    value = "".join(character for character in value if character in "\n\t" or ord(character) >= 32)
    value = re.sub(r"[\r\n]+", " ", value)
    return html.escape(value, quote=False)


def _text(value: str) -> str:
    value = _clean(value).replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "(", ")", "!", "|"):
        value = value.replace(character, f"\\{character}")
    return value


def _inline(value: str) -> str:
    return "`" + _clean(value).replace("`", "'").replace("|", "\\|") + "`"


def _economic_metrics_summary(metrics: EconomicMetrics | None) -> str:
    if metrics is None:
        return ""
    parts: list[str] = []
    value_unit = "base units" if metrics.financial_settlement is not None else "wei"
    if metrics.required_initial_capital is not None:
        parts.append(f"initial capital {metrics.required_initial_capital} {value_unit}")
    if metrics.borrowed_capital is not None:
        parts.append(f"borrowed {metrics.borrowed_capital} {value_unit}")
    if metrics.maximum_victim_loss is not None:
        parts.append(f"victim at risk {metrics.maximum_victim_loss} {value_unit}")
    if metrics.protocol_insolvency is not None:
        parts.append(f"protocol insolvency {metrics.protocol_insolvency} {value_unit}")
    if metrics.net_profit_or_loss is not None:
        parts.append(f"net {metrics.net_profit_or_loss} {value_unit}")
    if metrics.financial_settlement is not None:
        settlement = metrics.financial_settlement
        parts.extend(
            (
                f"repaid {settlement.repaid_assets} base units",
                f"fees {settlement.fees_paid} base units",
                f"slippage {settlement.slippage_loss} base units",
                f"ending {settlement.ending_assets} base units",
            )
        )
    if metrics.lending_boundary is not None:
        lending_boundary = metrics.lending_boundary
        parts.extend(
            (
                (f"debt {lending_boundary.debt_before}->{lending_boundary.debt_after} base units"),
                (
                    "collateral "
                    f"{lending_boundary.collateral_before}->"
                    f"{lending_boundary.collateral_after} base units"
                ),
                f"collateral seized {lending_boundary.collateral_seized} base units",
                f"bad debt {lending_boundary.bad_debt_after} base units",
            )
        )
    if metrics.share_price_boundary is not None:
        share_boundary = metrics.share_price_boundary
        parts.extend(
            (
                f"legitimate yield {share_boundary.legitimate_yield} base units",
                (
                    "share rate "
                    f"{share_boundary.expected_rate_after_yield}->"
                    f"{share_boundary.observed_rate_after} per {share_boundary.rate_scale}"
                ),
                f"shares redeemed {share_boundary.shares_redeemed}",
                f"assets redeemed {share_boundary.assets_redeemed} base units",
                f"excess assets {share_boundary.excess_assets} base units",
            )
        )
    if metrics.repeatable is not None:
        parts.append(f"repeatable={metrics.repeatable}")
    if metrics.resource_threshold is not None:
        parts.append(f"resource threshold {metrics.resource_threshold}")
    if metrics.bounded_actions is not None:
        parts.append(f"bounded actions {metrics.bounded_actions}")
    return "; ".join(parts)


def _capability_summary(policy: AttackerCapabilityPolicy | None) -> str:
    if policy is None:
        return ""
    parts: list[str] = []
    if policy.governance_rights:
        parts.append("governance_rights")
    if policy.max_time_shift_seconds:
        parts.append(f"time_shift<={policy.max_time_shift_seconds}s")
    if policy.cross_chain_messages.value != "none":
        parts.append(f"cross_chain={policy.cross_chain_messages.value}")
    if policy.attacker_controlled_contracts:
        parts.append("controlled_contracts=" + ",".join(policy.attacker_controlled_contracts))
    return "; ".join(parts)


def _status_qualification(status: FindingStatus) -> str:
    return {
        FindingStatus.CONFIRMED: "**Confirmed finding**",
        FindingStatus.STRONGLY_SUPPORTED: "**Strongly supported finding**",
        FindingStatus.HIGH_CONFIDENCE: "**High-confidence finding**",
        FindingStatus.PLAUSIBLE: "**Plausible finding - material assumptions remain**",
        FindingStatus.NEEDS_REVIEW: "**Needs human review — not established as fact**",
        FindingStatus.INFORMATIONAL: "**Informational security observation**",
        FindingStatus.INSUFFICIENT_CONTEXT: "**Insufficient context**",
        FindingStatus.UNSUPPORTED: "**Unsupported by the current engine**",
        FindingStatus.REJECTED: "**Rejected finding**",
    }[status]


_ORIGIN_LABELS = {
    "model_review": "Independent model review",
    "deterministic_execution": "Deterministic execution",
    "static_analyzer": "Static analyzer",
}


def _origin_label(finding: Finding) -> str:
    return _ORIGIN_LABELS[finding.origin_kind.value]


def _execution_origin_lines(finding: Finding) -> list[str]:
    if finding.origin_kind.value != "deterministic_execution":
        return []
    lines = [
        "This finding originated from deterministic execution and is not model-attributed.",
        "",
    ]
    if finding.execution_provenance:
        lines.extend(
            [
                "Execution provenance: "
                + "; ".join(
                    f"{_inline(provenance.producer)} / "
                    f"SHA-256 {_inline(provenance.provenance_sha256[:12] + '…')}"
                    for provenance in finding.execution_provenance
                ),
                "",
            ]
        )
    if finding.model_votes:
        lines.extend(
            [
                "Model contribution is limited to impact, exploitability, and remediation "
                "analysis; it cannot alter the execution-bound identity or location.",
                "",
            ]
        )
    return lines


def _execution_origin_disposition_lines(report: AuditReport) -> list[str]:
    """Render a bounded host-origin decision summary without inventing findings."""

    dispositions = sorted(
        report.execution_origin_dispositions,
        key=lambda item: item.execution_index,
    )
    if not dispositions:
        return []
    originated = sum(
        item.kind is ExecutionOriginDispositionKind.ORIGINATED for item in dispositions
    )
    rejected = len(dispositions) - originated
    lines = [
        "## Deterministic execution-origin dispositions",
        "",
        "Every runtime counterexample receives a host-authored origin decision before "
        "consensus. `originated` means a source-bound candidate was created; it does not "
        "imply final confirmation. `rejected` means the runtime record did not receive "
        "candidate authority, is not a finding, and is omitted from SARIF.",
        "",
        f"- Runtime counterexamples dispositioned: {len(dispositions)}",
        f"- Originated candidates: {originated}",
        f"- Rejected before candidate creation: {rejected}",
        "",
        "| Execution index | Invariant | Harness | Disposition | Candidate or rejection evidence |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for disposition in dispositions[:_MAX_EXECUTION_ORIGIN_DISPOSITION_ROWS]:
        if disposition.kind is ExecutionOriginDispositionKind.ORIGINATED:
            provenance = disposition.execution_provenance
            evidence = (
                f"candidate {_inline(disposition.candidate_id or 'unavailable')}; "
                "provenance SHA-256 "
                f"{_inline(provenance.provenance_sha256[:12] + '…' if provenance else 'unavailable')}"
            )
        else:
            category = (
                disposition.rejection_category.value
                if disposition.rejection_category is not None
                else "unavailable"
            )
            evidence = (
                f"category {_inline(category)} — "
                f"{_text(disposition.rejection_detail or 'rejection detail unavailable')}"
            )
        lines.append(
            f"| {disposition.execution_index} | {_inline(disposition.invariant_id)} | "
            f"{_text(disposition.harness_name)} | {_inline(disposition.kind.value)} | "
            f"{evidence} |"
        )
    omitted = len(dispositions) - _MAX_EXECUTION_ORIGIN_DISPOSITION_ROWS
    if omitted > 0:
        lines.extend(
            [
                "",
                f"{omitted} additional disposition record(s) remain in the JSON forensic "
                "artifacts.",
            ]
        )
    lines.append("")
    return lines


def _audited_suite_coverage_gap_lines(coverage: dict[str, object]) -> list[str]:
    """Render bounded source-bound test-quality gaps as non-finding evidence."""

    def count(field: str) -> int:
        value = coverage.get(field, 0)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    raw_gaps = coverage.get("gaps", [])
    gaps = (
        sorted(
            (gap for gap in raw_gaps if isinstance(gap, dict)),
            key=lambda gap: str(gap.get("gap_id", "")),
        )
        if isinstance(raw_gaps, list)
        else []
    )
    lines = [
        "### Audited-suite coverage gaps — not vulnerability findings",
        "",
        "These rows identify audited-source test-quality gaps only. They are not "
        "vulnerability findings and never populate finding or SARIF results.",
        "",
        f"- Repository tests selected: {count('repository_tests_selected')}",
        f"- Repository tests executed: {count('repository_tests_executed')}",
        f"- Repository tests failed: {count('repository_tests_failed')}",
        "- Audited-source classification complete: "
        f"{coverage.get('source_classification_complete') is True}",
        "- Critical-surface classification complete: "
        f"{coverage.get('critical_classification_complete') is True}",
        f"- Exact critical-surface coverage gaps: {len(gaps)}",
        "",
    ]
    raw_limitations = coverage.get("limitations", [])
    limitations = (
        [str(limitation) for limitation in raw_limitations]
        if isinstance(raw_limitations, list)
        else []
    )
    if limitations:
        lines.extend(
            [
                "Audited-suite classification limitations:",
                "",
                *[f"- {_text(limitation)}" for limitation in limitations[:20]],
                "",
            ]
        )
    if not gaps:
        lines.extend(["No audited-suite critical-surface coverage gaps were recorded.", ""])
        return lines

    lines.extend(
        [
            "| Gap ID | Kind | Entity | Exact location | Symbol | Source SHA-256 | "
            "Assertion state | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for gap in gaps[:_MAX_AUDITED_SUITE_COVERAGE_GAP_ROWS]:
        location = gap.get("location", {})
        if not isinstance(location, dict):
            location = {}
        path = str(location.get("path", "unknown"))
        start_line = int(location.get("start_line", 0))
        end_line = int(location.get("end_line", start_line))
        symbol = str(location.get("symbol") or "not available")
        source_hash = str(location.get("content_hash") or "not available")
        lines.append(
            f"| {_inline(str(gap.get('gap_id', 'unknown')))} | "
            f"{_inline(str(gap.get('kind', 'unknown')))} | "
            f"{_inline(str(gap.get('entity_id', 'unknown')))} | "
            f"{_inline(path)}:{start_line}-{end_line} | "
            f"{_inline(symbol)} | {_inline(source_hash)} | "
            f"{_inline(str(gap.get('assertion_status', 'unknown')))} | "
            f"{_text(str(gap.get('detail', 'no detail')))} |"
        )
    omitted = len(gaps) - _MAX_AUDITED_SUITE_COVERAGE_GAP_ROWS
    if omitted > 0:
        lines.extend(
            [
                "",
                f"{omitted} additional audited-suite coverage gap record(s) remain in the "
                "typed JSON report.",
            ]
        )
    lines.append("")
    return lines


def _effective_run_status(report: AuditReport) -> AuditRunStatus:
    if report.run_status is not None:
        return report.run_status
    if report.quality_status in {
        AuditQualityStatus.FAILED,
        AuditQualityStatus.ENVIRONMENT_UNSAFE,
        AuditQualityStatus.TARGET_UNSUPPORTED,
    }:
        return AuditRunStatus.FAILED
    if not report.completed or report.quality_status is AuditQualityStatus.INCOMPLETE:
        return AuditRunStatus.INCOMPLETE
    if report.quality_status is AuditQualityStatus.COMPLETED_WITH_LIMITATIONS:
        return AuditRunStatus.DEGRADED
    return AuditRunStatus.COMPLETE


def _finding(finding: Finding, report: AuditReport) -> list[str]:
    qualification = _status_qualification(finding.status)
    lines = [
        f"### {_text(finding.title)} ({_inline(finding.id)})",
        "",
        f"{qualification} · Severity: **{finding.severity.value}** · "
        f"Confidence: **{finding.confidence:.2f}**",
        "",
        f"Discovery origin: **{_origin_label(finding)}**",
        "",
        f"Evidence strength: {_inline(finding.evidence_strength.value)} · "
        f"Reproduction: {_inline(finding.reproduction_state.value)}",
        "",
    ]
    lines.extend(_execution_origin_lines(finding))
    lines.extend(
        [
            _text(finding.summary),
            "",
            f"Impact: {_text(finding.impact)}",
            "",
            "Locations:",
            "",
        ]
    )
    lines.extend(
        f"- {_inline(location.path)}:{location.start_line}-{location.end_line}"
        + (f" ({_inline(location.symbol)})" if location.symbol else "")
        for location in finding.locations
    )
    lines.extend(["", "Attack path:", ""])
    lines.extend(f"{index}. {_text(step)}" for index, step in enumerate(finding.attack_path, 1))
    lines.extend(["", "Preconditions:", ""])
    lines.extend(f"- {_text(value)}" for value in finding.preconditions)
    if finding.source is not None:
        lines.extend(
            [
                "",
                f"Source: {_text(finding.source.description)} "
                f"({_inline(finding.source.path)}:{finding.source.line})",
            ]
        )
    if finding.sink is not None:
        lines.append(
            f"Sink: {_text(finding.sink.description)} "
            f"({_inline(finding.sink.path)}:{finding.sink.line})"
        )
    lines.extend(["", "Evidence:", ""])
    lines.extend(
        f"- {_inline(evidence.type)} {_text(evidence.source)}"
        + (f" / {_inline(evidence.rule_id)}" if evidence.rule_id else "")
        + f": {_text(evidence.description)}"
        for evidence in finding.evidence
    )
    candidate_ids = set(finding.contributing_candidate_ids)
    verifier_decisions = [
        decision
        for decision in report.verification_decisions
        if decision.candidate_id in candidate_ids
    ]
    cross_examination_decisions = [
        decision
        for decision in report.cross_examination_decisions
        if decision.candidate_id in candidate_ids
    ]
    falsifier_decisions = [
        decision
        for decision in report.falsification_decisions
        if decision.candidate_id in candidate_ids
    ]
    if verifier_decisions:
        lines.extend(["", "Independent verifier:", ""])
        lines.extend(
            f"- {_inline(decision.candidate_id)}: {_inline(decision.verdict.value)} — "
            f"{_text(decision.rationale)}"
            for decision in verifier_decisions
        )
    if cross_examination_decisions:
        lines.extend(["", "Anonymized adversarial cross-examination:", ""])
        lines.extend(
            f"- reviewer {decision.reviewer_index} / "
            f"{_inline(decision.root_lineage)}: "
            f"{_inline(decision.verdict.value)} — {_text(decision.rationale)}"
            for decision in cross_examination_decisions
        )
    if falsifier_decisions:
        lines.extend(["", "Independent falsifier:", ""])
        lines.extend(
            f"- {_inline(decision.candidate_id)} / {_inline(decision.test_name)}: "
            f"{_inline(decision.verdict.value)} — {_text(decision.rationale)}"
            for decision in falsifier_decisions
        )
    if finding.compensating_controls:
        lines.extend(["", "Compensating controls:", ""])
        lines.extend(f"- {_text(value)}" for value in finding.compensating_controls)
    lines.extend(["", f"Recommended remediation: {_text(finding.recommendation)}", ""])
    if finding.verification_test:
        lines.extend(
            [
                f"Safe local verification: {_text(finding.verification_test.description)}",
                "",
            ]
        )
    if finding.false_positive_conditions:
        lines.extend(["Residual uncertainty / false-positive conditions:", ""])
        lines.extend(f"- {_text(value)}" for value in finding.false_positive_conditions)
        lines.append("")
    if finding.disagreement:
        lines.extend([f"Verifier/judge notes: {_text(finding.disagreement)}", ""])
    if not finding.location_validation.valid:
        lines.extend(
            [
                "Location validation warning: one or more contributing references were invalid.",
                "",
            ]
        )
    return lines


def render_markdown(report: AuditReport) -> str:
    report = AuditReport.model_validate(report.model_dump(mode="python"))
    counts = Counter(finding.severity.value for finding in report.findings)
    status_counts = Counter(finding.status.value for finding in report.findings)
    origin_counts = Counter(finding.origin_kind.value for finding in report.findings)
    scanner_failures = [
        run for run in report.scanner_runs if run.status is not ScannerStatus.SUCCESS
    ]
    model_config = report.metadata.get("configured_models", {})
    model_fallbacks = report.metadata.get("configured_fallbacks", {})
    dependency_preparation = report.metadata.get("dependency_preparation", {})
    solidity = report.metadata.get("solidity", {})
    effective_solidity_coverage = report.effective_solidity_coverage()
    solidity_coverage = (
        effective_solidity_coverage.model_dump(mode="json")
        if effective_solidity_coverage is not None
        else {}
    )
    solidity_compilation = solidity.get("compilation", []) if isinstance(solidity, dict) else []
    run_status = _effective_run_status(report)
    incomplete_empty_run = not report.findings and run_status in {
        AuditRunStatus.DEGRADED,
        AuditRunStatus.INCOMPLETE,
        AuditRunStatus.FAILED,
    }
    executive_summary = (
        "No reportable findings were identified by the analyses that completed. "
        "This run is incomplete and does not support a conclusion about repository safety."
        if incomplete_empty_run
        else (
            f"The audit produced **{len(report.findings)} surviving finding(s)**: "
            f"{status_counts[FindingStatus.CONFIRMED.value]} confirmed, "
            f"{status_counts[FindingStatus.STRONGLY_SUPPORTED.value]} strongly supported, "
            f"{status_counts[FindingStatus.HIGH_CONFIDENCE.value]} high-confidence, and "
            f"{status_counts[FindingStatus.NEEDS_REVIEW.value]} needing human review."
        )
    )
    lines = [
        "# Corrovera Security Assurance Report",
        "",
        "*Independent minds. Corroborated truth.*",
        "",
        "Generated by `mmaudit` · `corrovera.ai`",
        "",
        "## Executive summary",
        "",
        executive_summary,
        "",
        f"> **RUN STATUS: {_text(run_status.value)}**",
        "",
        f"Audit profile: **{_text(report.audit_profile.value)}**. "
        f"Quality status: **{_text(report.quality_status.value)}**.",
        "",
        "Finding discovery origins: "
        f"deterministic execution={origin_counts['deterministic_execution']}, "
        f"model review={origin_counts['model_review']}, "
        f"static analyzer={origin_counts['static_analyzer']}.",
        "",
    ]
    if report.maximum_assurance is not None:
        assurance = report.maximum_assurance
        lines.extend(
            [
                f"Maximum-assurance contract status: **{_text(assurance.status.value)}**.",
                "",
            ]
        )
        if assurance.downgraded:
            lines.extend(
                [
                    "> **DOWNGRADED:** this run did not satisfy the maximum-assurance "
                    "contract and must not be represented as maximum assurance.",
                    "",
                    *[f"- {_text(reason)}" for reason in assurance.downgrade_reasons],
                    "",
                ]
            )
    if not report.completed:
        lines.extend(
            [
                "> **Incomplete audit:** completed work is preserved, but the result must not be "
                "treated as comprehensive.",
                "",
            ]
        )
        lines.extend(f"- {_text(reason)}" for reason in report.incomplete_reasons)
        lines.append("")
    lines.extend(
        [
            "## Status semantics",
            "",
            "- **Confirmed:** passed the deterministic evidence gate through a validated "
            "execution/proof, or through verifier-backed corroborating evidence.",
            "- **Strongly supported:** complete validated attack path and independent support, "
            "but no reproduction or deterministic proof strong enough for confirmation.",
            "- **High-confidence:** strong validated evidence accepted by the verifier, without "
            "the independent proof required for confirmation.",
            "- **Plausible:** concrete code evidence survived review, but material assumptions remain.",
            "- **Needs review:** a surviving hypothesis, not an established vulnerability.",
            "- **Rejected:** unsupported or contradicted; retained only for auditability.",
            "",
            "For Solidity findings, model agreement alone cannot produce `confirmed`; "
            "confirmation requires a replay-confirmed deterministic invariant counterexample, "
            "local reproduction, formal proof/counterexample, or strong deterministic analyzer "
            "evidence plus verifier acceptance.",
            "",
            "Discovery origin is independent of later model adjudication. Model roles cannot "
            "create, suppress, or relocate an execution-originated finding; their contribution "
            "is retained as bounded analysis and dissent.",
            "",
            "Severity totals: "
            + ", ".join(
                f"{severity.value}={counts[severity.value]}"
                for severity in reversed(list(Severity))
            ),
            "",
            "## Audit scope",
            "",
            f"- Repository: {_inline(report.repository.root_name)}",
            f"- Git commit: {_inline(report.repository.git_commit or 'not available')}",
            f"- Changed since: {_inline(report.repository.changed_since or 'full repository')}",
            f"- Files mapped: {len(report.repository.files)}",
            f"- Discovery omissions/limits: {len(report.repository.omitted_files)}",
            "- Reporting severity threshold: "
            f"{_inline(str(report.metadata.get('severity_threshold', 'informational')))}",
            f"- Audit profile: {_inline(report.audit_profile.value)}",
            f"- Quality status: {_inline(report.quality_status.value)}",
            f"- Languages: {_text(', '.join(report.repository.languages) or 'none detected')}",
            f"- Frameworks: {_text(', '.join(report.repository.frameworks) or 'none detected')}",
            "",
        ]
    )
    if report.scope_assessment is not None:
        scope = report.scope_assessment
        lines.extend(
            [
                "## Requested and achieved scope",
                "",
                f"- Requested: {_inline(scope.requested.value)}",
                f"- Achieved: {_inline(scope.achieved.value if scope.achieved else 'none')}",
                f"- Required gate: {scope.gate_required}",
                f"- Complete: {scope.complete}",
                "",
                "| Component | Required | Status | Analyzed paths | Known omissions |",
                "| --- | --- | --- | ---: | ---: |",
            ]
        )
        for component in scope.components:
            lines.append(
                f"| {_text(component.component.value)} | {component.required} | "
                f"{_text(component.status.value)} | {len(component.analyzed_paths)} | "
                f"{len(component.omissions)} |"
            )
        lines.append("")
    if report.prior_audit_comparison is not None:
        prior_comparison = report.prior_audit_comparison
        discovery_counts: dict[str, int] = {}
        remediation_counts: dict[str, int] = {}
        for item in prior_comparison.items:
            discovery_counts[item.discovery_status.value] = (
                discovery_counts.get(item.discovery_status.value, 0) + 1
            )
            remediation_counts[item.remediation_status.value] = (
                remediation_counts.get(item.remediation_status.value, 0) + 1
            )
        lines.extend(
            [
                "## Blind-first prior-audit comparison",
                "",
                f"- Configured: {prior_comparison.configured}",
                f"- Required: {prior_comparison.required}",
                f"- Loaded after blind discovery: "
                f"{prior_comparison.loaded and prior_comparison.blind_discovery_completed_before_load}",
                f"- Prior material withheld from discovery contexts: "
                f"{prior_comparison.prior_material_withheld_from_discovery}",
                f"- Independent candidates available before load: "
                f"{prior_comparison.independent_candidate_count}",
                f"- Model requests completed before load: "
                f"{prior_comparison.model_request_count_before_load}",
                "- Discovery results: "
                + _text(
                    ", ".join(f"{key}={value}" for key, value in sorted(discovery_counts.items()))
                    or "none"
                ),
                "- Remediation results: "
                + _text(
                    ", ".join(f"{key}={value}" for key, value in sorted(remediation_counts.items()))
                    or "none"
                ),
                "",
            ]
        )
        if prior_comparison.errors:
            lines.extend(
                [
                    "Comparison input errors:",
                    "",
                    *[f"- {_text(error)}" for error in prior_comparison.errors],
                    "",
                ]
            )
        if prior_comparison.items:
            lines.extend(
                [
                    "| Prior ID | Title | Discovery | Remediation | Source valid | "
                    "Matched evidence |",
                    "| --- | --- | --- | --- | --- | ---: |",
                ]
            )
            for item in prior_comparison.items:
                lines.append(
                    f"| {_text(item.prior_id)} | {_text(item.title)} | "
                    f"{_text(item.discovery_status.value)} | "
                    f"{_text(item.remediation_status.value)} | {item.source_valid} | "
                    f"{len(item.matched_candidate_ids) + len(item.matched_finding_ids)} |"
                )
            lines.append("")
    lines.extend(["## Solidity coverage", ""])
    if isinstance(solidity_coverage, dict) and solidity_coverage:
        lines.extend(
            [
                f"- Projects discovered: {int(solidity_coverage.get('projects_discovered', 0))}",
                f"- Project types: {_text(', '.join(solidity_coverage.get('project_types', [])) or 'none')}",
                f"- Solidity files discovered: {int(solidity_coverage.get('files_discovered', 0))}",
                "- Solidity files analyzed by AST/fallback index: "
                f"{int(solidity_coverage.get('solidity_files_analyzed', 0))}",
                f"- Contracts indexed: {int(solidity_coverage.get('contracts_indexed', 0))}",
                f"- Functions indexed: {int(solidity_coverage.get('functions_indexed', 0))}",
                "- Functions included in model-reviewed context: "
                f"{int(solidity_coverage.get('functions_reviewed_by_models', 0))}",
                "- Functions with Slither evidence: "
                f"{int(solidity_coverage.get('functions_covered_by_static_tools', 0))}",
                "- Foundry action functions observed/declared: "
                f"{int(solidity_coverage.get('invariant_campaign_functions_observed', 0))}/"
                f"{int(solidity_coverage.get('invariant_campaign_functions_declared', 0))}",
                "- Foundry state properties observed/declared: "
                f"{int(solidity_coverage.get('invariant_campaign_state_properties_observed', 0))}/"
                f"{int(solidity_coverage.get('invariant_campaign_state_properties_declared', 0))}",
                "- Foundry counterexample sequences minimized/observed: "
                f"{int(solidity_coverage.get('invariant_counterexample_sequences_minimized', 0))}/"
                f"{int(solidity_coverage.get('invariant_counterexample_sequences_observed', 0))}",
                "- Contracts/projects with compilation failures: "
                f"{len(solidity_coverage.get('contracts_failed_compilation', []))}",
                "- Unsupported Solidity files: "
                f"{len(solidity_coverage.get('unsupported_files', []))}",
                "- Missing dependencies/unresolved imports: "
                f"{len(solidity_coverage.get('missing_dependencies', [])) + len(solidity_coverage.get('unresolved_imports', []))}",
                "",
                "These counts use explicit denominators; they are not a whole-project security coverage percentage.",
                "",
            ]
        )
        operation_counts = solidity_coverage.get("asset_flow_operation_counts", {})
        direction_counts = solidity_coverage.get("asset_flow_direction_counts", {})
        if isinstance(operation_counts, dict) and operation_counts:
            lines.extend(
                [
                    "Asset-flow operations: "
                    + ", ".join(
                        f"{_text(str(name))}={int(count)}"
                        for name, count in sorted(operation_counts.items())
                    ),
                    "Asset-flow endpoints: "
                    + ", ".join(
                        f"{_text(str(name))}={int(count)}"
                        for name, count in sorted(direction_counts.items())
                    ),
                    "",
                ]
            )
        semantic_summaries = (
            ("Control resolution", "control_resolution_counts"),
            ("Governance stages", "governance_stage_counts"),
            ("Dependency references", "dependency_resolution_counts"),
            ("Oracle freshness validation", "oracle_freshness_counts"),
        )
        for label, field_name in semantic_summaries:
            counts = solidity_coverage.get(field_name, {})
            if isinstance(counts, dict) and counts:
                lines.append(
                    f"{label}: "
                    + ", ".join(
                        f"{_text(str(name))}={int(count)}" for name, count in sorted(counts.items())
                    )
                )
        if any(
            isinstance(solidity_coverage.get(field_name), dict)
            and solidity_coverage.get(field_name)
            for _, field_name in semantic_summaries
        ):
            lines.append("")
        audited_suite_coverage = solidity_coverage.get("audited_suite_coverage")
        if isinstance(audited_suite_coverage, dict):
            lines.extend(_audited_suite_coverage_gap_lines(audited_suite_coverage))
        limitations = [
            *solidity_coverage.get("context_limitations", []),
            *solidity_coverage.get("graph_warnings", []),
            *solidity_coverage.get("project_configuration_assumptions", []),
        ][:20]
        if limitations:
            lines.extend(["Solidity analysis limitations:", ""])
            lines.extend(f"- {_text(str(value))}" for value in limitations)
            lines.append("")
        quality_metrics = solidity_coverage.get("quality_metrics", {})
        if isinstance(quality_metrics, dict) and quality_metrics:
            lines.extend(
                [
                    "Coverage scorecard (each row has its own denominator):",
                    "",
                    "| Metric | Covered | Denominator | Exclusions | Population | Percent | "
                    "N/A evidence | Confidence | Provenance | Failures | Evidence state |",
                    "| --- | ---: | ---: | --- | ---: | ---: | --- | ---: | --- | --- | --- |",
                ]
            )
            for name, raw_metric in sorted(quality_metrics.items()):
                if not isinstance(raw_metric, dict):
                    continue
                percentage = raw_metric.get("percentage")
                raw_exclusions = raw_metric.get("exclusions", [])
                exclusions = (
                    [
                        f"{item.get('subject', 'unknown')}: {item.get('reason', 'unspecified')}"
                        for item in raw_exclusions
                        if isinstance(item, dict)
                    ]
                    if isinstance(raw_exclusions, list)
                    else []
                )
                raw_not_applicable = raw_metric.get("not_applicable_evidence", [])
                not_applicable = (
                    [str(item) for item in raw_not_applicable]
                    if isinstance(raw_not_applicable, list)
                    else []
                )
                raw_provenance = raw_metric.get("provenance", [])
                provenance = (
                    [str(item) for item in raw_provenance]
                    if isinstance(raw_provenance, list)
                    else []
                )
                raw_failures = raw_metric.get("failures", [])
                failures = (
                    [str(item) for item in raw_failures] if isinstance(raw_failures, list) else []
                )
                lines.append(
                    f"| {_text(str(name))} | {int(raw_metric.get('numerator', 0))} | "
                    f"{int(raw_metric.get('denominator', 0))} | "
                    f"{_text('; '.join(exclusions) or 'none')} | "
                    f"{int(raw_metric.get('population', 0))} | "
                    f"{f'{float(percentage):.1f}%' if percentage is not None else 'n/a'} | "
                    f"{_text('; '.join(not_applicable) or 'none')} | "
                    f"{float(raw_metric.get('confidence', 0)):.2f} | "
                    f"{_text(', '.join(provenance) or 'none')} | "
                    f"{_text('; '.join(failures) or 'none')} | "
                    f"{_text(str(raw_metric.get('state', 'not_analyzed')))} |"
                )
            lines.append("")
    else:
        lines.extend(["No Solidity project was detected or analyzed.", ""])
    dependency_rows = (
        dependency_preparation.get("results", [])
        if isinstance(dependency_preparation, dict)
        else []
    )
    if isinstance(dependency_rows, list) and dependency_rows:
        lines.extend(
            [
                "## Dependency preparation",
                "",
                f"- Explicitly enabled: {bool(dependency_preparation.get('enabled', False))}",
                f"- Required: {bool(dependency_preparation.get('required', False))}",
                f"- SBOM documents: {int(dependency_preparation.get('sbom_documents', 0))}",
                "",
                "| Project | Status | Scan | Packages | Files copied | Snapshot |",
                "| --- | --- | --- | ---: | ---: | --- |",
            ]
        )
        for raw_result in dependency_rows:
            if not isinstance(raw_result, dict):
                continue
            packages = raw_result.get("packages", [])
            lines.append(
                f"| {_inline(str(raw_result.get('project_root', '.')))} | "
                f"{_text(str(raw_result.get('status', 'unknown')))} | "
                f"{_text(str(raw_result.get('scan_status', 'not_run')))} | "
                f"{len(packages) if isinstance(packages, list) else 0} | "
                f"{int(raw_result.get('copied_files', 0))} | "
                f"{_inline(str(raw_result.get('snapshot_sha256') or 'not available'))} |"
            )
        lines.append("")
    compilation_rows = (
        [item for item in solidity_compilation if isinstance(item, dict)]
        if isinstance(solidity_compilation, list)
        else []
    )
    if compilation_rows:
        lines.extend(
            [
                "## Solidity compilation isolation",
                "",
                "| Project | Framework | Status | Repository code | Isolation backend |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for compilation in compilation_rows:
            lines.append(
                f"| {_inline(str(compilation.get('project_root', '.')))} | "
                f"{_text(str(compilation.get('framework', 'unknown')))} | "
                f"{_text(str(compilation.get('status', 'unknown')))} | "
                f"{_text(str(compilation.get('repository_code_execution', 'not_applicable')))} | "
                f"{_text(str(compilation.get('isolation_backend') or 'not applicable'))} |"
            )
        lines.append("")
    model_coverage = report.model_review_coverage
    if model_coverage is not None:
        lines.extend(
            [
                "## Model review surface coverage",
                "",
                f"- Coverage applicable: {model_coverage.applicable}",
                "- Critical-surface classification complete: "
                f"{model_coverage.critical_classification_complete}",
                f"- Surfaces reviewed: {model_coverage.overall.numerator}/"
                f"{model_coverage.overall.denominator}",
                f"- Critical surfaces with at least "
                f"{model_coverage.minimum_critical_root_lineages} independent root lineages: "
                f"{model_coverage.critical.numerator}/{model_coverage.critical.denominator}",
                f"- Critical-surface gate passed: {model_coverage.critical_gate_passed}",
                "",
            ]
        )
        if model_coverage.limitations:
            lines.extend(
                [
                    "Model-review coverage limitations:",
                    "",
                    *[f"- {_text(limitation)}" for limitation in model_coverage.limitations[:20]],
                    "",
                ]
            )
        lines.extend(
            [
                "| Surface | Kind | Critical | Credited response records | "
                "Successful roles | Root lineages |",
                "| --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for surface in model_coverage.surfaces:
            credited_records = sum(reference.credited for reference in surface.evidence_references)
            lines.append(
                f"| {_text(surface.label)} | {_text(surface.kind.value)} | "
                f"{surface.critical} | {credited_records} | "
                f"{_text(', '.join(surface.reviewer_roles) or 'none')} | "
                f"{_text(', '.join(surface.root_lineages) or 'none')} |"
            )
        lines.append("")
    if report.quality_gates:
        lines.extend(
            [
                "## Quality gates",
                "",
                "| Gate | Required | Passed | Detail |",
                "| --- | --- | --- | --- |",
            ]
        )
        for gate in report.quality_gates:
            lines.append(
                f"| {_text(gate.gate)} | {gate.required} | {gate.passed} | {_text(gate.detail)} |"
            )
        lines.append("")
    if report.maximum_assurance is not None and report.maximum_assurance.requirements:
        lines.extend(
            [
                "## Maximum-assurance contract",
                "",
                "| Engine | Required | State | Passed | Detail |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for requirement in report.maximum_assurance.requirements:
            lines.append(
                f"| {_text(requirement.engine)} | {requirement.required} | "
                f"{_text(requirement.state.value)} | {requirement.passed} | "
                f"{_text(requirement.detail)} |"
            )
        lines.append("")
    if report.invariants is not None:
        lines.extend(
            [
                "## Invariant discovery",
                "",
                f"- Protocol profiles detected: "
                f"{_text(', '.join(report.invariants.protocol_profiles) or 'none')}",
                f"- Source-linked invariants proposed: {len(report.invariants.invariants)}",
                f"- Deterministic Foundry templates available: "
                f"{report.invariants.templates_available_count}",
                f"- Source-discovered executable harnesses: {report.invariants.executable_count}",
                "",
                "Inferred invariants are review hypotheses. They are not treated as protocol "
                "requirements until source documentation, existing tests, explicit configuration, "
                "or executable evidence validates them.",
                "",
            ]
        )
        for invariant in report.invariants.invariants[:30]:
            location = invariant.locations[0] if invariant.locations else None
            location_text = (
                f"{location.path}:{location.start_line}-{location.end_line}"
                if location
                else "no source location"
            )
            lines.append(
                f"- {_text(invariant.title)} — {_inline(invariant.category.value)}, "
                f"confidence {invariant.confidence:.2f}, {_inline(location_text)}"
            )
        lines.append("")
    if report.invariant_review is not None:
        invariant_review = report.invariant_review
        lines.extend(
            [
                "## Independent invariant review",
                "",
                f"- Existing invariant opinions recorded: {len(invariant_review.decisions)}",
                f"- Source-validated model proposals: {len(invariant_review.accepted_proposals)}",
                f"- Rejected model proposals: {len(invariant_review.rejected_proposals)}",
                "",
                "This stage proposes properties only. Its output is model-only, cannot create "
                "a finding, is excluded from deterministic invariant counts, and is not "
                "automatically translated or executed.",
                "",
            ]
        )
        for proposal in invariant_review.accepted_proposals[:30]:
            location = proposal.locations[0]
            lines.append(
                f"- {_text(proposal.title)} — {_inline(proposal.category.value)}, "
                f"model-only confidence cap {proposal.confidence:.2f}, "
                f"{_inline(f'{location.path}:{location.start_line}-{location.end_line}')}"
            )
        for rejection in invariant_review.rejected_proposals[:20]:
            lines.append(
                f"- Rejected proposal {_text(rejection.title)}: "
                f"{_text('; '.join(rejection.errors))}"
            )
        lines.append("")
    lines.extend(["## Stateful invariant execution", ""])
    if report.invariant_executions:
        lines.extend(
            [
                "| Invariant | Harness | Status | Attempts | Replay | Minimized | Minimized sequence | Runs | Depth | Seed | Ordering | Capabilities | Economic metrics | Limitation |",
                "| --- | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
            ]
        )
        for invariant_result in report.invariant_executions:
            minimization = invariant_result.minimization_evidence
            minimized_sequence = (
                " -> ".join(minimization.retained_action_ids)
                if minimization is not None and minimization.proven_minimal
                else "n/a"
            )
            lines.append(
                f"| {_inline(invariant_result.invariant_id)} | "
                f"{_text(invariant_result.harness_name)} | "
                f"{_text(invariant_result.status.value)} | "
                f"{invariant_result.successful_attempts}/{invariant_result.attempts} | "
                f"{'confirmed' if invariant_result.replay_confirmed else 'not confirmed'} | "
                f"{'proven' if minimization and minimization.proven_minimal else 'n/a'} | "
                f"{_text(minimized_sequence)} | "
                f"{invariant_result.runs} | {invariant_result.depth} | "
                f"{invariant_result.seed} | "
                f"{_text(invariant_result.required_transaction_ordering.value)} | "
                f"{_text(_capability_summary(invariant_result.capability_policy))} | "
                f"{_text(_economic_metrics_summary(invariant_result.economic_metrics))} | "
                f"{_text('; '.join(invariant_result.limitations))} |"
            )
        lines.append("")
    else:
        lines.extend(
            [
                "No validated typed stateful invariant harness was executed. Inferred "
                "invariants remain hypotheses, and this is reported as missing coverage.",
                "",
            ]
        )
    lines.extend(_execution_origin_disposition_lines(report))
    lines.extend(["## Protocol economic simulations", ""])
    if report.economic_simulations:
        executed_economic = {
            plan.kind: [
                result
                for result in report.invariant_executions
                if result.economic_template is plan.kind
            ]
            for plan in report.economic_simulations
        }
        lines.extend(
            [
                "| Template | Applicable | Typed harness | Generated | Execution | Replayed | Minimized | Ordering | Linked invariants | Limitation |",
                "| --- | --- | --- | ---: | --- | ---: | ---: | --- | ---: | --- |",
            ]
        )
        for plan in report.economic_simulations:
            executions = executed_economic[plan.kind]
            statuses = Counter(result.status.value for result in executions)
            execution_summary = ", ".join(
                f"{count} {status}" for status, count in sorted(statuses.items())
            )
            lines.append(
                f"| {_text(plan.kind.value)} | {plan.applicable} | "
                f"{plan.typed_harness_available} | "
                f"{len(executions)} | "
                f"{_text(execution_summary or 'not_executed')} | "
                f"{sum(result.replay_confirmed for result in executions)} | "
                f"{sum(result.minimization_evidence is not None and result.minimization_evidence.proven_minimal for result in executions)} | "
                f"{_text(plan.required_transaction_ordering.value)} | "
                f"{len(plan.invariant_ids)} | {_text('; '.join(plan.limitations))} |"
            )
        lines.extend(
            [
                "",
                "Economic feasibility is not inferred from technical test success. Capital, "
                "fees, gas, market depth, net profit, victim loss, privileges, and repeatability "
                "remain unknown unless an execution result explicitly measures them.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "No protocol-specific economic template was selected from the available "
                "deterministic facts.",
                "",
            ]
        )
    lines.extend(
        [
            "## Formal and symbolic engines",
            "",
        ]
    )
    if report.formal_runs:
        lines.extend(
            [
                "| Tool | Status | Version | Binary SHA-256 | Dependencies | Corpus | Translated | Seed | Evidence | Assumptions | Limitation |",
                "| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |",
            ]
        )
        for formal_run in report.formal_runs:
            dependency_summary = "; ".join(
                f"{dependency.name} {dependency.version or 'unknown'} "
                f"sha256={dependency.executable_sha256}"
                for dependency in formal_run.dependencies
            )
            lines.append(
                f"| {_text(formal_run.tool)} | {_text(formal_run.status.value)} | "
                f"{_text(formal_run.version or 'unavailable')} | "
                f"{_inline(formal_run.executable_sha256 or 'not recorded')} | "
                f"{_inline(dependency_summary or 'none')} | "
                f"{_inline(formal_run.property_corpus_hash or 'not applicable')} | "
                f"{formal_run.translated_properties} | "
                f"{formal_run.campaign_seed if formal_run.campaign_seed is not None else 'n/a'} | "
                f"{len(formal_run.evidence)} | "
                f"{_text('; '.join(formal_run.assumptions))} | "
                f"{_text('; '.join(formal_run.translation_limitations) or formal_run.failure_reason or '')} |"
            )
        lines.append("")
        comparisons = compare_dynamic_engine_outcomes(report.formal_runs)
        if comparisons:
            lines.extend(
                [
                    "| Property | Echidna | Medusa | Disagreement |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for comparison in comparisons:
                lines.append(
                    f"| {_inline(comparison.property_id)} | "
                    f"{_text(comparison.outcomes['echidna'].value)} | "
                    f"{_text(comparison.outcomes['medusa'].value)} | "
                    f"{comparison.disagreement} |"
                )
            lines.append("")
    else:
        lines.extend(
            [
                "No formal or symbolic engine result was recorded. This is missing coverage, "
                "not evidence of safety.",
                "",
            ]
        )
    if report.report_quality_review is not None:
        review = report.report_quality_review
        lines.extend(
            [
                "## Independent report-quality review",
                "",
                f"- Review completed: **{review.passed}**",
                f"- Missing sections flagged: {len(review.missing_sections)}",
                f"- Unsupported claims flagged: {len(review.unsupported_claims)}",
                f"- Coverage caveats flagged: {len(review.coverage_caveats)}",
                f"- Contradictions flagged: {len(review.contradictions)}",
                f"- Rationale: {_text(review.rationale)}",
                "",
            ]
        )
        for label, values in (
            ("Missing section", review.missing_sections),
            ("Unsupported claim", review.unsupported_claims),
            ("Coverage caveat", review.coverage_caveats),
            ("Contradiction", review.contradictions),
        ):
            lines.extend(f"- {label}: {_text(value)}" for value in values[:20])
        if any(
            (
                review.missing_sections,
                review.unsupported_claims,
                review.coverage_caveats,
                review.contradictions,
            )
        ):
            lines.append("")
    reproduced = [
        result
        for result in report.reproductions
        if result.state
        in {
            ReproductionState.REPRODUCED,
            ReproductionState.REPRODUCED_AND_MINIMIZED,
            ReproductionState.FORMALLY_PROVEN,
        }
        and result.integrity is not None
        and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
    ]
    if report.reproductions:
        lines.extend(
            [
                "## Executable verification",
                "",
                (
                    f"{len(report.reproductions)} generated Foundry fork-test result(s) were "
                    f"recorded; {len(reproduced)} reproduced the submitted claim."
                ),
                "",
                "| Candidate | Test | State | Integrity | Attempts | Block | Chain | Artifact |",
                "| --- | --- | --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for result in report.reproductions:
            artifact = result.regression_test_path or result.generated_test_path or "not stored"
            lines.append(
                f"| {_inline(result.candidate_id)} | {_text(result.test_name)} | "
                f"{_text(result.state.value)} | "
                f"{_text(result.integrity.status.value if result.integrity else 'not verified')} | "
                f"{result.successful_attempts}/{result.attempts} | "
                f"{_text(str(result.required_block_number or 'not pinned'))} | "
                f"{_text(str(result.expected_chain_id or 'not pinned'))} | "
                f"{_inline(artifact)} |"
            )
        financial_results = [
            result for result in report.reproductions if result.financial_settlement is not None
        ]
        if financial_results:
            lines.extend(
                [
                    "",
                    "Settled financial impact (single-asset base units):",
                    "",
                    "| Candidate | Actor | Asset | Start | Borrowed | Repaid | Gross received | Fees | Slippage | End | Net impact | Verified |",
                    "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
                ]
            )
            for result in financial_results:
                settlement = result.financial_settlement
                assert settlement is not None
                asset = settlement.asset_target or settlement.asset_kind.value
                lines.append(
                    f"| {_inline(result.candidate_id)} | {_text(settlement.actor)} | "
                    f"{_text(asset)} | {settlement.starting_assets} | "
                    f"{settlement.borrowed_assets} | {settlement.repaid_assets} | "
                    f"{settlement.gross_assets_received} | {settlement.fees_paid} | "
                    f"{settlement.slippage_loss} | {settlement.ending_assets} | "
                    f"{settlement.net_impact} | {result.financial_settlement_verified} |"
                )
        limitations = [
            limitation for result in report.reproductions for limitation in result.limitations
        ][:20]
        if limitations:
            lines.extend(["", "Executable-verification limitations:", ""])
            lines.extend(f"- {_text(value)}" for value in limitations)
        lines.append("")
    elif solidity_coverage:
        lines.extend(
            [
                "## Executable verification",
                "",
                "No generated Foundry fork-test result was recorded. Solidity confirmation "
                "therefore remains capped below confirmed unless deterministic analyzer proof "
                "is present.",
                "",
            ]
        )
    lines.extend(
        [
            "## Scanner execution",
            "",
            "| Scanner | Status | Version | Repository code | Isolation backend | Findings |",
            "| --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for scanner_run in report.scanner_runs:
        lines.append(
            f"| {_text(scanner_run.scanner)} | {_text(scanner_run.status.value)} | "
            f"{_text(scanner_run.version or 'unavailable')} | "
            f"{_text(scanner_run.repository_code_execution.value)} | "
            f"{_text(scanner_run.isolation_backend or 'not applicable')} | "
            f"{len(scanner_run.findings)} |"
        )
    if scanner_failures:
        lines.extend(["", "Scanner limitations/failures:", ""])
        lines.extend(
            f"- {_text(run.scanner)}: {_text(run.error or run.status.value)}"
            for run in scanner_failures
        )
    differential = report.repository_suite_differential
    if differential is not None:
        raw_fork_rpc_privacy = report.privacy.get("fork_rpc_egress")
        fork_rpc_privacy = raw_fork_rpc_privacy if isinstance(raw_fork_rpc_privacy, dict) else {}
        lines.extend(
            [
                "",
                "## Repository suite differential execution",
                "",
                f"- Matrix status: **{_text(differential.status.value)}**",
                "- Execution states: "
                + ", ".join(_inline(state_id) for state_id in differential.requested_state_ids),
                f"- Fresh-workspace repetitions per state: **{differential.required_repetitions}**",
                "- Fork RPC boundary: **trusted read-only loopback bridge**",
                "- Fork RPC network scope: **single configured loopback origin**",
                "- Transaction-capable requests forwarded: "
                f"**{bool(fork_rpc_privacy.get('transaction_capable_request_forwarded'))}**",
                "- Credentials forwarded: "
                f"**{bool(fork_rpc_privacy.get('credentials_forwarded'))}**",
                f"- Permitted read calls: **{int(fork_rpc_privacy.get('permitted_rpc_call_count', 0))}**",
                "- Origin reads validated: "
                f"**{int(fork_rpc_privacy.get('origin_validated_rpc_call_count', 0))}** / "
                f"**{int(fork_rpc_privacy.get('origin_attempted_rpc_call_count', 0))}**",
                f"- Differential result SHA-256: {_inline(differential.result_sha256)}",
            ]
        )
        if differential.matrix is not None:
            classifications = Counter(
                comparison.classification.value for comparison in differential.matrix.comparisons
            )
            lines.extend(
                [
                    "- Per-test classifications: "
                    + ", ".join(
                        f"{_text(classification)}={count}"
                        for classification, count in sorted(classifications.items())
                    ),
                ]
            )
            directions = Counter(
                comparison.direction.value
                for comparison in differential.matrix.comparisons
                if comparison.direction is not None
            )
            if directions:
                direction_labels = {
                    "clean_pass_pinned_failure": "clean-pass / pinned-failure",
                    "clean_failure_pinned_pass": "clean-failure / pinned-pass",
                    "semantic_result_changed": "semantic result changed",
                }
                lines.append(
                    "- Divergence directions: "
                    + ", ".join(
                        f"{_text(direction_labels.get(direction, direction))}={count}"
                        for direction, count in sorted(directions.items())
                    )
                )
        lines.extend(
            f"- Differential limitation: {_text(item)}" for item in differential.limitations
        )
        lines.extend(
            [
                "",
                "Differential execution is bounded validation evidence, not proof that either "
                "execution state or the audited repository is safe.",
            ]
        )
    lines.extend(["", "## Model roles and reproducibility", ""])
    displayed_roles = [
        *ALL_MODEL_ROLES,
        *sorted(set(model_config) - set(ALL_MODEL_ROLES)),
    ]
    for role in displayed_roles:
        identifier = str(model_config.get(role, "not called"))
        fallbacks = model_fallbacks.get(role, [])
        fallback_text = (
            ", ".join(_inline(str(value)) for value in fallbacks)
            if isinstance(fallbacks, list) and fallbacks
            else "none"
        )
        lines.append(
            f"- {_text(role)}: primary {_inline(identifier)}; explicit fallbacks: {fallback_text}"
        )
    lines.extend(
        [
            "",
            f"- Model configuration SHA-256: {_inline(report.model_configuration_hash)}",
            f"- Full configuration SHA-256: {_inline(report.configuration_hash)}",
            f"- Run ID: {_inline(report.run_id)}",
            f"- Generated at (UTC): {_inline(report.generated_at.isoformat())}",
            "",
            "| Role | Requested model | Returned model | Provider | Tokens | Cost (USD) | ZDR requested |",
            "| --- | --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for usage in report.usage:
        lines.append(
            f"| {_text(usage.role)} | {_text(usage.requested_model)} | "
            f"{_text(usage.returned_model or 'not returned')} | "
            f"{_text(usage.provider or 'not returned')} | {usage.total_tokens} | "
            f"{usage.accounted_cost_usd:.4f} | "
            f"{bool(usage.routing.get('zdr_requested'))} |"
        )
    effective_privacy = report.privacy.get("effective_policy")
    effective_privacy = effective_privacy if isinstance(effective_privacy, dict) else {}
    lines.extend(
        [
            "",
            "## Privacy and cost",
            "",
            f"- Privacy profile: **{report.privacy.get('profile', 'UNKNOWN')}**",
            f"- Source-code egress enabled: **{bool(report.privacy.get('code_egress_enabled'))}**",
            f"- ZDR required: **{bool(report.privacy.get('require_zdr'))}**",
            f"- Secret redaction enabled: **{bool(report.privacy.get('redact_secrets'))}**",
            f"- Raw prompts stored: **{bool(report.privacy.get('store_raw_prompts'))}**",
            f"- Raw responses stored: **{bool(report.privacy.get('store_raw_responses'))}**",
            "- Files withheld from model context by secret safeguards: "
            f"**{int(report.metadata.get('context_files_withheld_by_secret_safeguards', 0))}**",
            f"- Accounted model cost: **${report.accounted_cost_usd:.4f}** / "
            f"**${report.budget_usd:.2f}** budget",
            f"- Tokens reported: **{sum(record.total_tokens for record in report.usage)}**",
            "",
            "Provider and routing metadata are retained in the JSON report. Prompts, responses, "
            "credentials, and authorization headers are omitted by default.",
            "",
        ]
    )
    if effective_privacy:
        consent_sha256 = effective_privacy.get("consent_sha256")
        if consent_sha256:
            retention_consent = (
                f"`{consent_sha256}`; expires {effective_privacy.get('consent_expires_at')}"
            )
        elif effective_privacy.get("privacy_profile") == "STRICT_ZDR":
            retention_consent = "not applicable under STRICT_ZDR"
        elif (
            effective_privacy.get("privacy_profile") == "SYNTHETIC_BENCHMARK"
            and effective_privacy.get("require_zdr") is True
        ):
            retention_consent = "not applicable to ZDR-enforced synthetic benchmark source"
        else:
            retention_consent = "missing from non-strict effective privacy evidence"
        lines.extend(
            [
                "- Effective privacy evidence: "
                f"`{effective_privacy.get('evidence_sha256', 'unavailable')}`",
                "- Provider-visible source scope: "
                f"`{effective_privacy.get('source_sha256', 'unavailable')}` "
                f"({effective_privacy.get('source_classification', 'UNKNOWN')})",
                "- Privacy-permitted exact model routes: "
                + ", ".join(
                    f"`{model}`"
                    for model in effective_privacy.get("permitted_model_ids", [])
                    if isinstance(model, str)
                ),
                "- Privacy-permitted exact provider endpoints: "
                + ", ".join(
                    f"`{endpoint}`"
                    for endpoint in effective_privacy.get("permitted_provider_endpoints", [])
                    if isinstance(endpoint, str)
                ),
                f"- Retention consent: {retention_consent}",
            ]
        )
        privacy_limitations = effective_privacy.get("limitations")
        if isinstance(privacy_limitations, list):
            lines.extend(f"- Privacy limitation: {item}" for item in privacy_limitations)
        lines.append("")
    lines.extend(["## Findings", ""])
    ordered = sorted(
        report.findings,
        key=lambda finding: (
            -{
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFORMATIONAL: 0,
            }[finding.severity],
            finding.id,
        ),
    )
    if not ordered:
        lines.extend(
            [
                "No surviving findings met the configured scope. This is not proof that the "
                "repository is secure.",
                "",
            ]
        )
    for finding in ordered:
        lines.extend(_finding(finding, report))
    lines.extend(
        [
            "## Rejected and disputed proposals",
            "",
            f"{len(report.rejected_findings)} candidate group(s) were rejected. Rejection details "
            "and origin-specific contributing evidence remain in the JSON artifacts.",
            "",
        ]
    )
    for finding in report.rejected_findings:
        lines.append(
            f"- {_inline(finding.id)} [{_text(_origin_label(finding))}] — "
            f"{_text(finding.title)}: {_text(finding.disagreement)}"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- This is a bounded source review, not a proof of security or a penetration test.",
            "- Models can hallucinate; only deterministic location and consensus constraints are automatic.",
            "- Unavailable scanners, omitted files, framework behavior, runtime configuration, and "
            "external controls can materially change conclusions.",
            "- `needs_review` items are hypotheses and must not be represented as established vulnerabilities.",
            "",
            "## Recommended next actions",
            "",
            "1. Reproduce confirmed and high-confidence findings in a disposable local environment.",
            "2. Review `needs_review` items with maintainers who understand runtime controls.",
            "3. Resolve scanner failures and repeat the audit after material code changes.",
            "4. Obtain professional review for high-impact or regulated systems.",
            "",
        ]
    )
    return "\n".join(lines)
