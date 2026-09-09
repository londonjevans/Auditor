"""Bounded descriptive candidate variance reports; never qualified client audit evidence."""

from __future__ import annotations

from collections import Counter
from decimal import Decimal

from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusBenchmarkTruth,
)
from mmaudit.benchmark.development_corpus_stability import (
    DevelopmentControlFrequency,
    DevelopmentCorpusStability,
    DevelopmentStabilityGroup,
    DevelopmentStabilityRatio,
    read_development_corpus_stability,
)
from mmaudit.models.development_corpus_repeats import (
    DevelopmentCorpusRepeatsObservation,
    read_development_corpus_repeats,
)
from mmaudit.models.schemas import Severity
from mmaudit.reporting.markdown import _inline, _text

MAX_DEVELOPMENT_STABILITY_REPORT_BYTES = 4_000_000
_CLASSES = (
    "STABLE",
    "INTERMITTENT",
    "SINGLE_RUN",
    "NEVER",
    "INCOMPLETE_OBSERVATIONS",
    "NO_REPEATS",
)


class _Report:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.size = 0

    def add(self, *lines: str) -> None:
        for line in lines:
            self.size += len(line.encode("utf-8")) + 1
            if self.size > MAX_DEVELOPMENT_STABILITY_REPORT_BYTES:
                raise ValueError("candidate variance report exceeds its byte bound")
            self.lines.append(line)

    def finish(self) -> str:
        return "\n".join(self.lines) + "\n"


def _indexes(values: tuple[int, ...]) -> str:
    return ", ".join(str(i + 1) for i in values) or "none"


def _ratio(value: DevelopmentStabilityRatio) -> str:
    fraction = f"{value.numerator}/{value.denominator}"
    if value.value is None:
        return fraction + " — unavailable (" + _text(value.state) + ")"
    return fraction + f" = {value.value:.6g}"


def _number(value: float | None) -> str:
    return "unavailable" if value is None else f"{value:.12g}"


def _frequency(value: DevelopmentControlFrequency) -> str:
    return (
        _inline(value.classification)
        + "; "
        + _ratio(value.frequency)
        + "; present: "
        + _indexes(value.positive_trial_indexes)
        + "; observed absence: "
        + _indexes(value.known_absence_trial_indexes)
        + "; unavailable: "
        + _indexes(value.unobserved_trial_indexes)
    )


def _costs(
    report: _Report,
    *,
    accounted: Decimal,
    actual: Decimal,
    uncertain: Decimal,
    reserved: Decimal,
    seconds: float,
) -> None:
    report.add(
        "## Retained accounting",
        "",
        "These retained liabilities are not provider reconciliation, a total bill, or a hard "
        "price guarantee. Unknown charges are not zero. Recorded durations are not end-to-end time.",
        "",
        "| Measure | Retained value |",
        "| --- | --- |",
        f"| Accounted cost (USD) | {_text(str(accounted))} |",
        f"| Reported actual cost (USD) | {_text(str(actual))} |",
        f"| Uncertain accounted cost (USD) | {_text(str(uncertain))} |",
        f"| Active reservation (USD) | {_text(str(reserved))} |",
        f"| Recorded duration (seconds) | {_number(seconds)} |",
        "",
    )


def _series(report: _Report, series: DevelopmentCorpusRepeatsObservation) -> None:
    report.add(
        "## Predeclared candidate series",
        "",
        "Local predeclaration is not independent campaign registration or exhaustive selection.",
        "",
        f"Series artifact digest: {_inline(series.observation_sha256)}.",
        f"Plan artifact digest: {_inline(series.plan.plan_sha256)}.",
        f"Planned trials: {series.plan.trial_count}; started selections: "
        f"{series.started_trial_count}; complete candidate trials: {series.completed_trial_count}.",
        f"Candidate retention status: {_inline(series.status)}; stop reason: "
        f"{_inline(series.stop_reason or 'none')}.",
        f"Measurement availability: {_inline(series.measurement_scope)}.",
        f"Selected requests: {series.selected_request_count}; missing accounting: "
        f"{len(series.missing_accounting_request_ids)}; missing runtime: "
        f"{len(series.missing_runtime_request_ids)}; unknown actual costs: "
        f"{len(series.unknown_actual_cost_request_ids)}.",
        "Missing whole trial results: " + _indexes(series.missing_result_trial_indexes) + ".",
        "",
        "| Trial | Retention status | Selected requests | Observed responses |",
        "| --- | --- | --- | --- |",
    )
    for slot, plan in zip(series.trials, series.plan.trials, strict=True):
        observed = (
            sum(s.status == "OBSERVED" for s in slot.observation.observations)
            if slot.observation is not None
            else 0
        )
        report.add(
            f"| {slot.trial_index + 1} | {_inline(slot.status)} | {len(plan.shards)} | {observed} |"
        )
    report.add(
        "", "Full original evidence and request-level liabilities: [result.json](result.json).", ""
    )
    _costs(
        report,
        accounted=series.total_accounted_cost_usd,
        actual=series.reported_actual_cost_usd,
        uncertain=series.uncertain_accounted_cost_usd,
        reserved=series.active_reserved_usd,
        seconds=series.elapsed_seconds,
    )
    report.add("Duration scope: " + _inline(series.elapsed_scope) + ".", "")


def _metrics(report: _Report, group: DevelopmentStabilityGroup) -> None:
    report.add(
        "| Descriptive proxy | Value |",
        "| --- | --- |",
        "| Declared planted-root location coverage (not validated recall) | "
        + _ratio(group.union_location_coverage)
        + " |",
        "| Declared planted-root asserted-violation coverage | "
        + _ratio(group.union_assertion_coverage)
        + " |",
        "| Severity-weighted location coverage | "
        + _ratio(group.severity_weighted_union_location_coverage)
        + " |",
        "| Severity-weighted asserted-violation coverage | "
        + _ratio(group.severity_weighted_union_assertion_coverage)
        + " |",
        "| Pooled per-trial weighted location precision proxy | "
        + _ratio(group.pooled_per_trial_location_precision)
        + " |",
        "| Pooled per-trial weighted assertion precision proxy | "
        + _ratio(group.pooled_per_trial_assertion_precision)
        + " |",
        "| Mean selected-run location coverage | "
        + _number(group.mean_selected_run_location_coverage)
        + " |",
        "| Location-coverage population variance | "
        + _number(group.population_variance_selected_run_location_coverage)
        + " |",
        "| Mean selected-run assertion coverage | "
        + _number(group.mean_selected_run_assertion_coverage)
        + " |",
        "| Assertion-coverage population variance | "
        + _number(group.population_variance_selected_run_assertion_coverage)
        + " |",
        "",
    )


def _group(report: _Report, group: DevelopmentStabilityGroup, index: int) -> None:
    report.add(
        f"## Cohort {index}: candidate observations",
        "",
        "Selected trials: " + _indexes(group.trial_indexes) + ".",
        "Comparison scope: " + _inline(group.comparison_scope) + ".",
        "Observation scope: " + _inline(group.quality_scope) + ".",
        "",
    )
    if len(group.trial_indexes) < 2:
        report.add(
            "> NO REPEATS: this cohort has one retained trial; repeated-run variance is unavailable.",
            "",
        )
    if group.comparison_scope == "SAME_REQUEST_CONFIGURATION_CONTINUATION_CHAINS_NOT_SINGLE_PASSES":
        report.add(
            "> CONTINUATION CHAINS: these aggregate multiple recorded attempts, not repeated "
            "single-pass audits. Do not pool their results as independent first attempts.",
            "",
        )
    _metrics(report, group)
    report.add(
        "### Declared planted controls by severity",
        "",
        "Classes below describe retained model assertions against declared controls, "
        "not validated vulnerabilities. Unavailable observations are not known misses.",
        "",
        "| Severity | Declared | Stable | Intermittent | Single run | Never observed | "
        "Unavailable | No repeats | Guarded asserted |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    )
    for summary in group.severity:
        frequencies: Counter[str] = Counter(
            c.assertion.classification
            for c in group.controls
            if c.expected == "PLANTED" and c.severity == summary.severity
        )
        report.add(
            f"| {_text(summary.severity.value)} | {summary.expected_root_count} | "
            + " | ".join(str(frequencies[name]) for name in _CLASSES)
            + f" | {len(summary.guarded_assertion_control_ids)} |"
        )
    report.add("")
    for classes, warning in (
        ({"INTERMITTENT", "SINGLE_RUN"}, "HIGH/CRITICAL VARIATION"),
        ({"INCOMPLETE_OBSERVATIONS"}, "HIGH/CRITICAL OBSERVATION GAPS"),
    ):
        controls = [
            c.control_id
            for c in group.controls
            if c.expected == "PLANTED"
            and c.severity in {Severity.HIGH, Severity.CRITICAL}
            and c.assertion.classification in classes
        ]
        if controls:
            report.add(
                "> "
                + warning
                + ": "
                + ", ".join(_inline(c) for c in controls)
                + ". These are declared-control observations, not confirmed findings.",
                "",
            )
    report.add(
        "### Complete selected control observations",
        "",
        "Location matches include advisory claims; assertions require the retained "
        "invariant-violation kind. Guarded assertions are not automatically false positives.",
        "",
        "| Control | Declared expectation | Severity | Location observations | Assertion observations |",
        "| --- | --- | --- | --- | --- |",
    )
    for control in group.controls:
        report.add(
            f"| {_inline(control.control_id)} | {_text(control.expected)} | "
            f"{_text(control.severity.value)} | {_frequency(control.location)} | "
            f"{_frequency(control.assertion)} |"
        )
    report.add("")


def _measured(report: _Report, stability: DevelopmentCorpusStability) -> None:
    report.add(
        "## Retained measurement",
        "",
        "Stability artifact digest: " + _inline(stability.stability_sha256) + ".",
        "Selection scope: " + _inline(stability.selection_scope) + ".",
        f"Retained trials: {len(stability.trials)}; cohorts: {len(stability.cohorts)}; "
        f"pairs: {len(stability.pairs)}.",
        "Combined comparison: " + _inline(stability.combined.comparison_scope) + ".",
        "Combined observation scope: " + _inline(stability.combined.quality_scope) + ".",
        "",
        "The selected inputs may be post-hoc or non-exhaustive. Missing trials outside this "
        "retained selection are not inferred. Cohort membership does not establish independence.",
        "",
        "| Trial | Cohort | Source scope | Transport | Selected requests | Missing accounting | "
        "Missing runtime | Unknown actual costs |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    )
    cohort_indexes = {
        trial: index
        for index, group in enumerate(stability.cohorts, 1)
        for trial in group.trial_indexes
    }
    for trial in stability.trials:
        report.add(
            f"| {trial.trial_index + 1} | {cohort_indexes[trial.trial_index]} | "
            f"{_inline(trial.source_scope)} | {_inline(trial.transport)} | "
            f"{trial.selected_request_count} | {len(trial.missing_accounting_request_ids)} | "
            f"{len(trial.missing_runtime_request_ids)} | "
            f"{len(trial.unknown_actual_cost_request_ids)} |"
        )
    report.add("")
    for trial in stability.trials:
        report.add(
            f"Trial {trial.trial_index + 1}: original {_inline(trial.original_run_id)}; "
            "retained runs " + ", ".join(_inline(r) for r in trial.run_ids) + "; "
            "measurement " + _inline(trial.measurement_sha256) + ".",
            "",
        )
    combined = stability.combined
    report.add(
        f"All retained claims: {combined.total_claim_count}; guarded invariant assertions: "
        f"{combined.guarded_invariant_claim_count}; guarded advisories: "
        f"{combined.guarded_advisory_claim_count}; unmatched: {combined.unmatched_claim_count}; "
        f"ambiguous: {combined.ambiguous_claim_count}.",
        "Unmatched, ambiguous and guarded claims remain unvalidated; these counts do not "
        "establish a false-positive rate. Precision proxies retain all claim weights.",
        "",
    )
    if len(stability.cohorts) > 1:
        report.add(
            "> MIXED COHORTS: the combined figures are aggregate descriptive coverage, not "
            "fixed-configuration audit jitter. Do not infer variance from this mixture.",
            "",
        )
        _metrics(report, combined)
    for index, group in enumerate(stability.cohorts, 1):
        selected = next(t for t in stability.trials if t.trial_index == group.trial_indexes[0])
        _group(report, group, index)
        report.add(
            "Cohort digest: " + _inline(selected.cohort_sha256) + ".",
            "Configuration digest: " + _inline(selected.configuration_sha256) + ".",
            "",
        )
    report.add(
        "## Pairwise overlap",
        "",
        "Jaccard is shared over union observations. Empty or incomplete sets are not perfect "
        "agreement; cross-cohort pairs are not fixed-configuration comparisons.",
        "",
        "| Trials | Same cohort | Location Jaccard | Assertion Jaccard |",
        "| --- | --- | --- | --- |",
    )
    for pair in stability.pairs:
        report.add(
            f"| {pair.left_trial_index + 1}, {pair.right_trial_index + 1} | "
            f"{'yes' if pair.same_cohort else 'no'} | {_ratio(pair.location_jaccard)} | "
            f"{_ratio(pair.assertion_jaccard)} |"
        )
    report.add("", "Complete measured evidence: [stability.json](stability.json).", "")


def _truth(
    stability: DevelopmentCorpusStability | None,
    series: DevelopmentCorpusRepeatsObservation | None,
) -> DevelopmentCorpusBenchmarkTruth:
    if series is not None:
        return series.plan.benchmark.truth
    if stability is None:
        raise ValueError("candidate variance report requires retained evidence")
    source = stability.measurements[0].source_score
    if isinstance(source, DevelopmentCorpusBenchmarkScore):
        return source.binding.truth
    original = source.history.original_score
    if original is None:
        raise ValueError("candidate variance report requires original declared labels")
    return original.binding.truth


def _validate_join(
    stability: DevelopmentCorpusStability | None,
    series: DevelopmentCorpusRepeatsObservation | None,
) -> None:
    if series is None:
        if stability is None:
            raise ValueError("candidate variance report requires retained evidence")
        return
    available = series.measurement_scope == "ALL_PREDECLARED_TRIAL_RESULTS_RETAINED"
    if available != (stability is not None):
        raise ValueError("candidate variance measurement differs from complete series availability")
    if stability is None:
        return
    if len(stability.measurements) != series.plan.trial_count:
        raise ValueError("candidate variance report loses a predeclared trial")
    for measurement, slot in zip(stability.measurements, series.trials, strict=True):
        source = measurement.source_score
        if (
            not isinstance(source, DevelopmentCorpusBenchmarkScore)
            or source.observation != slot.observation
            or source.binding.truth_file_content != series.plan.benchmark.truth_file_content
            or source.binding.truth_file_sha256 != series.plan.benchmark.truth_file_sha256
        ):
            raise ValueError("candidate variance report changes original trial or label evidence")


def render_development_stability_report(
    *,
    stability: DevelopmentCorpusStability | None = None,
    series: DevelopmentCorpusRepeatsObservation | None = None,
) -> str:
    """Revalidate complete source artifacts and joins before emitting any descriptive report."""

    if stability is not None:
        if type(stability) is not DevelopmentCorpusStability:
            raise ValueError("candidate variance report requires an exact stability artifact")
        stability = read_development_corpus_stability(stability.model_dump_json().encode())
    if series is not None:
        if type(series) is not DevelopmentCorpusRepeatsObservation:
            raise ValueError("candidate variance report requires an exact repeat artifact")
        series = read_development_corpus_repeats(series.model_dump_json().encode())
    _validate_join(stability, series)
    truth = _truth(stability, series)
    report = _Report()
    report.add(
        "# Candidate variance report — not an audit",
        "",
        "Report version: 1. Role measured: CANDIDATE. Other audit roles: NOT MEASURED.",
        "",
        "These are descriptive retained source-location and model-assertion observations, not "
        "validated findings, qualified recall/precision, or proof of complete security.",
        "",
        "Trial independence, root independence and predictive stability: NOT ESTABLISHED. "
        "The selected frequencies do not predict detection in a future audit. Stable here "
        "means observed in all selected trials, not deterministic or guaranteed detection.",
        "",
        "Trial numbers in this report are one-based; JSON trial indexes are zero-based. "
        "Missing observations remain in the selected denominator. Empty sets are not "
        "perfect agreement.",
        "",
        "Declared label set: " + _inline(truth.truth_id) + ".",
        "Declared provenance: " + _inline(truth.provenance) + ".",
        "Declared-label scope: " + _inline(truth.truth_scope) + ".",
        "A label declaration or hash is not verified external/exhaustive ground truth. "
        "Artifact digests below identify semantic artifacts, not file-byte checksums, "
        "signatures or externally anchored seals.",
        "",
    )
    if series is not None:
        _series(report, series)
    if stability is not None:
        if series is None:
            _costs(
                report,
                accounted=stability.accounted_cost_usd,
                actual=stability.reported_actual_cost_usd,
                uncertain=stability.uncertain_accounted_cost_usd,
                reserved=stability.active_reserved_usd,
                seconds=stability.sum_recorded_run_elapsed_seconds,
            )
        _measured(report, stability)
    else:
        report.add(
            "## Measurement unavailable",
            "",
            "A whole planned trial result is missing or evidence identities were reused. "
            "No successful-only subset is presented as the series. Stability, coverage and "
            "precision measurements are unavailable; missing data is not a pass or a "
            "zero-finding audit. See every planned slot and retained liability above.",
            "",
        )
    report.add(
        "## Assurance boundary",
        "",
        "findings_validated=false; audit_complete=false; qualification_eligible=false; "
        "release_eligible=false.",
        "",
        "Actual audit/per-role integration, independently grounded truth and predictive client "
        "variance remain unproved. This private derivative grants no qualification, release "
        "or publication authority.",
    )
    return report.finish()
