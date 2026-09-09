"""Descriptive report controls retain missing scope, declared labels and unvalidated claims."""

import socket
import subprocess
from decimal import Decimal

import pytest

import mmaudit.reporting.development_stability as reporting
from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_stability import measure_development_corpus_stability
from mmaudit.orchestration.development_corpus_repeats import _report
from tests.development_corpus_benchmark_support import paired_observation
from tests.development_corpus_control_measurement_support import direct_responses
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_repeats_support import repeat_case
from tests.development_corpus_stability_support import trial
from tests.development_review_support import local_controls
from tests.unit.test_development_corpus_stability import evaluate, responses


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("candidate report attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize(
    "pattern,classification,present,absent",
    [
        ((True, True, True), "STABLE", "1, 2, 3", "none"),
        ((True, False, True), "INTERMITTENT", "1, 3", "2"),
        ((False, False, True), "SINGLE_RUN", "3", "1, 2"),
        ((False, False, False), "NEVER", "none", "1, 2, 3"),
    ],
)
def test_report_retains_every_frequency_severity_and_nonqualification_boundary(
    pattern, classification, present, absent
):
    measured = evaluate(pattern)
    before = measured.model_dump_json()
    text = reporting.render_development_stability_report(stability=measured)
    assert text == reporting.render_development_stability_report(stability=measured)
    assert measured.model_dump_json() == before
    assert text.startswith("# Candidate variance report — not an audit\n")
    assert text.endswith("\n") and measured.stability_sha256 in text
    assert "Role measured: CANDIDATE. Other audit roles: NOT MEASURED." in text
    assert "not validated recall" in text and "precision proxy" in text
    assert "do not predict detection in a future audit" in text
    assert "not file-byte checksums" in text and "NOT ESTABLISHED" in text
    assert "AGENT_CONSTRUCTED_DEVELOPMENT_CONTROLS" in text
    assert "DECLARED_LABELS_NOT_VERIFIED_EXTERNAL_OR_EXHAUSTIVE_GROUND_TRUTH" in text
    for control in measured.combined.controls:
        assert f"| `{control.control_id}` | {control.expected} | {control.severity.value} |" in text
        assert f"`{classification}`; {sum(pattern)}/3" in text
        assert f"present: {present}; observed absence: {absent}; unavailable: none" in text
    assert ("HIGH/CRITICAL VARIATION" in text) == (classification in {"INTERMITTENT", "SINGLE_RUN"})
    assert "| 1, 2 | yes |" in text and "| 2, 3 | yes |" in text
    assert "findings_validated=false; audit_complete=false" in text
    assert "qualification_eligible=false; release_eligible=false" in text


def test_report_separates_location_advisory_assertion_and_guarded_claims():
    measured = evaluate((True, True, False), advisory=(0,))
    text = reporting.render_development_stability_report(stability=measured)
    root = next(c for c in measured.combined.controls if c.expected == "PLANTED")
    line = next(line for line in text.splitlines() if line.startswith(f"| `{root.control_id}` |"))
    assert "`INTERMITTENT`; 2/3" in line and "`SINGLE_RUN`; 1/3" in line
    assert "guarded invariant assertions: 1; guarded advisories: 1" in text
    assert "not automatically false positives" in text
    assert "All retained claims: 4" in text


def test_missing_observation_denominators_are_not_known_misses_or_zero_quality():
    measured = measure_development_corpus_stability(
        measurements=(
            trial("synthetic-complete"),
            trial("synthetic-missing", complete=False, responses=responses(False)),
        )
    )
    text = reporting.render_development_stability_report(stability=measured)
    assert "INCOMPLETE_OBSERVATIONS" in text
    assert "unavailable (INCOMPLETE\\_SCOPE)" in text
    assert "HIGH/CRITICAL OBSERVATION GAPS" in text
    assert "observed absence: none; unavailable: 2" in text
    assert "| Location-coverage population variance | unavailable |" in text
    assert "| 2 | 1 | `ORIGINAL_FIRST_ATTEMPT` | `MOCK_HTTP` | 6 | 5 | 5 |" in text


def test_empty_overlap_and_precision_are_unavailable_not_perfect_agreement():
    text = reporting.render_development_stability_report(stability=evaluate((False, False)))
    assert "0/0 — unavailable (EMPTY\\_DENOMINATOR)" in text
    assert "| 1, 2 | yes | 0/0 — unavailable" in text
    assert "Empty or incomplete sets are not perfect agreement" in text


def test_mixed_configurations_preserve_single_trial_cohorts_and_pair_scope():
    binding, observed = paired_observation(policy=selected_policy(timeout=99))
    measured = measure_development_corpus_stability(
        measurements=(
            trial("synthetic-first"),
            trial(
                "synthetic-second",
                score=score_development_corpus(binding=binding, observation=observed),
            ),
        )
    )
    text = reporting.render_development_stability_report(stability=measured)
    assert "MIXED COHORTS" in text and "Do not infer variance from this mixture" in text
    assert text.count("> NO REPEATS:") == 2
    assert "## Cohort 1:" in text and "## Cohort 2:" in text
    assert "| 1, 2 | no |" in text
    for trial_value in measured.trials:
        assert trial_value.configuration_sha256 in text and trial_value.cohort_sha256 in text


@pytest.mark.parametrize("complete", [False, True])
def test_continuation_chains_keep_all_run_ids_costs_and_uncertainty(complete):
    measured = measure_development_corpus_stability(
        measurements=tuple(
            trial(f"synthetic-chain-{i}", cumulative=True, complete=complete) for i in range(2)
        )
    )
    text = reporting.render_development_stability_report(stability=measured)
    assert "CONTINUATION CHAINS" in text and "not repeated single-pass audits" in text
    assert "CUMULATIVE_RECORDED_ATTEMPTS" in text
    for trial_value in measured.trials:
        assert all(run_id in text for run_id in trial_value.run_ids)
    assert f"| Uncertain accounted cost (USD) | {measured.uncertain_accounted_cost_usd} |" in text
    assert "Unknown charges are not zero" in text


@pytest.mark.parametrize("count", [2, 3])
def test_unstarted_series_reports_every_planned_slot_without_success_only_measurement(
    tmp_path, count
):
    prepared = repeat_case(trial_count=count)
    ledger, _ = local_controls(tmp_path)
    series = _report(prepared, ledger, [None] * count, 0, "MOCK_HTTP", "LOCAL_FAILURE", 0.0)
    text = reporting.render_development_stability_report(series=series)
    assert "## Measurement unavailable" in text and "MISSING_PLANNED_TRIAL_RESULTS" in text
    assert series.observation_sha256 in text and series.plan.plan_sha256 in text
    assert "Selected requests: " + str(count * 6) in text
    assert "missing accounting: " + str(count * 6) in text
    assert text.count("`NOT_STARTED` | 6 | 0 |") == count
    assert "[result.json](result.json)" in text and "[stability.json]" not in text
    assert "## Pairwise overlap" not in text and "precision proxy" not in text
    with pytest.raises(ValueError, match="availability"):
        reporting.render_development_stability_report(
            series=series, stability=evaluate((True, True))
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("stability_sha256", "0" * 64),
        ("audit_complete", True),
        ("accounted_cost_usd", Decimal("0")),
    ],
)
def test_forged_stability_artifacts_are_revalidated_before_rendering(field, value):
    measured = evaluate((True, False)).model_copy(update={field: value})
    with pytest.raises(ValueError):
        reporting.render_development_stability_report(stability=measured)


@pytest.mark.parametrize("value", [None, {}, "artifact", object()])
def test_missing_or_nonexact_artifacts_are_not_accepted(value):
    with pytest.raises(ValueError):
        reporting.render_development_stability_report(stability=value)


def test_report_byte_limit_counts_utf8_and_refuses_the_first_excess_byte(monkeypatch):
    measured = evaluate((True, False))
    expected = reporting.render_development_stability_report(stability=measured)
    bound = len(expected.encode())
    monkeypatch.setattr(reporting, "MAX_DEVELOPMENT_STABILITY_REPORT_BYTES", bound)
    assert reporting.render_development_stability_report(stability=measured) == expected
    monkeypatch.setattr(reporting, "MAX_DEVELOPMENT_STABILITY_REPORT_BYTES", bound - 1)
    with pytest.raises(ValueError, match="byte bound"):
        reporting.render_development_stability_report(stability=measured)


def test_provider_prose_is_not_dumped_into_the_private_report():
    selected = direct_responses()
    marker = "UNTRUSTED_PRIVATE_PROSE <script>must-not-render</script>"
    for response in selected:
        for finding in response["findings"]:
            finding["title"] = marker
    measured = measure_development_corpus_stability(
        measurements=tuple(trial(f"synthetic-prose-{i}", responses=selected) for i in range(2))
    )
    assert marker in measured.model_dump_json()
    text = reporting.render_development_stability_report(stability=measured)
    assert "UNTRUSTED_PRIVATE_PROSE" not in text and "<script>" not in text
