"""Actual maximum-width retained file ingestion; constructed inputs do not prove real audit quality."""

from __future__ import annotations

import hashlib
import socket
import stat
import subprocess
from decimal import Decimal

import pytest

import mmaudit.development_cli as cli
from mmaudit.benchmark.development_corpus_stability import (
    DevelopmentStabilitySelection,
    read_development_corpus_stability,
)
from mmaudit.orchestration.development_corpus_stability import (
    measure_development_corpus_stability_files,
)
from mmaudit.orchestration.manifest import ManifestFileBinding
from tests.development_corpus_stability_scale_support import maximum_stability_score
from tests.development_corpus_stability_support import trial


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("maximum stability touched credentials, network or a subprocess")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "load_operator_secrets", forbidden)


@pytest.mark.parametrize("kind", ["same", "mixed", "incomplete", "cumulative"])
def test_eight_full_source_trials_keep_maximum_scope_weights_cohorts_and_liabilities(
    tmp_path, kind
):
    selected = tmp_path / "retained"
    selected.mkdir(mode=0o700)
    measurements, bindings = [], []
    for index in range(8):
        value = trial(
            f"synthetic-maximum-trial-{index}",
            score=maximum_stability_score(
                complete=not (kind == "incomplete" and index == 7),
                cumulative=kind == "cumulative",
                request_timeout_seconds=90 + index if kind == "mixed" else None,
            ),
        )
        raw = value.model_dump_json().encode()
        path = selected / f"trial-{index}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        measurements.append(value)
        bindings.append(
            ManifestFileBinding(
                path=path.name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()
            )
        )
    selection = DevelopmentStabilitySelection(measurements=tuple(bindings))
    selection_file = selected / "selection.json"
    selection_raw = selection.model_dump_json().encode()
    selection_file.write_bytes(selection_raw)
    selection_file.chmod(0o600)
    assert sum(binding.size for binding in bindings) <= 128_000_000
    output = tmp_path / "result"
    result = measure_development_corpus_stability_files(
        selection_file=selection_file, output_dir=output
    )
    artifact = output / "stability.json"
    content = artifact.read_bytes()
    assert len(content) <= 192_000_000
    assert read_development_corpus_stability(content) == result
    assert result.measurements == tuple(measurements)
    assert selection_file.read_bytes() == selection_raw
    for binding in bindings:
        raw = (selected / binding.path).read_bytes()
        assert len(raw) == binding.size and hashlib.sha256(raw).hexdigest() == binding.sha256
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert len(result.trials) == 8 and len(result.pairs) == 28
    assert len(result.combined.controls) == 1024
    assert result.combined.trial_indexes == tuple(range(8))
    assert len(result.cohorts) == (8 if kind == "mixed" else 1)
    assert all(pair.same_cohort == (kind != "mixed") for pair in result.pairs)
    assert len({run for t in result.trials for run in t.run_ids}) == (
        72 if kind == "cumulative" else 8
    )
    assert result.trial_independence == result.root_independence == "NOT_ESTABLISHED"
    assert result.predictive_stability == "NOT_ESTABLISHED"
    assert result.role_scope == "CANDIDATE_ONLY_OTHER_AUDIT_ROLES_NOT_MEASURED"
    assert not any(
        (
            result.findings_validated,
            result.audit_complete,
            result.qualification_eligible,
            result.release_eligible,
        )
    )
    if kind == "cumulative":
        assert result.combined.total_claim_count == 0
        assert all(t.selected_request_count == 576 for t in result.trials)
        assert sum(len(t.unknown_actual_cost_request_ids) for t in result.trials) == 64
        assert sum(len(t.missing_accounting_request_ids) for t in result.trials) == 4544
        assert sum(len(t.missing_runtime_request_ids) for t in result.trials) == 4544
        assert result.reported_actual_cost_usd == 0 and result.uncertain_accounted_cost_usd > 0
        assert result.accounted_cost_usd == result.uncertain_accounted_cost_usd
        assert result.sum_recorded_run_elapsed_seconds == 72
        assert result.combined.union_location_coverage.value is None
        assert result.combined.pooled_per_trial_assertion_precision.value is None
        assert all(
            c.assertion.unobserved_trial_indexes == tuple(range(8))
            for c in result.combined.controls
        )
        assert all(c.assertion.frequency.denominator == 8 for c in result.combined.controls)
        assert all(pair.assertion_jaccard.value is None for pair in result.pairs)
        assert result.combined.comparison_scope == (
            "SAME_REQUEST_CONFIGURATION_CONTINUATION_CHAINS_NOT_SINGLE_PASSES"
        )
    else:
        claims = 8176 if kind == "incomplete" else 8192
        assert result.combined.total_claim_count == claims
        assert all(t.selected_request_count == 64 for t in result.trials)
        assert (
            result.accounted_cost_usd
            == result.reported_actual_cost_usd
            == (Decimal("5.11") if kind == "incomplete" else Decimal("5.12"))
        )
        assert result.uncertain_accounted_cost_usd == 0
        assert result.sum_recorded_run_elapsed_seconds == 8
        assert result.combined.pooled_per_trial_assertion_precision.denominator == claims * 10
        assert result.combined.pooled_per_trial_assertion_precision.numerator == claims * 10
        critical = next(group for group in result.combined.severity if group.severity == "critical")
        assert len(critical.asserted_union_root_ids) == 1024
        assert result.combined.union_assertion_coverage.denominator == 1024
        if kind == "incomplete":
            assert result.combined.union_assertion_coverage.value is None
            assert len(result.trials[-1].missing_accounting_request_ids) == 1
            assert len(result.trials[-1].missing_runtime_request_ids) == 1
            unknown = [c for c in result.combined.controls if c.assertion.unobserved_trial_indexes]
            assert len(unknown) == 16
            assert all(c.assertion.positive_trial_indexes == tuple(range(7)) for c in unknown)
            assert all(c.assertion.unobserved_trial_indexes == (7,) for c in unknown)
            assert all(c.assertion.frequency.denominator == 8 for c in unknown)
            assert all(c.assertion.frequency.value is None for c in unknown)
        else:
            assert result.combined.union_assertion_coverage.value == 1
            assert result.combined.pooled_per_trial_assertion_precision.value == 1
            assert all(c.assertion.classification == "STABLE" for c in result.combined.controls)
            assert all(pair.assertion_jaccard.value == 1 for pair in result.pairs)
        assert result.combined.population_variance_selected_run_assertion_coverage == (
            0 if kind == "same" else None
        )
        assert result.combined.mean_selected_run_assertion_coverage == (
            1 if kind == "same" else None
        )
