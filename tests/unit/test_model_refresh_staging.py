from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.models.refresh_staging as refresh_staging_module
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshFailureCode,
    SelectedModelRoute,
    build_model_refresh_snapshot_from_source,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    load_model_refresh_attempt,
    load_model_refresh_diff,
    load_model_refresh_freshness,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
    seal_model_refresh_attempt,
    write_model_refresh_failure,
    write_model_refresh_success,
)
from mmaudit.models.refresh_staging import (
    WORKFLOW_STATUS_FILENAME,
    ModelRefreshStagingError,
    ModelRefreshWorkflowDisposition,
    ModelRefreshWorkflowStatus,
    load_model_refresh_workflow_status,
    stage_model_refresh_evidence,
)
from mmaudit.reporting.json_report import stable_json
from scripts.stage_model_refresh_artifacts import main as stage_script_main
from tests.unit.test_model_refresh import (
    ENDPOINT,
    MODEL,
    NOW,
    _endpoint,
    _registry,
    _reseal_catalog_model,
    _sha,
    _snapshot,
    _source,
)

SOURCE_COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[2]
SUCCESS_NAMES = {
    SOURCE_EVIDENCE_FILENAME,
    SNAPSHOT_FILENAME,
    DIFF_FILENAME,
    ATTEMPT_FILENAME,
    FRESHNESS_FILENAME,
    WORKFLOW_STATUS_FILENAME,
}


def _write_success_bundle(
    output: Path,
    *,
    previous: Any | None = None,
    blocked: bool = False,
    retrieved_at: datetime | None = None,
) -> tuple[Any, tuple[SelectedModelRoute, ...]]:
    registry = _registry()
    observed_at = (
        retrieved_at
        if retrieved_at is not None
        else (NOW if previous is None else NOW + timedelta(hours=1))
    )
    selected = (
        (SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),) if blocked else ()
    )
    source = _source(
        registry,
        retrieved_at=observed_at,
        zdr_endpoints=[_endpoint()],
        candidate_endpoints={MODEL: [_endpoint()] if not blocked else []},
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    diff = diff_model_refresh(
        current=snapshot,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=observed_at,
        selected_routes=selected,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=observed_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=observed_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=bool(selected),
    )
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
    )
    return registry, selected


def _stage(
    *,
    output: Path,
    staging: Path,
    registry: Any,
    exit_status: int,
    previous: Any | None = None,
    previous_source: Any | None = None,
    selected: tuple[SelectedModelRoute, ...] = (),
    pricing_tolerance_fraction: str = "0.05",
    soft_max_age_hours: int = 30,
    hard_max_age_hours: int = 72,
    validation_observed_at: Any = NOW + timedelta(hours=1),
):
    return stage_model_refresh_evidence(
        output_dir=output,
        staging_dir=staging,
        candidate_registry=registry,
        refresh_exit_status=exit_status,
        source_commit=SOURCE_COMMIT,
        workflow_run_id="123",
        workflow_run_attempt="1",
        pricing_tolerance_fraction=pricing_tolerance_fraction,
        soft_max_age_hours=soft_max_age_hours,
        hard_max_age_hours=hard_max_age_hours,
        previous_snapshot=previous,
        previous_source_evidence=previous_source,
        expected_selected_routes=selected,
        _validation_observed_at=validation_observed_at,
    )


def test_success_bundle_is_revalidated_reconstructed_and_commit_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-staging-secret-canary"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)

    status = _stage(
        output=output,
        staging=staging,
        registry=registry,
        exit_status=0,
        selected=selected,
    )

    assert status.disposition is ModelRefreshWorkflowDisposition.COMPLETED
    assert status.source_commit == SOURCE_COMMIT
    assert status.candidate_registry_sha256 == registry.registry_sha256
    assert status.pricing_tolerance_fraction == "0.05"
    assert status.soft_max_age_hours == 30
    assert status.hard_max_age_hours == 72
    assert status.validated_at == NOW + timedelta(hours=1)
    assert {path.name for path in staging.iterdir()} == SUCCESS_NAMES
    assert staging.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in staging.iterdir())
    assert load_model_refresh_workflow_status(staging / WORKFLOW_STATUS_FILENAME) == status
    serialized = "".join(path.read_text(encoding="utf-8") for path in staging.iterdir())
    assert canary not in serialized
    assert all(binding.content_sha256 for binding in status.artifacts)
    assert all(binding.artifact_sha256 for binding in status.artifacts)
    expected_self_hashes = {
        SOURCE_EVIDENCE_FILENAME: load_model_refresh_source_evidence(
            output / SOURCE_EVIDENCE_FILENAME
        ).source_evidence_sha256,
        SNAPSHOT_FILENAME: load_model_refresh_snapshot(output / SNAPSHOT_FILENAME).snapshot_sha256,
        DIFF_FILENAME: load_model_refresh_diff(output / DIFF_FILENAME).diff_sha256,
        ATTEMPT_FILENAME: load_model_refresh_attempt(output / ATTEMPT_FILENAME).attempt_sha256,
        FRESHNESS_FILENAME: load_model_refresh_freshness(
            output / FRESHNESS_FILENAME
        ).freshness_sha256,
    }
    assert {
        binding.filename: binding.artifact_sha256 for binding in status.artifacts
    } == expected_self_hashes

    legacy_payload = status.model_dump(mode="json")
    legacy_payload["schema_version"] = "1.0"
    legacy_payload["workflow_status_sha256"] = _sha(
        {key: value for key, value in legacy_payload.items() if key != "workflow_status_sha256"}
    )
    with pytest.raises(ValidationError, match=r"2\.0"):
        ModelRefreshWorkflowStatus.model_validate(legacy_payload)


def test_production_blocked_bundle_requires_exit_six_and_expected_routes(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    registry, selected = _write_success_bundle(output, blocked=True)

    status = _stage(
        output=output,
        staging=tmp_path / "staging",
        registry=registry,
        exit_status=6,
        selected=selected,
    )

    assert status.disposition is ModelRefreshWorkflowDisposition.PRODUCTION_BLOCKED
    assert status.refresh_exit_status == 6
    with pytest.raises(ModelRefreshStagingError, match="blocking attempt"):
        _stage(
            output=output,
            staging=tmp_path / "wrong-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
        )


def test_typed_provider_failure_and_missing_prerequisite_have_exact_inventories(
    tmp_path: Path,
) -> None:
    registry = _registry()
    failed = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        failure_code=ModelRefreshFailureCode.AUTHENTICATION,
    )
    output = tmp_path / "failed"
    write_model_refresh_failure(output, attempt=failed)

    failure_status = _stage(
        output=output,
        staging=tmp_path / "failure-staging",
        registry=registry,
        exit_status=4,
    )
    assert failure_status.disposition is ModelRefreshWorkflowDisposition.FAILED
    assert failure_status.artifacts[0].artifact_sha256 == failed.attempt_sha256
    assert {path.name for path in (tmp_path / "failure-staging").iterdir()} == {
        ATTEMPT_FILENAME,
        WORKFLOW_STATUS_FILENAME,
    }

    prerequisite_status = _stage(
        output=tmp_path / "absent-output",
        staging=tmp_path / "prerequisite-staging",
        registry=registry,
        exit_status=78,
    )
    assert prerequisite_status.disposition is ModelRefreshWorkflowDisposition.PREREQUISITE_MISSING
    assert [path.name for path in (tmp_path / "prerequisite-staging").iterdir()] == [
        WORKFLOW_STATUS_FILENAME
    ]


def test_previous_snapshot_baseline_must_be_supplied_and_hash_bound(tmp_path: Path) -> None:
    registry = _registry()
    previous = _snapshot(registry)
    previous_source = _source(registry)
    output = tmp_path / "output"
    _registry_again, selected = _write_success_bundle(output, previous=previous)

    with pytest.raises(ModelRefreshStagingError, match="baseline or source is unavailable"):
        _stage(
            output=output,
            staging=tmp_path / "missing-prior",
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    with pytest.raises(ModelRefreshStagingError, match="must be supplied together"):
        _stage(
            output=output,
            staging=tmp_path / "unpaired-prior",
            registry=registry,
            exit_status=0,
            previous=previous,
            selected=selected,
        )
    status = _stage(
        output=output,
        staging=tmp_path / "with-prior",
        registry=registry,
        exit_status=0,
        previous=previous,
        previous_source=previous_source,
        selected=selected,
    )
    assert status.disposition is ModelRefreshWorkflowDisposition.COMPLETED


def test_resealed_previous_snapshot_requires_matching_source_replay(
    tmp_path: Path,
) -> None:
    registry = _registry()
    previous_source = _source(registry)
    previous = build_model_refresh_snapshot_from_source(
        source_evidence=previous_source,
        candidate_registry=registry,
    )
    payload = previous.model_dump(mode="json")
    payload["source_evidence_sha256"] = "f" * 64
    payload["snapshot_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "snapshot_sha256"}
    )
    forged_previous = type(previous).model_validate(payload)
    output = tmp_path / "output"
    _write_success_bundle(output, previous=forged_previous)

    with pytest.raises(ModelRefreshStagingError, match="baseline binding is invalid"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            previous=forged_previous,
            previous_source=previous_source,
        )


@pytest.mark.parametrize(
    ("tolerance", "soft_age", "hard_age"),
    [
        ("0.99", 30, 72),
        ("0.05", 1, 2),
    ],
)
def test_staging_rejects_workflow_policy_mismatch(
    tmp_path: Path,
    tolerance: str,
    soft_age: int,
    hard_age: int,
) -> None:
    output = tmp_path / "output"
    registry, selected = _write_success_bundle(output)

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            pricing_tolerance_fraction=tolerance,
            soft_max_age_hours=soft_age,
            hard_max_age_hours=hard_age,
        )


def test_staging_rejects_a_self_consistent_hard_expired_success_bundle(
    tmp_path: Path,
) -> None:
    registry = _registry()
    source = _source(registry)
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    diff = diff_model_refresh(
        current=snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=NOW,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=NOW,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=NOW + timedelta(hours=73),
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    output = tmp_path / "output"
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=diff,
        attempt=attempt,
        freshness=freshness,
    )

    with pytest.raises(ModelRefreshStagingError, match="not current"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
        )


def test_staging_uses_its_own_clock_to_reject_future_and_stale_bundles(
    tmp_path: Path,
) -> None:
    future_output = tmp_path / "future-output"
    future_at = datetime(2099, 1, 1, tzinfo=UTC)
    registry, selected = _write_success_bundle(
        future_output,
        retrieved_at=future_at,
    )
    with pytest.raises(ModelRefreshStagingError, match="future-dated"):
        _stage(
            output=future_output,
            staging=tmp_path / "future-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW,
        )

    stale_output = tmp_path / "stale-output"
    registry, selected = _write_success_bundle(stale_output, retrieved_at=NOW)
    with pytest.raises(ModelRefreshStagingError, match="not current at staging time"):
        _stage(
            output=stale_output,
            staging=tmp_path / "stale-staging",
            registry=registry,
            exit_status=0,
            selected=selected,
            validation_observed_at=NOW + timedelta(hours=31),
        )


def test_staging_rejects_a_resealed_semantically_false_diff(tmp_path: Path) -> None:
    registry = _registry()
    previous = _snapshot(registry)
    parameters = ["max_tokens", "reasoning", "response_format", "seed", "temperature"]
    endpoint = _endpoint(parameters=parameters)
    observed_at = NOW + timedelta(hours=1)
    # Build the changed live snapshot from provider-shaped inputs rather than
    # reusing normalized evidence as untrusted metadata.
    source = _source(
        registry,
        retrieved_at=observed_at,
        models=[
            {
                "id": MODEL,
                "canonical_slug": MODEL,
                "context_length": 100_000,
                "top_provider": {
                    "context_length": 100_000,
                    "max_completion_tokens": 8_192,
                },
                "supported_parameters": parameters,
            }
        ],
        zdr_endpoints=[endpoint],
        candidate_endpoints={MODEL: [endpoint]},
    )
    snapshot = build_model_refresh_snapshot_from_source(
        source_evidence=source,
        candidate_registry=registry,
    )
    actual = diff_model_refresh(
        current=snapshot,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=observed_at,
    )
    assert actual.changes
    payload = actual.model_dump(mode="json")
    payload["changes"] = []
    payload["semantic_unchanged"] = True
    payload["status"] = "UNCHANGED"
    payload["production_block_reasons"] = []
    payload["diff_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "diff_sha256"}
    )
    forged = type(actual).model_validate(payload)
    attempt = seal_model_refresh_attempt(
        attempted_at=observed_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=forged,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=observed_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    output = tmp_path / "output"
    write_model_refresh_success(
        output,
        source_evidence=source,
        snapshot=snapshot,
        diff=forged,
        attempt=attempt,
        freshness=freshness,
    )

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic diff"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            previous=previous,
            previous_source=_source(registry),
        )


def test_staging_rejects_a_fully_resealed_snapshot_without_source_support(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    registry, _selected = _write_success_bundle(output)
    snapshot = load_model_refresh_snapshot(output / SNAPSHOT_FILENAME)
    payload = snapshot.model_dump(mode="json")
    payload["models"][0]["catalog_context_limit"] -= 1
    payload["models"][0] = _reseal_catalog_model(payload["models"][0])
    payload["semantic_sha256"] = _sha(payload["models"])
    payload["snapshot_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "snapshot_sha256"}
    )
    forged_snapshot = type(snapshot).model_validate(payload)
    forged_diff = diff_model_refresh(
        current=forged_snapshot,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=forged_snapshot.retrieved_at,
    )
    forged_attempt = seal_model_refresh_attempt(
        attempted_at=forged_snapshot.retrieved_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=forged_snapshot,
        diff=forged_diff,
    )
    forged_freshness = evaluate_model_refresh_freshness(
        observed_at=forged_snapshot.retrieved_at,
        snapshot=forged_snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=False,
    )
    for filename, artifact in (
        (SNAPSHOT_FILENAME, forged_snapshot),
        (DIFF_FILENAME, forged_diff),
        (ATTEMPT_FILENAME, forged_attempt),
        (FRESHNESS_FILENAME, forged_freshness),
    ):
        (output / filename).write_text(stable_json(artifact), encoding="utf-8")

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic snapshot"):
        _stage(
            output=output,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
        )


def test_staging_rejects_a_cross_run_source_evidence_swap(tmp_path: Path) -> None:
    first = tmp_path / "first"
    registry, selected = _write_success_bundle(first)
    previous = _snapshot(registry)
    second = tmp_path / "second"
    _write_success_bundle(second, previous=previous)
    (first / SOURCE_EVIDENCE_FILENAME).write_bytes((second / SOURCE_EVIDENCE_FILENAME).read_bytes())
    (first / SOURCE_EVIDENCE_FILENAME).chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="reproduced semantic snapshot"):
        _stage(
            output=first,
            staging=tmp_path / "staging",
            registry=registry,
            exit_status=0,
            selected=selected,
        )


@pytest.mark.parametrize("mutation", ["extra", "mode", "hardlink", "tamper"])
def test_unsafe_or_tampered_source_inventory_is_rejected_without_staging(
    tmp_path: Path,
    mutation: str,
) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)
    attempt = output / ATTEMPT_FILENAME
    if mutation == "extra":
        extra = output / "unexpected.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
    elif mutation == "mode":
        attempt.chmod(0o644)
    elif mutation == "hardlink":
        outside = tmp_path / "shared-attempt.json"
        try:
            os.link(attempt, outside)
        except OSError:
            pytest.skip("hardlinks unavailable")
    else:
        attempt.write_text(attempt.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises((ModelRefreshStagingError, ValueError)):
        _stage(
            output=output,
            staging=staging,
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    assert not staging.exists()


def test_cross_hash_exit_identity_and_reused_destination_fail_closed(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    registry, selected = _write_success_bundle(first)
    second = tmp_path / "second"
    previous = _snapshot(registry)
    _write_success_bundle(second, previous=previous)
    (first / ATTEMPT_FILENAME).write_bytes((second / ATTEMPT_FILENAME).read_bytes())
    (first / ATTEMPT_FILENAME).chmod(0o600)

    with pytest.raises(ModelRefreshStagingError, match="hash bindings"):
        _stage(
            output=first,
            staging=tmp_path / "cross-hash",
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    with pytest.raises(ModelRefreshStagingError, match="accepted workflow"):
        _stage(
            output=first,
            staging=tmp_path / "unknown-exit",
            registry=registry,
            exit_status=70,
            selected=selected,
        )

    clean = tmp_path / "clean"
    registry, selected = _write_success_bundle(clean)
    reused = tmp_path / "reused"
    reused.mkdir(mode=0o700)
    with pytest.raises(ModelRefreshStagingError, match="must be fresh"):
        _stage(
            output=clean,
            staging=reused,
            registry=registry,
            exit_status=0,
            selected=selected,
        )


def test_invalid_workflow_identity_removes_partial_staging(tmp_path: Path) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)

    with pytest.raises(ModelRefreshStagingError, match="workflow identity"):
        stage_model_refresh_evidence(
            output_dir=output,
            staging_dir=staging,
            candidate_registry=registry,
            refresh_exit_status=0,
            source_commit="not-a-commit",
            workflow_run_id="123",
            workflow_run_attempt="1",
            pricing_tolerance_fraction="0.05",
            soft_max_age_hours=30,
            hard_max_age_hours=72,
            expected_selected_routes=selected,
        )
    assert not staging.exists()


def test_final_inventory_injection_quarantines_the_upload_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    staging = tmp_path / "staging"
    registry, selected = _write_success_bundle(output)
    original_write = refresh_staging_module.write_json_evidence

    def inject_after_status(**kwargs: Any) -> Any:
        result = original_write(**kwargs)
        if kwargs["relative_path"] == WORKFLOW_STATUS_FILENAME:
            injected = Path(kwargs["evidence_root"]) / "injected.txt"
            injected.write_text("untrusted\n", encoding="utf-8")
            injected.chmod(0o600)
        return result

    monkeypatch.setattr(
        refresh_staging_module,
        "write_json_evidence",
        inject_after_status,
    )
    with pytest.raises(ModelRefreshStagingError, match="inventory"):
        _stage(
            output=output,
            staging=staging,
            registry=registry,
            exit_status=0,
            selected=selected,
        )

    assert not staging.exists()
    assert list(tmp_path.glob(".staging.rejected-*"))


def test_staging_script_executes_prerequisite_and_rejects_unknown_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    common = [
        "--output-dir",
        str(tmp_path / "absent-output"),
        "--candidate-registry",
        str(ROOT / "config" / "models.candidates.toml"),
        "--source-commit",
        SOURCE_COMMIT,
        "--workflow-run-id",
        "123",
        "--workflow-run-attempt",
        "1",
        "--pricing-tolerance-fraction",
        "0.05",
        "--soft-max-age-hours",
        "30",
        "--hard-max-age-hours",
        "72",
    ]
    staged = tmp_path / "staged"

    assert (
        stage_script_main(
            [
                *common,
                "--staging-dir",
                str(staged),
                "--refresh-exit-status",
                "78",
            ]
        )
        == 0
    )
    assert load_model_refresh_workflow_status(staged / WORKFLOW_STATUS_FILENAME)
    assert "PREREQUISITE_MISSING" in capsys.readouterr().out

    rejected = tmp_path / "rejected"
    assert (
        stage_script_main(
            [
                *common,
                "--staging-dir",
                str(rejected),
                "--refresh-exit-status",
                "70",
            ]
        )
        == 74
    )
    assert not rejected.exists()
    assert capsys.readouterr().out == "model-refresh artifact staging failed\n"
