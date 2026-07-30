from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.refresh_staging as refresh_staging_module
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    ModelRefreshFailureCode,
    SelectedModelRoute,
    diff_model_refresh,
    evaluate_model_refresh_freshness,
    seal_model_refresh_attempt,
    write_model_refresh_failure,
    write_model_refresh_success,
)
from mmaudit.models.refresh_staging import (
    WORKFLOW_STATUS_FILENAME,
    ModelRefreshStagingError,
    ModelRefreshWorkflowDisposition,
    load_model_refresh_workflow_status,
    stage_model_refresh_evidence,
)
from scripts.stage_model_refresh_artifacts import main as stage_script_main
from tests.unit.test_model_refresh import (
    ENDPOINT,
    MODEL,
    NOW,
    _endpoint,
    _registry,
    _snapshot,
)

SOURCE_COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[2]
SUCCESS_NAMES = {
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
) -> tuple[Any, tuple[SelectedModelRoute, ...]]:
    registry = _registry()
    retrieved_at = NOW if previous is None else NOW + timedelta(hours=1)
    selected = (
        (SelectedModelRoute(exact_model_id=MODEL, provider_endpoint=ENDPOINT),) if blocked else ()
    )
    snapshot = _snapshot(
        registry,
        retrieved_at=retrieved_at,
        zdr_endpoints=[_endpoint()],
        candidate_endpoints={MODEL: [_endpoint()] if not blocked else []},
    )
    diff = diff_model_refresh(
        current=snapshot,
        previous=previous,
        candidate_registry=registry,
        pricing_tolerance_fraction="0.05",
        compared_at=retrieved_at,
        selected_routes=selected,
    )
    attempt = seal_model_refresh_attempt(
        attempted_at=retrieved_at,
        candidate_registry_sha256=registry.registry_sha256,
        snapshot=snapshot,
        diff=diff,
    )
    freshness = evaluate_model_refresh_freshness(
        observed_at=retrieved_at,
        snapshot=snapshot,
        soft_max_age_hours=30,
        hard_max_age_hours=72,
        production_selection_present=bool(selected),
    )
    write_model_refresh_success(
        output,
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
    selected: tuple[SelectedModelRoute, ...] = (),
    pricing_tolerance_fraction: str = "0.05",
    soft_max_age_hours: int = 30,
    hard_max_age_hours: int = 72,
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
        expected_selected_routes=selected,
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
    assert {path.name for path in staging.iterdir()} == SUCCESS_NAMES
    assert staging.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in staging.iterdir())
    assert load_model_refresh_workflow_status(staging / WORKFLOW_STATUS_FILENAME) == status
    serialized = "".join(path.read_text(encoding="utf-8") for path in staging.iterdir())
    assert canary not in serialized
    assert all(binding.content_sha256 for binding in status.artifacts)
    assert all(binding.artifact_sha256 for binding in status.artifacts)


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
    output = tmp_path / "output"
    _registry_again, selected = _write_success_bundle(output, previous=previous)

    with pytest.raises(ModelRefreshStagingError, match="baseline is unavailable"):
        _stage(
            output=output,
            staging=tmp_path / "missing-prior",
            registry=registry,
            exit_status=0,
            selected=selected,
        )
    status = _stage(
        output=output,
        staging=tmp_path / "with-prior",
        registry=registry,
        exit_status=0,
        previous=previous,
        selected=selected,
    )
    assert status.disposition is ModelRefreshWorkflowDisposition.COMPLETED


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
    snapshot = _snapshot(registry)
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
