from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_benchmark import CandidateBenchmarkRunState
from mmaudit.models.qualification import LineageReviewStatus
from mmaudit.models.qualification_workflow import QualificationWorkflowBundle
from mmaudit.models.schemas import ExecutionEvidenceKind
from tests.qualification_support import synthetic_release_observation
from tests.unit import test_qualification_workflow as workflow_fixtures

runner = CliRunner()


def _workflow_fixture(
    *,
    lineage_status: LineageReviewStatus = LineageReviewStatus.APPROVED,
) -> dict[str, Any]:
    manifest, evidence, registry = workflow_fixtures._candidate_inputs(
        lineage_status=lineage_status
    )
    report = workflow_fixtures._as_real_report(
        asyncio.run(workflow_fixtures._mock_report()),
        candidate=registry.candidates[0],
    )
    bundle = workflow_fixtures._run(
        report=report,
        lineage_status=lineage_status,
    )
    portfolio, campaign_verification = workflow_fixtures._portfolio_evidence(
        registry=registry,
        report=report,
    )
    ready_verification = bundle.qualification_verification.model_copy(
        update={"production_selection_ready": True}
    )
    ready_bundle = bundle.model_copy(update={"qualification_verification": ready_verification})
    return {
        "manifest": manifest,
        "evidence": evidence,
        "registry": registry,
        "report": report,
        "portfolio": portfolio,
        "campaign_verification": campaign_verification,
        "policy": workflow_fixtures._policy(),
        "suite": workflow_fixtures.load_model_benchmark_corpus(workflow_fixtures.CORPUS_PATH),
        "bindings": workflow_fixtures._release_bindings(report),
        "bundle": bundle,
        "ready_bundle": ready_bundle,
    }


def _patch_external_inputs(
    monkeypatch: pytest.MonkeyPatch,
    fixture: dict[str, Any],
) -> None:
    monkeypatch.setattr(cli_module, "load_config", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_candidate_registry",
        lambda _path: fixture["registry"],
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (fixture["manifest"], fixture["evidence"]),
    )
    monkeypatch.setattr(
        cli_module,
        "load_qualification_policy",
        lambda _path: fixture["policy"],
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_corpus",
        lambda _path, *, ground_truth_path: fixture["suite"],
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_portfolio",
        lambda _path, *, candidate_registry, corpus: (
            fixture["portfolio"],
            (fixture["report"],),
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "_require_real_qualification_portfolio",
        lambda _portfolio, *, policy: None,
    )
    monkeypatch.setattr(
        cli_module,
        "load_qualification_release_bindings",
        lambda _path: fixture["bindings"],
    )
    monkeypatch.setattr(
        cli_module,
        "_verify_qualification_campaign",
        lambda **_kwargs: fixture["campaign_verification"],
    )
    monkeypatch.setattr(
        cli_module,
        "_require_qualification_release_pins",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        cli_module,
        "_observe_qualification_release",
        lambda **_kwargs: synthetic_release_observation(
            fixture["bindings"],
            observed_at=workflow_fixtures.NOW + timedelta(hours=1),
        ),
    )


def _qualify_args() -> list[str]:
    return [
        "models",
        "qualify",
        "--config",
        "config.toml",
        "--candidate-registry",
        "candidates.toml",
        "--discovery-run",
        "discovery",
        "--policy",
        "policy.toml",
        "--corpus",
        "corpus.json",
        "--ground-truth",
        "ground-truth.json",
        "--portfolio",
        "portfolio",
        "--campaign-journal",
        "campaign",
        "--cost-ledger",
        "cost-ledger.json",
        "--release-bindings",
        "release.json",
        "--release-source-root",
        "release-root",
        "--qualification-expires-at",
        "2026-08-16T12:00:00Z",
        "--output",
        "qualification.json",
        "--secrets-env-file",
        "secrets.env",
        "--no-color",
    ]


def _verify_args() -> list[str]:
    return [
        "models",
        "verify-qualification",
        "--config",
        "config.toml",
        "--bundle",
        "qualification.json",
        "--candidate-registry",
        "candidates.toml",
        "--discovery-run",
        "discovery",
        "--policy",
        "policy.toml",
        "--corpus",
        "corpus.json",
        "--ground-truth",
        "ground-truth.json",
        "--portfolio",
        "portfolio",
        "--campaign-journal",
        "campaign",
        "--cost-ledger",
        "cost-ledger.json",
        "--release-bindings",
        "release.json",
        "--release-source-root",
        "release-root",
        "--secrets-env-file",
        "secrets.env",
        "--no-color",
    ]


def _patch_refetch(
    monkeypatch: pytest.MonkeyPatch,
    captured: dict[str, object],
) -> object:
    trusted_capability = object()

    async def refetch(**kwargs: object) -> object:
        captured["refetch"] = kwargs
        return trusted_capability

    monkeypatch.setattr(cli_module, "_refetch_qualification_generations", refetch)
    return trusted_capability


def test_models_qualify_uses_atomic_portfolio_and_mocked_refetch_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _workflow_fixture()
    _patch_external_inputs(monkeypatch, fixture)
    captured: dict[str, object] = {}
    events: list[str] = []
    trusted_capability = object()

    async def refetch(**kwargs: object) -> object:
        events.append("refetch")
        captured["refetch"] = kwargs
        return trusted_capability

    monkeypatch.setattr(cli_module, "_refetch_qualification_generations", refetch)

    def observe(**_kwargs: object) -> object:
        events.append("observe")
        return synthetic_release_observation(
            fixture["bindings"],
            observed_at=workflow_fixtures.NOW + timedelta(hours=1),
        )

    monkeypatch.setattr(cli_module, "_observe_qualification_release", observe)

    def run_workflow(**kwargs: object) -> QualificationWorkflowBundle:
        events.append("workflow")
        assert kwargs["benchmark_portfolio"] == fixture["portfolio"]
        assert kwargs["benchmark_reports"] == (fixture["report"],)
        assert kwargs["trusted_campaign_verification"] is fixture["campaign_verification"]
        assert kwargs["trusted_generation_verification"] is trusted_capability
        captured["workflow_called"] = True
        return fixture["ready_bundle"]

    monkeypatch.setattr(cli_module, "run_qualification_workflow", run_workflow)
    monkeypatch.setattr(
        cli_module,
        "write_qualification_workflow_bundle",
        lambda _path, bundle: captured.update({"written": bundle}),
    )

    result = runner.invoke(cli_module.app, _qualify_args())

    assert result.exit_code == ExitCode.SUCCESS
    assert captured["workflow_called"] is True
    assert captured["written"] == fixture["ready_bundle"]
    refetch = captured["refetch"]
    assert isinstance(refetch, dict)
    assert refetch["secrets_env_file"].name == "secrets.env"
    assert events == ["refetch", "observe", "workflow"]
    assert "production_selection_ready=true" in result.output
    assert "source_excerpt" not in result.output


def test_models_qualify_persists_nonready_bundle_then_exits_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _workflow_fixture(lineage_status=LineageReviewStatus.PENDING)
    _patch_external_inputs(monkeypatch, fixture)
    _patch_refetch(monkeypatch, {})
    captured: dict[str, QualificationWorkflowBundle] = {}
    monkeypatch.setattr(
        cli_module,
        "run_qualification_workflow",
        lambda **_kwargs: fixture["bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "write_qualification_workflow_bundle",
        lambda _path, bundle: captured.update({"bundle": bundle}),
    )

    result = runner.invoke(cli_module.app, _qualify_args())

    assert result.exit_code == ExitCode.INCOMPLETE
    assert captured["bundle"] == fixture["bundle"]
    assert "production_selection_ready=false" in result.output


def test_models_verify_qualification_refetches_and_semantically_recomputes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _workflow_fixture()
    _patch_external_inputs(monkeypatch, fixture)
    captured: dict[str, object] = {}
    _patch_refetch(monkeypatch, captured)
    monkeypatch.setattr(
        cli_module,
        "load_qualification_workflow_bundle",
        lambda _path: fixture["ready_bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "run_qualification_workflow",
        lambda **_kwargs: fixture["ready_bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "verify_model_qualification",
        lambda **kwargs: (
            captured.update({"verified": kwargs})
            or fixture["ready_bundle"].qualification_verification
        ),
    )

    result = runner.invoke(cli_module.app, _verify_args())

    assert result.exit_code == ExitCode.SUCCESS
    verified = captured["verified"]
    assert isinstance(verified, dict)
    assert verified["artifact"] == fixture["ready_bundle"].qualification_artifact
    assert "workflow_sha256=" in result.output


def test_models_verify_qualification_rejects_semantic_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = _workflow_fixture()
    drifted = _workflow_fixture(lineage_status=LineageReviewStatus.PENDING)
    _patch_external_inputs(monkeypatch, frozen)
    _patch_refetch(monkeypatch, {})
    monkeypatch.setattr(
        cli_module,
        "load_qualification_workflow_bundle",
        lambda _path: frozen["bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "run_qualification_workflow",
        lambda **_kwargs: drifted["bundle"],
    )

    result = runner.invoke(cli_module.app, _verify_args())

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "authenticated semantic" in result.output
    assert "recomputation" in result.output


def test_models_verify_qualification_rejects_stale_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _workflow_fixture()
    _patch_external_inputs(monkeypatch, fixture)
    _patch_refetch(monkeypatch, {})
    monkeypatch.setattr(
        cli_module,
        "load_qualification_workflow_bundle",
        lambda _path: fixture["bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "run_qualification_workflow",
        lambda **_kwargs: fixture["bundle"],
    )
    monkeypatch.setattr(
        cli_module,
        "verify_model_qualification",
        lambda **_kwargs: fixture["bundle"].qualification_verification,
    )

    monkeypatch.setattr(
        cli_module,
        "_observe_qualification_release",
        lambda **_kwargs: synthetic_release_observation(
            fixture["bindings"],
            observed_at=datetime(2027, 1, 1, tzinfo=UTC),
        ),
    )

    result = runner.invoke(cli_module.app, _verify_args())

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "qualification bundle is stale" in result.output


@pytest.mark.parametrize(
    ("evidence", "usage_count", "diagnostics"),
    (
        (ExecutionEvidenceKind.MOCK, 1, ("complete",)),
        (ExecutionEvidenceKind.UNVERIFIED, 1, ("complete",)),
        (ExecutionEvidenceKind.REAL, 0, ("complete",)),
        (ExecutionEvidenceKind.REAL, 1, ()),
        (ExecutionEvidenceKind.REAL, 1, ("unverified_failure",)),
    ),
)
def test_qualification_rejects_unqualified_portfolio_before_refetch(
    monkeypatch: pytest.MonkeyPatch,
    evidence: ExecutionEvidenceKind,
    usage_count: int,
    diagnostics: tuple[str, ...],
) -> None:
    fixture = _workflow_fixture()
    require_real = cli_module._require_real_qualification_portfolio
    _patch_external_inputs(monkeypatch, fixture)
    monkeypatch.setattr(
        cli_module,
        "_require_real_qualification_portfolio",
        require_real,
    )
    candidate_diagnostics = tuple(
        SimpleNamespace(
            state=CandidateBenchmarkRunState(value),
            failed_request_count=0,
            unresolved_cost_count=0,
        )
        for value in diagnostics
    )
    invalid_portfolio = fixture["portfolio"].model_copy(
        update={
            "execution_evidence": evidence,
            "usage": fixture["portfolio"].usage.model_copy(
                update={"usage_record_count": usage_count}
            ),
            "diagnostics": candidate_diagnostics,
        }
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_portfolio",
        lambda *_args, **_kwargs: (invalid_portfolio, (fixture["report"],)),
    )
    refetch_called = False

    async def unexpected_refetch(**_kwargs: object) -> object:
        nonlocal refetch_called
        refetch_called = True
        return object()

    monkeypatch.setattr(
        cli_module,
        "_refetch_qualification_generations",
        unexpected_refetch,
    )

    result = runner.invoke(cli_module.app, _qualify_args())

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "complete non-empty" in result.output
    assert "all-REAL benchmark portfolio" in result.output
    assert not refetch_called


def test_loose_report_flag_is_not_a_qualification_interface() -> None:
    arguments = _qualify_args()
    portfolio_index = arguments.index("--portfolio")
    arguments[portfolio_index : portfolio_index + 2] = ["--report", "model-a.json"]

    result = runner.invoke(cli_module.app, arguments)

    assert result.exit_code != ExitCode.SUCCESS
    assert "No such option: --report" in result.output
