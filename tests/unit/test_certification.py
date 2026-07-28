from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditReport,
    ExecutionEvidenceKind,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    RepositoryMap,
)
from mmaudit.orchestration import certification as certification_module
from mmaudit.orchestration.certification import (
    MaximumAssuranceCertification,
    certify_maximum_assurance_run,
    write_maximum_assurance_certification,
)
from mmaudit.orchestration.manifest import (
    ManifestFileBinding,
    RunEvidenceManifest,
    canonical_sha256,
)
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayComponent,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.orchestration.verification import RunVerificationStatus

_RUN_ID = "certification-test-run"
_MANIFEST_SHA256 = "1" * 64
_VERIFICATION_SHA256 = "2" * 64
ConfigFactory = Callable[[], AuditConfig]


def _requirement(
    engine: str,
    *,
    passed: bool,
    state: AnalysisState,
) -> MaximumAssuranceRequirement:
    return MaximumAssuranceRequirement(
        engine=engine,
        required=True,
        passed=passed,
        blocking=not passed,
        state=state,
        detail=f"{engine} {'passed' if passed else 'did not pass'}",
        artifacts=[],
    )


def _base_assessment(
    *,
    additional_blocker: bool = False,
) -> MaximumAssuranceAssessment:
    requirements = [
        _requirement(
            "successful_ast_compilation",
            passed=not additional_blocker,
            state=(
                AnalysisState.DETERMINISTIC
                if not additional_blocker
                else AnalysisState.ATTEMPTED_FAILED
            ),
        ),
        _requirement(
            "isolated_replay_execution",
            passed=False,
            state=AnalysisState.ATTEMPTED_FAILED,
        ),
        _requirement(
            "certified_execution_isolation",
            passed=False,
            state=AnalysisState.ATTEMPTED_FAILED,
        ),
    ]
    return MaximumAssuranceAssessment(
        requested=True,
        required=True,
        downgrade_allowed=False,
        downgraded=False,
        status=MaximumAssuranceStatus.INCONCLUSIVE,
        requirements=requirements,
        downgrade_reasons=[],
    )


def _report(assessment: MaximumAssuranceAssessment) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        run_id=_RUN_ID,
        generated_at=datetime(2026, 7, 27, tzinfo=UTC),
        completed=False,
        incomplete_reasons=["post-run replay certification pending"],
        repository=RepositoryMap(
            root_name="synthetic-certification-repository",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="3" * 64,
        model_configuration_hash="4" * 64,
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=AuditProfile.MAXIMUM_ASSURANCE,
        maximum_assurance=assessment,
    )


def _replay(
    *,
    run_id: str = _RUN_ID,
    manifest_sha256: str = _MANIFEST_SHA256,
    verification_sha256: str = _VERIFICATION_SHA256,
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.REAL,
) -> OfflineReplay:
    observation_sha256 = canonical_sha256({"scanner": "matched"})
    component = OfflineReplayComponent(
        kind=ReplayComponentKind.SCANNER,
        identifier="slither",
        status=ReplayComponentStatus.MATCHED,
        executed=True,
        execution_evidence=execution_evidence,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="7" * 64,
        expected_state="success",
        observed_state="success",
        expected_sha256=observation_sha256,
        observed_sha256=observation_sha256,
    )
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "status": OfflineReplayStatus.REPLAYED,
        "run_id": run_id,
        "manifest_sha256": manifest_sha256,
        "run_verification_sha256": verification_sha256,
        "model_provider_contacted": False,
        "remote_network_policy": "denied",
        "loopback_policy": "local_only",
        "components": [component.model_dump(mode="json")],
        "applicable_kinds": [ReplayComponentKind.SCANNER.value],
        "missing_kinds": [],
    }
    return OfflineReplay.model_validate(
        {
            **payload,
            "replay_sha256": canonical_sha256(payload),
        }
    )


def _certify(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
    *,
    assessment: MaximumAssuranceAssessment | None = None,
    replay: OfflineReplay | None = None,
    verification_manifest_sha256: str = _MANIFEST_SHA256,
) -> MaximumAssuranceCertification:
    manifest = SimpleNamespace(
        run_id=_RUN_ID,
        manifest_sha256=_MANIFEST_SHA256,
    )
    verification = SimpleNamespace(
        status=RunVerificationStatus.CURRENT,
        run_id=_RUN_ID,
        manifest_sha256=verification_manifest_sha256,
        verification_sha256=_VERIFICATION_SHA256,
    )
    monkeypatch.setattr(
        certification_module,
        "load_run_evidence_manifest",
        lambda _path: manifest,
    )
    monkeypatch.setattr(
        certification_module,
        "verify_run_evidence",
        lambda **_kwargs: verification,
    )
    monkeypatch.setattr(
        certification_module,
        "_load_report",
        lambda _path, _manifest: _report(assessment or _base_assessment()),
    )
    monkeypatch.setattr(
        certification_module,
        "load_offline_replay",
        lambda _path: replay or _replay(),
    )
    monkeypatch.setattr(
        certification_module,
        "expected_replay_kinds_for_run",
        lambda _path: {ReplayComponentKind.SCANNER},
    )
    monkeypatch.setattr(
        certification_module,
        "expected_replay_components_for_run",
        lambda _path: {(ReplayComponentKind.SCANNER, "slither")},
    )
    return certify_maximum_assurance_run(
        manifest_path=Path("run-evidence-manifest.json"),
        run_dir=Path("run"),
        repository_root=Path("repository"),
        replay_path=Path("offline-replay.json"),
        config=config_factory(),
    )


def test_v11_certification_reconstructs_embedded_effective_config(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    config = config_factory()
    manifest = SimpleNamespace(
        run_id=_RUN_ID,
        manifest_sha256=_MANIFEST_SHA256,
        run_configuration=SimpleNamespace(
            effective_config_sha256=config.stable_hash(),
        ),
    )
    verification = SimpleNamespace(
        status=RunVerificationStatus.CURRENT,
        run_id=_RUN_ID,
        manifest_sha256=_MANIFEST_SHA256,
        verification_sha256=_VERIFICATION_SHA256,
    )
    observed_verification: dict[str, object] = {}

    def resolve_config(
        observed_manifest: object,
        *,
        file_config: AuditConfig | None = None,
    ) -> AuditConfig:
        assert observed_manifest is manifest
        assert file_config is None
        return config

    def verify(**kwargs: object) -> object:
        observed_verification.update(kwargs)
        return verification

    monkeypatch.setattr(
        certification_module,
        "load_run_evidence_manifest",
        lambda _path: manifest,
    )
    monkeypatch.setattr(
        certification_module,
        "resolve_run_evidence_config",
        resolve_config,
    )
    monkeypatch.setattr(certification_module, "verify_run_evidence", verify)
    monkeypatch.setattr(
        certification_module,
        "_load_report",
        lambda _path, _manifest: _report(_base_assessment()),
    )
    monkeypatch.setattr(
        certification_module,
        "load_offline_replay",
        lambda _path: _replay(),
    )
    monkeypatch.setattr(
        certification_module,
        "expected_replay_kinds_for_run",
        lambda _path: {ReplayComponentKind.SCANNER},
    )
    monkeypatch.setattr(
        certification_module,
        "expected_replay_components_for_run",
        lambda _path: {(ReplayComponentKind.SCANNER, "slither")},
    )

    certification = certify_maximum_assurance_run(
        manifest_path=Path("run-evidence-manifest.json"),
        run_dir=Path("run"),
        repository_root=Path("repository"),
        replay_path=Path("offline-replay.json"),
    )

    assert certification.assessment.status is MaximumAssuranceStatus.COMPLETE
    assert observed_verification["config"] == config
    assert observed_verification["file_config"] is None


def test_v10_certification_requires_explicit_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        certification_module,
        "load_run_evidence_manifest",
        lambda _path: SimpleNamespace(
            run_id=_RUN_ID,
            manifest_sha256=_MANIFEST_SHA256,
            run_configuration=None,
        ),
    )

    with pytest.raises(ValueError, match="legacy run manifest requires"):
        certify_maximum_assurance_run(
            manifest_path=Path("run-evidence-manifest.json"),
            run_dir=Path("run"),
            repository_root=Path("repository"),
            replay_path=Path("offline-replay.json"),
        )


def test_certification_is_self_hashed_and_rejects_tampering(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    certification = _certify(monkeypatch, config_factory)

    assert certification.certification_sha256 == canonical_sha256(
        certification.model_dump(mode="json", exclude={"certification_sha256"})
    )
    tampered = certification.model_dump(mode="json")
    tampered["manifest_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="certification hash is inconsistent"):
        MaximumAssuranceCertification.model_validate(tampered)


def test_certification_rejects_manifest_changed_during_verification(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    with pytest.raises(ValueError, match="changed run manifest"):
        _certify(
            monkeypatch,
            config_factory,
            verification_manifest_sha256="f" * 64,
        )


def test_certification_reloads_only_manifest_bound_report_bytes(tmp_path: Path) -> None:
    report = _report(_base_assessment())
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    report_path = run_dir / "final-findings.json"
    report_bytes = report.model_dump_json().encode("utf-8")
    report_path.write_bytes(report_bytes)
    manifest = cast(
        RunEvidenceManifest,
        SimpleNamespace(
            artifacts=[
                ManifestFileBinding(
                    path="final-findings.json",
                    sha256=hashlib.sha256(report_bytes).hexdigest(),
                    size=len(report_bytes),
                )
            ]
        ),
    )

    assert certification_module._load_report(run_dir, manifest) == report

    report_path.write_bytes(report_bytes + b"\n")
    with pytest.raises(ValueError, match="not manifest-bound"):
        certification_module._load_report(run_dir, manifest)


def test_certification_promotes_only_replay_blocked_assessment(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    certification = _certify(monkeypatch, config_factory)

    assert certification.assessment.status is MaximumAssuranceStatus.COMPLETE
    assert all(
        requirement.passed
        for requirement in certification.assessment.requirements
        if requirement.required
    )
    replay_requirement = next(
        requirement
        for requirement in certification.assessment.requirements
        if requirement.engine == "isolated_replay_execution"
    )
    assert replay_requirement.state is AnalysisState.REPRODUCED
    assert replay_requirement.artifacts == ["offline-replay.json"]


def test_certification_does_not_promote_when_a_non_replay_blocker_exists(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    certification = _certify(
        monkeypatch,
        config_factory,
        assessment=_base_assessment(additional_blocker=True),
    )

    assert certification.assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert {
        requirement.engine
        for requirement in certification.assessment.requirements
        if requirement.required and not requirement.passed
    } == {
        "successful_ast_compilation",
        "isolated_replay_execution",
        "certified_execution_isolation",
    }


@pytest.mark.parametrize(
    "replay",
    [
        _replay(run_id="different-run"),
        _replay(manifest_sha256="a" * 64),
        _replay(verification_sha256="b" * 64),
        _replay(execution_evidence=ExecutionEvidenceKind.UNVERIFIED),
    ],
    ids=[
        "wrong-run",
        "wrong-manifest",
        "wrong-verification",
        "unverified-execution",
    ],
)
def test_certification_rejects_nonqualifying_replay_bindings(
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
    replay: OfflineReplay,
) -> None:
    certification = _certify(monkeypatch, config_factory, replay=replay)

    assert certification.assessment.status is MaximumAssuranceStatus.INCONCLUSIVE
    assert {
        requirement.engine
        for requirement in certification.assessment.requirements
        if requirement.required and not requirement.passed
    } == {
        "isolated_replay_execution",
        "certified_execution_isolation",
    }


def test_certification_output_rejects_sensitive_and_linked_destinations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    certification = _certify(monkeypatch, config_factory)

    with pytest.raises(ValueError, match="sensitive"):
        write_maximum_assurance_certification(tmp_path / ".env", certification)

    link_target = tmp_path / "target.json"
    link_target.write_text("{}\n", encoding="utf-8")
    symlink = tmp_path / "certification.json"
    symlink.symlink_to(link_target)
    with pytest.raises(ValueError, match="may not be a link"):
        write_maximum_assurance_certification(symlink, certification)

    hardlink = tmp_path / "hardlink.json"
    os.link(link_target, hardlink)
    with pytest.raises(ValueError, match="must be an unshared file"):
        write_maximum_assurance_certification(hardlink, certification)


def test_certification_output_round_trips_through_strict_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: ConfigFactory,
) -> None:
    certification = _certify(monkeypatch, config_factory)
    path = tmp_path / "maximum-assurance-certification.json"

    write_maximum_assurance_certification(path, certification)

    loaded = MaximumAssuranceCertification.model_validate_json(path.read_text(encoding="utf-8"))
    assert loaded == certification
