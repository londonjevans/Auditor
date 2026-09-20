"""Original seven-pass findings and verification-only file replay; no external execution."""

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import AuditReport, CandidateFindingArtifact, MaximumAssuranceStatus
from mmaudit.models.sharding import (
    SolidityGraphsArtifact,
    SolidityIndexArtifact,
    SolidityShardsArtifact,
)
from mmaudit.orchestration import manifest
from mmaudit.orchestration.scheduler import open_scheduler_journal_for_verification
from tests.integration.test_truncation_tree_manifest_files import _write_model
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.truncation_tree_assurance_support import CompleteTreeAssuranceFixture
from tests.unit.test_truncation_tree_manifest import _manifest_arguments


def test_candidate_report_reopens_original_promotions_and_refuses_every_omitted_origin(
    original_candidate_report: tuple[AuditConfig, CompleteTreeAssuranceFixture, AuditReport],
) -> None:
    config, fixture, report = original_candidate_report
    root = fixture.privacy.run_directory
    state = fixture.candidate_report
    journal = fixture.journal
    original = journal.artifact()
    qualification = ModelRegistry.validate_production_qualification(
        config, fixture.authorities.qualification, now=fixture.authorities.qualification.verified_at
    )
    # The configured synthetic routes must pass the unchanged production validator.
    # Synthetic qualification custody is not a real provider qualification or a complete audit.
    assert qualification.valid, qualification.errors
    assert not report.completed
    assert report.maximum_assurance is not None
    assert report.maximum_assurance.status is not MaximumAssuranceStatus.COMPLETE
    arguments = _manifest_arguments(config, fixture)
    candidates = CandidateFindingArtifact.model_validate(
        {
            "schema_version": "1.1",
            "findings": [item.model_dump(mode="json") for item in state.candidates],
        }
    )
    _write_model(root / "report.json", report)
    _write_model(root / "candidate-findings.json", candidates)
    _write_model(
        root / "reproduction-results.json",
        manifest._ManifestReproductionArtifact(
            schema_version="1.0",
            test_specifications=[],
            results=[],
            candidate_resolutions=state.resolutions,
        ),
    )
    _write_model(root / manifest.MODEL_REVIEW_ARTIFACT_INVENTORY_PATH, arguments["inventory"])
    _write_model(
        root / manifest.PROMOTED_MODEL_REVIEW_ARTIFACT_INVENTORY_PATH,
        arguments["promoted_inventory"],
    )
    _write_model(root / "solidity-index.json", SolidityIndexArtifact(index=fixture.source.index))
    _write_model(
        root / "solidity-graphs.json", SolidityGraphsArtifact(graphs=fixture.source.graphs)
    )
    # Every tamper case compares against the same unchanged original journal.
    authority_snapshot = manifest._scheduler_report_authority_snapshot(journal)

    def validate(*, detached: bool, full_custody: bool = True) -> None:
        decoded = AuditReport.model_validate_json((root / "report.json").read_bytes())
        assert not decoded.completed and not decoded.reproductions
        if full_custody:
            replay = manifest.validate_scheduler_artifact(
                root,
                decoded,
                config=config,
                run_options=fixture.source.analysis_arguments["run_options"],
                require_retained_usage_custody=not detached,
                qualification_runtime=qualification.as_dict(),
                scheduler_runtime_journal=None if detached else journal,
            )
            assert replay == original
        else:
            manifest._validate_scheduler_report_authority(
                root=root,
                report=decoded,
                snapshot=authority_snapshot,
                config=config,
                run_options=fixture.source.analysis_arguments["run_options"],
            )

    _write_model(
        root / "solidity-shards.json",
        SolidityShardsArtifact(inventory=fixture.source.semantic_shards),
    )
    _write_model(root / "scheduler-state.json", original)
    validate(detached=False)
    assert len(candidates.findings) == 9
    for omitted in candidates.findings:
        _write_model(
            root / "candidate-findings.json",
            candidates.model_copy(
                update={
                    "findings": [item for item in candidates.findings if item is not omitted],
                }
            ),
        )
        # Named invariant: neither ordinary, retained parent/bridge nor leaf findings may vanish.
        with pytest.raises(
            ValueError, match="candidate artifact differs from scheduler host authority"
        ):
            validate(detached=False, full_custody=False)
    _write_model(root / "candidate-findings.json", candidates)
    for field, changed in (
        ("judge_decisions", []),
        ("findings", []),
        ("report_quality_review", None),
        ("consensus_review", None),
    ):
        _write_model(root / "report.json", report.model_copy(update={field: changed}))
        with pytest.raises(ValueError):
            validate(detached=False, full_custody=False)
    _write_model(root / "report.json", report)
    validate(detached=False)
    assert journal.artifact() == original

    expected = journal.manifest
    inputs = journal.analysis_input_inventory
    path = journal.path
    journal.close()
    # The detached validator owns its verifier; no competing descriptor may be held here.
    with pytest.raises(
        ValueError, match="credited model-review evidence lacks live pre-dispatch runtime authority"
    ):
        validate(detached=True)
    assert report.minimum_analysis_floor is not None
    # The earlier review-credit refusal must not hide the independent live floor requirement.
    with pytest.raises(
        ValueError, match="minimum-floor recovery credit lacks exact live scheduler authority"
    ):
        manifest._validate_minimum_floor_recovery_usage_bindings(
            bindings=tuple(report.minimum_analysis_floor.recovery_model_usage_bindings),
            serialized_leaf_inventory=manifest._promoted_model_review_leaf_usage_inventory(
                arguments["promoted_inventory"]
            ),
            recovery_model_requests={
                request.logical_request_id: request for request in original.recovery_model_requests
            },
            runtime_journal=None,
        )
    journal = open_scheduler_journal_for_verification(
        path,
        expected_bindings=expected.bindings,
        expected_analysis_input_inventory=inputs,
        expected_shard_inventory=expected.shard_inventory,
        expected_cost_ledger_baseline=expected.cost_ledger_baseline,
        expected_privacy_evidence_custody=expected.privacy_evidence_custody,
        expected_terminal_report_authority_required=expected.terminal_report_authority_required,
        expected_terminal_evidence_authority_required=expected.terminal_evidence_authority_required,
    )
    try:
        # Rebuild from the reopened original descriptor; do not reuse live-owner evidence.
        authority_snapshot = manifest._scheduler_report_authority_snapshot(journal)
        # Named invariant: verification custody remains exclusive even without a live writer.
        with pytest.raises(
            ValueError, match="scheduler journal already has live in-process custody"
        ):
            validate(detached=True)
        # A descriptor-only reopen may compare findings, not recreate live floor credit.
        validate(detached=True, full_custody=False)
        decoded = AuditReport.model_validate_json((root / "report.json").read_bytes())
        with journal.open_privacy_evidence_custody() as custody:
            assert custody == expected.privacy_evidence_custody
            manifest._validate_scheduler_privacy_artifacts(
                root=root, report=decoded, custody=custody
            )
        # Exact privacy and finding comparisons do not restore credited review authority.
        with pytest.raises(
            ValueError,
            match="credited model-review evidence lacks live pre-dispatch runtime authority",
        ):
            manifest._validate_scheduler_privacy_custody_and_reconstruct(
                root=root,
                report=decoded,
                public_artifact=original,
                journal=journal,
                config=config,
                run_options=fixture.source.analysis_arguments["run_options"],
                require_retained_usage_custody=False,
                model_review_inventory=manifest._load_model_review_artifact_inventory(
                    root, decoded
                ),
                promoted_model_review_inventory=manifest._load_promoted_model_review_artifact_inventory(
                    root, decoded
                ),
                detached=True,
            )
        assert journal.artifact() == original
    finally:
        journal.close()
