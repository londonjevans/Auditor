"""Quality policy follows the run contract without manufacturing analysis evidence."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from mmaudit.models.schemas import AuditProfile, QualityGateResult, SolidityProjectMetadata
from mmaudit.orchestration.actor_model import load_actor_model
from mmaudit.orchestration.assurance import MaximumAssuranceContract
from mmaudit.orchestration.pipeline import _evaluate_quality_gates


@pytest.mark.parametrize("profile", ["standard", "maximum-assurance"])
@pytest.mark.parametrize("configured_requirement", [False, True])
@pytest.mark.parametrize("run_requirement", [None, False, True])
@pytest.mark.parametrize("scanner_only", [False, True])
def test_all_maximum_quality_gates_follow_resolved_run_requirement(
    tmp_path, config_factory, profile, configured_requirement, run_requirement, scanner_only
):
    config = config_factory(
        profile=profile,
        maximum_assurance={"require": configured_requirement},
    ).effective()
    before = config.model_dump_json()
    contract = MaximumAssuranceContract(config, require=run_requirement)
    gates = _evaluate_quality_gates(
        config=config,
        maximum_assurance_required=contract.required,
        actor_model_input=load_actor_model(
            tmp_path, config.actor_model, evaluated_at=datetime(2026, 9, 7, tzinfo=UTC)
        ),
        solidity_projects=[SolidityProjectMetadata(project_type="foundry", project_root=".")],
        compilations=[],
        scanner_runs=[],
        coverage=None,
        model_review_coverage=None,
        taxonomy_coverage=None,
        model_surface_coverage_plan=None,
        authoritative_model_surface_requests=(),
        language_capability=None,
        scope_assessment=None,
        prior_audit_comparison=None,
        invariant_executions=[],
        eligible_candidates=[],
        reproductions=[],
        usage_roles=set(),
        scanner_only=scanner_only,
        model_surface_assignment_gate=QualityGateResult(
            gate="model_surface_assignment",
            required=True,
            passed=False,
            detail="No model work in this synthetic policy-only control.",
        ),
        repository_execution_sha256=None,
    )
    by_name = {gate.gate: gate for gate in gates}
    expected = config.profile is AuditProfile.MAXIMUM_ASSURANCE or contract.required
    assert by_name["known_issue_taxonomy_critical_disposition"].required is expected
    assert by_name["known_issue_taxonomy_critical_disposition"].passed is False
    if not scanner_only:
        for name in (
            "solidity_index_coverage",
            "compiler_contract_index_coverage",
            "stateful_invariants",
            "public_external_entry_point_review_coverage",
            "invariant_execution_coverage",
            "economic_template_execution_coverage",
            "dependency_resolution_coverage",
        ):
            assert by_name[name].required is expected, name
            assert by_name[name].passed is False, name
        assert by_name["compilation"].required is config.quality_gates.require_compilation
        assert by_name["slither"].required is config.quality_gates.require_slither
    assert config.model_dump_json() == before
    assert contract.required is (
        configured_requirement if run_requirement is None else run_requirement
    )


def test_synthetic_review_fixture_canonicalizes_its_owned_temp_root_before_journal(
    tmp_path, config_factory, monkeypatch
):
    from tests.unit import test_model_coverage as support

    actual = tmp_path / "owned-temporary-root"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "temporary-alias"
    alias.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(
        support, "TemporaryDirectory", lambda **kwargs: SimpleNamespace(name=str(alias))
    )

    class ObservedCanonicalRoot(Exception):
        pass

    def observe(root, **kwargs):
        assert root == actual.resolve(strict=True) / "journal"
        raise ObservedCanonicalRoot

    monkeypatch.setattr(support, "_create_test_scheduler_journal", observe)
    config = config_factory()
    # This pre-journal sentinel does not construct a review or grant authority.
    with pytest.raises(ObservedCanonicalRoot):
        support._authorized_ordinary_review_evidence(
            config,
            index=None,
            graphs=None,
            requests=[],
            reviewers=(("source_audit", config.models.source_audit.primary),),
            contexts=(object(),),
        )
