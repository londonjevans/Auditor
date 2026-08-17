from __future__ import annotations

import copy
import hashlib
import pickle
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.models.policy_eligibility import (
    ClientConstraintMode,
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyAuditContext,
    PolicyCriterionDisposition,
    PolicyEligibilityDecision,
    PolicyEligibilityEvaluation,
    PolicyEligibilityRoute,
    PolicyEvidenceKind,
    PolicyExclusionReason,
    PolicyLegalCriterion,
    PolicyUsePurpose,
    build_client_policy_constraints,
    build_model_policy_eligibility_artifact,
    build_model_policy_eligibility_determination,
    build_official_policy_evidence_reference,
    build_policy_audit_context,
    build_policy_criterion_assessment,
    build_policy_eligibility_route,
    build_policy_eligibility_source_reference_observation,
    evaluate_model_policy_eligibility,
)
from mmaudit.models.policy_eligibility_authority import (
    POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    PolicyEligibilitySourceObservation,
    TrustedModelPolicyEligibilitySelectionVerification,
    build_model_policy_eligibility_authority_envelope,
    build_model_policy_eligibility_authority_evidence_projection,
    build_model_policy_eligibility_authority_statement,
    build_model_policy_eligibility_trust_anchor,
    build_policy_eligibility_source_commitment,
    build_policy_eligibility_source_observation,
    model_policy_eligibility_authority_statement_bytes,
    trusted_policy_eligibility_ssh_keygen_sha256,
    verify_operator_model_policy_eligibility_authority,
)
from mmaudit.models.policy_selection import (
    AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME,
    AuditModelRoutingEvidence,
    AuditModelSelection,
    AuditModelSelectionEvidenceBundle,
    AuditSelectedTechnicalModel,
    VerifiedAuditModelSelection,
    build_audit_model_selection_evidence_bundle,
    resolve_verified_audit_model_selection,
    verify_audit_model_selection_evidence_bundle,
)
from mmaudit.models.qualification import (
    QualificationDisposition,
    VerifiedProductionQualification,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacySourceClassification
from tests.conftest import MODEL_IDS, base_config_data, model_registry_entry
from tests.qualification_support import synthetic_production_qualification

BASE_TIME = datetime(2026, 8, 17, 12, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PolicyBundle:
    artifact: ModelPolicyEligibilityArtifact
    evaluation: PolicyEligibilityEvaluation
    audit_context: PolicyAuditContext
    client_constraints: ClientPolicyConstraints
    routes: tuple[PolicyEligibilityRoute, ...]
    evidence_content_sha256: str


@dataclass(frozen=True, slots=True)
class _AuthorityBundle:
    source_observation: PolicyEligibilitySourceObservation
    capability: TrustedModelPolicyEligibilitySelectionVerification
    trust_anchor_sha256: str
    operator_principal: str
    verified_at: datetime
    expires_at: datetime


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _technical_qualification() -> VerifiedProductionQualification:
    data = base_config_data()
    base_ids = tuple(MODEL_IDS.values())
    extra_ids = (
        "golf/glacier-secure",
        "hotel/harbor-secure",
        "india/ion-secure",
    )
    model_ids = (*base_ids, *extra_ids)
    roots = tuple(f"sha256:{_hash(f'root-{index}')}" for index in range(6))
    registry = [
        model_registry_entry(
            model_id,
            root_lineage=roots[index] if index < 6 else roots[index - 6],
        )
        for index, model_id in enumerate(model_ids)
    ]
    data["privacy"]["approved_model_lineages"] = list(roots)
    data["models"]["registry"] = registry
    data["models"]["specialists"] = {
        "access_control": {"primary": extra_ids[0], "fallbacks": []},
        "false_negative_hunter": {"primary": extra_ids[1], "fallbacks": []},
        "report_quality": {"primary": extra_ids[2], "fallbacks": []},
    }
    config = AuditConfig.model_validate(data)
    capability = synthetic_production_qualification(
        config,
        BASE_TIME,
        provider_endpoint="openrouter/provider-a",
        provider_name="Synthetic Provider",
    )
    assert len(capability.models) == 9
    assert len({model.root_lineage for model in capability.models}) == 6
    return capability


def _policy_bundle(
    technical: VerifiedProductionQualification,
    *,
    excluded_ids: frozenset[str] = frozenset(),
    intended_use: PolicyUsePurpose = (PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT),
    context_tag: str = "a",
    first_endpoint_override: str | None = None,
    source_sha256_override: str | None = None,
    base_time: datetime = BASE_TIME,
) -> _PolicyBundle:
    routes = tuple(
        build_policy_eligibility_route(
            exact_model_id=model.exact_model_id,
            provider_name=model.approved_provider_name,
            provider_endpoint=(
                first_endpoint_override
                if first_endpoint_override is not None and index == 0
                else model.approved_provider_endpoint
            ),
        )
        for index, model in enumerate(technical.models)
    )
    routes = tuple(sorted(routes, key=lambda route: route.identity))
    evidence = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.COMMERCIAL_TERMS,
        publisher="Synthetic Provider",
        official_source_url="https://example.invalid/official-policy",
        retrieved_at=base_time - timedelta(days=1),
        content_sha256=_hash("policy-content"),
        byte_count=128,
        source_version="synthetic-v1",
    )
    determinations = []
    for route in routes:
        ineligible = route.exact_model_id in excluded_ids
        assessments = tuple(
            build_policy_criterion_assessment(
                criterion=criterion,
                disposition=(
                    PolicyCriterionDisposition.PROHIBITED
                    if ineligible and index == 0
                    else PolicyCriterionDisposition.PERMITTED
                ),
                evidence_reference_sha256s=(evidence.reference_sha256,),
                assessment_record_sha256=_hash(
                    f"assessment:{route.exact_model_id}:{criterion.value}"
                ),
            )
            for index, criterion in enumerate(
                sorted(PolicyLegalCriterion, key=lambda item: item.value)
            )
        )
        determinations.append(
            build_model_policy_eligibility_determination(
                route=route,
                decision=(
                    PolicyEligibilityDecision.INELIGIBLE
                    if ineligible
                    else PolicyEligibilityDecision.ELIGIBLE
                ),
                intended_use=intended_use,
                applicable_client_entity_sha256s=(_hash(f"client:{context_tag}"),),
                applicable_client_jurisdictions=("GB",),
                applicable_operator_entity_sha256s=(_hash("operator"),),
                applicable_operator_jurisdictions=("GB",),
                assessments=assessments,
                reviewed_by="synthetic-policy-reviewer",
                reviewed_at=base_time - timedelta(hours=12),
                effective_at=base_time - timedelta(hours=11),
                expires_at=base_time + timedelta(days=10),
                review_record_sha256=_hash(f"review:{route.exact_model_id}"),
            )
        )
    artifact = build_model_policy_eligibility_artifact(
        created_at=base_time - timedelta(hours=10),
        official_evidence=(evidence,),
        determinations=tuple(determinations),
    )
    audit_context = build_policy_audit_context(
        audit_scope_sha256=_hash(f"scope:{context_tag}"),
        source_sha256=source_sha256_override or _hash(f"source:{context_tag}"),
        source_classification=(
            PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
            if intended_use is PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
            else PrivacySourceClassification.PUBLIC_BENCHMARK
        ),
        intended_use=intended_use,
        client_entity_sha256=_hash(f"client:{context_tag}"),
        client_jurisdiction="GB",
        operator_entity_sha256=_hash("operator"),
        operator_jurisdiction="GB",
    )
    constraints = build_client_policy_constraints(
        audit_context=audit_context,
        mode=ClientConstraintMode.DENY_ONLY,
        provider_names=(),
        exact_model_ids=(),
        exact_routes=(),
        reviewed_by="synthetic-client-reviewer",
        reviewed_at=base_time - timedelta(hours=12),
        effective_at=base_time - timedelta(hours=11),
        expires_at=base_time + timedelta(days=9),
        constraint_basis_sha256=_hash(f"constraints:{context_tag}"),
    )
    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=constraints,
        audit_context=audit_context,
        technical_routes=routes,
        observed_at=base_time + timedelta(hours=1),
    )
    return _PolicyBundle(
        artifact=artifact,
        evaluation=evaluation,
        audit_context=audit_context,
        client_constraints=constraints,
        routes=routes,
        evidence_content_sha256=evidence.content_sha256,
    )


def _ssh_keygen() -> Path:
    candidate = Path("/usr/bin/ssh-keygen")
    if not candidate.is_file():
        pytest.skip("fixed system ssh-keygen is unavailable")
    return candidate


def _policy_authority(tmp_path: Path, bundle: _PolicyBundle) -> _AuthorityBundle:
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = tmp_path / "operator"
    generated = subprocess.run(
        [
            str(_ssh_keygen()),
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            str(key),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
    )
    if generated.returncode != 0:
        pytest.skip("system ssh-keygen cannot generate an ephemeral Ed25519 key")
    public_key = " ".join(key.with_suffix(".pub").read_text(encoding="ascii").split()[:2])
    anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="synthetic-policy-reviewer",
        public_key=public_key,
        verifier_executable_sha256=trusted_policy_eligibility_ssh_keygen_sha256(),
    )
    source_observation = _source_observation(bundle)
    signed_at = bundle.evaluation.evaluated_at
    expires_at = signed_at + timedelta(hours=6)
    statement = build_model_policy_eligibility_authority_statement(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source_observation,
        trust_anchor=anchor,
        signed_at=signed_at,
        expires_at=expires_at,
    )
    message = tmp_path / "statement.json"
    message.write_bytes(model_policy_eligibility_authority_statement_bytes(statement))
    signed = subprocess.run(
        [
            str(_ssh_keygen()),
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
            str(message),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
    )
    assert signed.returncode == 0, signed.stderr.decode("utf-8", errors="replace")
    envelope = build_model_policy_eligibility_authority_envelope(
        statement=statement,
        detached_signature=message.with_suffix(".json.sig").read_bytes(),
    )
    verified_at = signed_at + timedelta(minutes=1)
    receipt, capability = verify_operator_model_policy_eligibility_authority(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source_observation,
        envelope=envelope,
        trust_anchor=anchor,
        expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
        expected_operator_principal=anchor.operator_principal,
        observed_at=verified_at,
    )
    assert receipt.expires_at == expires_at
    return _AuthorityBundle(
        source_observation=source_observation,
        capability=capability,
        trust_anchor_sha256=anchor.trust_anchor_sha256,
        operator_principal=anchor.operator_principal,
        verified_at=verified_at,
        expires_at=expires_at,
    )


def _source_observation(
    bundle: _PolicyBundle,
    *,
    observed_at: datetime | None = None,
    current_content_sha256: str | None = None,
) -> PolicyEligibilitySourceObservation:
    observed = bundle.evaluation.evaluated_at if observed_at is None else observed_at
    reference = bundle.artifact.official_evidence[0]
    current = build_policy_eligibility_source_reference_observation(
        reference=reference,
        current_content_sha256=(
            bundle.evidence_content_sha256
            if current_content_sha256 is None
            else current_content_sha256
        ),
    )
    commitments = tuple(
        build_policy_eligibility_source_commitment(
            artifact=bundle.artifact,
            route=route,
            source_reference_observations=(current,),
        )
        for route in bundle.evaluation.eligible_routes
    )
    return build_policy_eligibility_source_observation(
        artifact=bundle.artifact,
        observed_at=observed,
        expires_at=observed + timedelta(hours=12),
        source_commitments=commitments,
    )


def _resolve(
    technical: VerifiedProductionQualification,
    policy: _PolicyBundle,
    authority: _AuthorityBundle,
    **overrides: Any,
) -> tuple[
    AuditModelSelection,
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
]:
    arguments: dict[str, Any] = {
        "technical_qualification": technical,
        "policy_artifact": policy.artifact,
        "policy_evaluation": policy.evaluation,
        "audit_context": policy.audit_context,
        "client_constraints": policy.client_constraints,
        "source_observation": authority.source_observation,
        "trusted_policy_verification": authority.capability,
        "selected_at": authority.verified_at + timedelta(minutes=1),
    }
    arguments.update(overrides)
    return resolve_verified_audit_model_selection(**arguments)


def _runtime_bindings(policy: _PolicyBundle) -> dict[str, str]:
    return {
        "expected_audit_scope_sha256": policy.audit_context.audit_scope_sha256,
        "expected_source_sha256": policy.audit_context.source_sha256,
        "expected_audit_context_sha256": policy.audit_context.context_sha256,
        "expected_client_constraints_sha256": policy.client_constraints.constraints_sha256,
    }


def _detached_evidence_bindings(
    selection: AuditModelSelection,
    authority: _AuthorityBundle,
) -> dict[str, str]:
    return {
        "expected_trust_anchor_sha256": authority.trust_anchor_sha256,
        "expected_operator_principal": authority.operator_principal,
        "expected_audit_selection_sha256": selection.selection_sha256,
        "expected_technical_qualification_artifact_sha256": (
            selection.technical_qualification_artifact_sha256
        ),
        "expected_technical_qualification_verification_sha256": (
            selection.technical_qualification_verification_sha256
        ),
        "expected_technical_production_selection_sha256": (
            selection.technical_production_selection_sha256
        ),
        "expected_technical_selection_verification_sha256": (
            selection.technical_selection_verification_sha256
        ),
        "expected_technical_production_effective_config_sha256": (
            selection.technical_production_effective_config_sha256
        ),
        "expected_technical_candidate_registry_sha256": (
            selection.technical_candidate_registry_sha256
        ),
        "expected_technical_qualification_policy_sha256": (
            selection.technical_qualification_policy_sha256
        ),
        "expected_technical_release_observation_sha256": (
            selection.technical_release_observation_sha256
        ),
    }


def test_audit_selection_excludes_policy_ineligible_tier_a_and_preserves_evidence(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)

    selection, evidence_bundle, capability = _resolve(technical, policy, authority)

    assert len(technical.models) == 9
    assert all(
        model.qualification_disposition is QualificationDisposition.TIER_A
        for model in technical.models
    )
    assert selection.technical_model_ids == tuple(
        model.exact_model_id for model in technical.models
    )
    assert len(selection.models) == len(capability.models) == 8
    assert len({model.root_lineage for model in capability.models}) == 6
    assert excluded_id not in selection.selected_model_ids
    assert excluded_id not in tuple(model.exact_model_id for model in capability.models)
    assert selection.policy_excluded_model_ids == (excluded_id,)
    assert selection.policy_exclusions[0].reasons == (PolicyExclusionReason.DECISION_INELIGIBLE,)
    assert selection.policy_exclusion_sha256s == (selection.policy_exclusions[0].exclusion_sha256,)
    assert policy.evaluation.expires_at is not None
    assert selection.expires_at == min(
        technical.expires_at,
        policy.evaluation.expires_at,
        authority.source_observation.expires_at,
        authority.expires_at,
    )
    assert selection.technical_production_selection_sha256 == (
        technical.production_selection_sha256
    )
    assert selection.policy_artifact_sha256 == policy.artifact.artifact_sha256
    assert selection.policy_evaluation_sha256 == policy.evaluation.evaluation_sha256
    assert selection.policy_source_observation_sha256 == (
        authority.source_observation.observation_sha256
    )
    assert type(selection.technical_qualification_authorized) is bool
    assert not selection.technical_qualification_authorized
    assert not selection.policy_selection_authorized
    assert not selection.source_egress_authorized
    assert not selection.general_production_authorized
    assert selection.selection_sha256 == canonical_sha256(
        selection.model_dump(mode="json", exclude={"selection_sha256"})
    )
    assert AUDIT_MODEL_SELECTION_EVIDENCE_FILENAME == ("audit-model-selection-evidence.json")
    assert evidence_bundle.selection == selection
    assert evidence_bundle.technical_evidence_mode == ("EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED")
    assert evidence_bundle.policy_artifact == policy.artifact
    assert evidence_bundle.policy_evaluation == policy.evaluation
    assert evidence_bundle.audit_context == policy.audit_context
    assert evidence_bundle.client_constraints == policy.client_constraints
    assert evidence_bundle.current_source_observation == authority.source_observation
    assert evidence_bundle.policy_authority_evidence == authority.capability.evidence_projection()
    assert type(evidence_bundle.policy_selection_authorized) is bool
    assert not evidence_bundle.technical_qualification_authorized
    assert not evidence_bundle.policy_selection_authorized
    assert not evidence_bundle.source_egress_authorized
    assert not evidence_bundle.general_production_authorized
    assert evidence_bundle.bundle_sha256 == canonical_sha256(
        evidence_bundle.model_dump(mode="json", exclude={"bundle_sha256"})
    )
    assert (
        verify_audit_model_selection_evidence_bundle(
            evidence_bundle=evidence_bundle,
            **_detached_evidence_bindings(selection, authority),
        )
        == evidence_bundle
    )

    technical_by_id = {model.exact_model_id: model for model in technical.models}
    for selected, live_model in zip(selection.models, capability.models, strict=True):
        technical_model = technical_by_id[selected.exact_model_id]
        assert live_model is technical_model
        assert selected.approved_roles == technical_model.approved_roles
        assert selected.approved_provider_endpoint == technical_model.approved_provider_endpoint
        assert selected.approved_provider_name == technical_model.approved_provider_name
        assert selected.quality_measurement_sha256 == (technical_model.quality_measurement_sha256)
        assert selected.qualification_result_sha256 == (technical_model.qualification_result_sha256)
        assert selected.reasoning_bindings == technical_model.reasoning_bindings

    use_time = authority.verified_at + timedelta(minutes=2)
    selected_id = capability.models[0].exact_model_id
    bindings = _runtime_bindings(policy)
    assert capability.require_current(now=use_time, **bindings) is capability
    assert capability.model_for(selected_id, now=use_time, **bindings) is capability.models[0]
    with pytest.raises(ValueError, match="lacks verified audit selection"):
        capability.model_for(excluded_id, now=use_time, **bindings)
    routing = capability.routing_evidence(selected_id, now=use_time, **bindings)
    metadata = capability.request_metadata(selected_id, now=use_time, **bindings)
    assert routing.audit_model_selection_bundle_sha256 == evidence_bundle.bundle_sha256
    assert routing.audit_selection_sha256 == selection.selection_sha256
    assert routing.selected_model_set_sha256 == selection.selected_model_set_sha256
    assert routing.audit_scope_sha256 == policy.audit_context.audit_scope_sha256
    assert routing.source_sha256 == policy.audit_context.source_sha256
    assert routing.audit_context_sha256 == policy.audit_context.context_sha256
    assert routing.client_constraints_sha256 == policy.client_constraints.constraints_sha256
    assert routing.intended_use is PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT
    assert routing.route.exact_model_id == selected_id
    assert routing.policy_source_commitment_set_sha256 == (
        selection.policy_source_commitment_set_sha256
    )
    assert metadata["policy_authority_statement_sha256"] == (
        selection.policy_authority_statement_sha256
    )
    assert metadata["audit_model_selection_bundle_sha256"] == evidence_bundle.bundle_sha256
    assert metadata["selected_model_set_sha256"] == selection.selected_model_set_sha256
    assert metadata["policy_authority_envelope_sha256"] == (
        selection.policy_authority_envelope_sha256
    )
    assert metadata["policy_authority_trust_anchor_sha256"] == (
        selection.policy_authority_trust_anchor_sha256
    )
    assert metadata["audit_scope_sha256"] == policy.audit_context.audit_scope_sha256
    assert metadata["source_sha256"] == policy.audit_context.source_sha256
    assert metadata["audit_context_sha256"] == policy.audit_context.context_sha256
    assert metadata["client_constraints_sha256"] == policy.client_constraints.constraints_sha256
    assert metadata["intended_use"] == (
        PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT.value
    )
    assert metadata["policy_route_sha256"] == routing.route.route_sha256
    with pytest.raises(TypeError):
        metadata["exact_model_id"] = excluded_id  # type: ignore[index]

    routing_payload = routing.model_dump()
    routing_payload.pop("intended_use")
    with pytest.raises(ValidationError, match="intended_use"):
        AuditModelRoutingEvidence.model_validate(routing_payload)
    routing_payload = routing.model_dump()
    routing_payload["runtime_authorized"] = 0
    with pytest.raises(ValidationError, match="literal boolean"):
        AuditModelRoutingEvidence.model_validate(routing_payload)
    routing_payload = routing.model_dump()
    routing_payload["routing_evidence_sha256"] = _hash("tampered-routing")
    with pytest.raises(ValidationError, match="self-hash is inconsistent"):
        AuditModelRoutingEvidence.model_validate(routing_payload)

    with pytest.raises(TypeError, match="only be issued"):
        VerifiedAuditModelSelection()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)
    forged = object.__new__(VerifiedAuditModelSelection)
    with pytest.raises(ValueError, match="absent or forged"):
        forged.require_current(now=use_time, **bindings)
    with pytest.raises(ValueError, match="expired"):
        capability.require_current(now=capability.expires_at, **bindings)


def test_audit_selection_rejects_cross_audit_binding_reuse_at_every_runtime_api(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    other_audit = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        context_tag="other-audit",
    )
    authority = _policy_authority(tmp_path, policy)
    _selection, _evidence_bundle, capability = _resolve(technical, policy, authority)
    selected_id = capability.models[0].exact_model_id
    use_time = authority.verified_at + timedelta(minutes=2)
    expected = _runtime_bindings(policy)

    with pytest.raises(ValueError, match="differs from expected audit bindings"):
        capability.require_current(
            now=use_time,
            **{
                **expected,
                "expected_audit_scope_sha256": other_audit.audit_context.audit_scope_sha256,
            },
        )
    with pytest.raises(ValueError, match="differs from expected audit bindings"):
        capability.model_for(
            selected_id,
            now=use_time,
            **{
                **expected,
                "expected_source_sha256": other_audit.audit_context.source_sha256,
            },
        )
    with pytest.raises(ValueError, match="differs from expected audit bindings"):
        capability.routing_evidence(
            selected_id,
            now=use_time,
            **{
                **expected,
                "expected_audit_context_sha256": other_audit.audit_context.context_sha256,
            },
        )
    with pytest.raises(ValueError, match="differs from expected audit bindings"):
        capability.request_metadata(
            selected_id,
            now=use_time,
            **{
                **expected,
                "expected_client_constraints_sha256": (
                    other_audit.client_constraints.constraints_sha256
                ),
            },
        )
    with pytest.raises(ValueError, match="must be exact SHA-256"):
        capability.require_current(
            now=use_time,
            **{**expected, "expected_source_sha256": "not-a-sha256"},
        )


def test_audit_selection_rejects_fewer_than_eight_policy_eligible_models(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded = frozenset(model.exact_model_id for model in technical.models[-2:])
    policy = _policy_bundle(technical, excluded_ids=excluded)
    authority = _policy_authority(tmp_path, policy)

    assert len(policy.evaluation.eligible_model_ids) == 7
    with pytest.raises(ValueError, match="at least eight policy-eligible"):
        _resolve(technical, policy, authority)


def test_audit_selection_rejects_fewer_than_six_policy_eligible_root_lineages(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    uniquely_rooted_id = technical.models[3].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({uniquely_rooted_id}))
    authority = _policy_authority(tmp_path, policy)

    assert len(policy.evaluation.eligible_model_ids) == 8
    assert (
        len(
            {
                model.root_lineage
                for model in technical.models
                if model.exact_model_id in policy.evaluation.eligible_model_ids
            }
        )
        == 5
    )
    with pytest.raises(ValueError, match="at least six policy-eligible root lineages"):
        _resolve(technical, policy, authority)


def test_audit_selection_rejects_route_mismatch_forged_authority_and_source_drift(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)
    route_mismatch = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        first_endpoint_override="openrouter/provider-b",
    )
    route_authority = _policy_authority(tmp_path / "route", route_mismatch)

    with pytest.raises(ValueError, match="technical routes differ"):
        _resolve(technical, route_mismatch, route_authority)
    forged = object.__new__(TrustedModelPolicyEligibilitySelectionVerification)
    with pytest.raises(ValueError, match="absent or forged"):
        _resolve(technical, policy, authority, trusted_policy_verification=forged)
    with pytest.raises(ValueError, match="absent or forged"):
        _resolve(technical, policy, authority, trusted_policy_verification=None)

    drifted = _source_observation(
        policy,
        observed_at=authority.verified_at + timedelta(minutes=1),
        current_content_sha256=_hash("changed-policy-source"),
    )
    with pytest.raises(ValueError, match="requires review"):
        _resolve(technical, policy, authority, source_observation=drifted)

    caller_built_later = _source_observation(
        policy,
        observed_at=authority.verified_at + timedelta(minutes=1),
    )
    copied_later = PolicyEligibilitySourceObservation.model_validate_json(
        caller_built_later.model_dump_json(),
        strict=True,
    )
    with pytest.raises(ValueError, match="not independently authorized"):
        _resolve(technical, policy, authority, source_observation=copied_later)


def test_audit_selection_rejects_mismatched_or_expired_live_authority(tmp_path: Path) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    first = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        context_tag="first",
    )
    second = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        context_tag="second",
    )
    authority = _policy_authority(tmp_path, first)

    with pytest.raises(ValueError, match=r"differs from (policy evidence|its artifact)"):
        _resolve(technical, second, authority)
    with pytest.raises(ValueError, match="currently valid"):
        _resolve(
            technical,
            first,
            authority,
            selected_at=authority.expires_at,
        )
    with pytest.raises(ValueError, match="production qualification is expired"):
        _resolve(
            technical,
            first,
            authority,
            selected_at=technical.expires_at,
        )
    forged_technical = object.__new__(VerifiedProductionQualification)
    with pytest.raises(ValueError, match="invalid capability type"):
        _resolve(
            forged_technical,
            first,
            authority,
        )


def test_public_or_synthetic_policy_authority_cannot_select_paid_audit_models(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        intended_use=PolicyUsePurpose.PUBLIC_OR_SYNTHETIC_DEFENSIVE_EVALUATION,
    )
    authority = _policy_authority(tmp_path, policy)

    with pytest.raises(ValueError, match="paid customer-facing intended use"):
        _resolve(technical, policy, authority)


def test_durable_audit_selection_rejects_tampering_and_boolean_coercion(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)
    selection, _evidence_bundle, _capability = _resolve(technical, policy, authority)
    payload = selection.model_dump()
    payload["selection_sha256"] = _hash("tampered")
    with pytest.raises(ValidationError, match="self-hash is inconsistent"):
        AuditModelSelection.model_validate(payload)

    payload = selection.model_dump()
    payload["policy_selection_authorized"] = 0
    with pytest.raises(ValidationError, match="literal booleans"):
        AuditModelSelection.model_validate(payload)


def test_durable_audit_selection_evidence_rejects_omission_tamper_and_coercion(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)
    _selection, evidence_bundle, _capability = _resolve(technical, policy, authority)

    assert (
        AuditModelSelectionEvidenceBundle.model_validate_json(
            evidence_bundle.model_dump_json(),
            strict=True,
        )
        == evidence_bundle
    )

    payload = evidence_bundle.model_dump()
    payload.pop("policy_artifact")
    with pytest.raises(ValidationError, match="policy_artifact"):
        AuditModelSelectionEvidenceBundle.model_validate(payload)

    payload = evidence_bundle.model_dump()
    payload["bundle_sha256"] = _hash("tampered-bundle")
    with pytest.raises(ValidationError, match="self-hash is inconsistent"):
        AuditModelSelectionEvidenceBundle.model_validate(payload)

    payload = evidence_bundle.model_dump()
    payload["policy_selection_authorized"] = 0
    with pytest.raises(ValidationError, match="literal booleans"):
        AuditModelSelectionEvidenceBundle.model_validate(payload)


def test_detached_evidence_crypto_replay_rejects_coherently_resealed_bad_signature(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)
    selection, evidence_bundle, _capability = _resolve(technical, policy, authority)
    projection = evidence_bundle.policy_authority_evidence

    signature_lines = projection.authority_envelope.detached_signature.splitlines(keepends=True)
    encoded_line = signature_lines[1]
    signature_lines[1] = ("A" if encoded_line[0] != "A" else "B") + encoded_line[1:]
    tampered_envelope = build_model_policy_eligibility_authority_envelope(
        statement=projection.authority_statement,
        detached_signature="".join(signature_lines),
    )
    receipt_payload = projection.verification_receipt.model_dump()
    receipt_payload["signature_sha256"] = tampered_envelope.signature_sha256
    receipt_payload["authority_envelope_sha256"] = tampered_envelope.authority_envelope_sha256
    receipt_hash_payload = projection.verification_receipt.model_dump(mode="json")
    receipt_hash_payload["signature_sha256"] = tampered_envelope.signature_sha256
    receipt_hash_payload["authority_envelope_sha256"] = tampered_envelope.authority_envelope_sha256
    receipt_payload["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in receipt_hash_payload.items() if key != "receipt_sha256"}
    )
    tampered_receipt = ModelPolicyEligibilityAuthorityVerificationReceipt.model_validate(
        receipt_payload
    )
    tampered_projection = build_model_policy_eligibility_authority_evidence_projection(
        initial_source_observation=projection.initial_source_observation,
        statement=projection.authority_statement,
        envelope=tampered_envelope,
        trust_anchor=projection.trust_anchor,
        receipt=tampered_receipt,
    )
    selection_payload = selection.model_dump()
    selection_payload["policy_authority_envelope_sha256"] = (
        tampered_envelope.authority_envelope_sha256
    )
    selection_payload["policy_authority_receipt_sha256"] = tampered_receipt.receipt_sha256
    selection_hash_payload = selection.model_dump(mode="json")
    selection_hash_payload["policy_authority_envelope_sha256"] = (
        tampered_envelope.authority_envelope_sha256
    )
    selection_hash_payload["policy_authority_receipt_sha256"] = tampered_receipt.receipt_sha256
    selection_payload["selection_sha256"] = canonical_sha256(
        {key: value for key, value in selection_hash_payload.items() if key != "selection_sha256"}
    )
    tampered_selection = AuditModelSelection.model_validate(selection_payload)
    coherently_resealed = build_audit_model_selection_evidence_bundle(
        selection=tampered_selection,
        policy_artifact=evidence_bundle.policy_artifact,
        policy_evaluation=evidence_bundle.policy_evaluation,
        audit_context=evidence_bundle.audit_context,
        client_constraints=evidence_bundle.client_constraints,
        current_source_observation=evidence_bundle.current_source_observation,
        policy_authority_evidence=tampered_projection,
    )

    with pytest.raises(ValueError, match=r"signature (verification failed|is not trusted)"):
        verify_audit_model_selection_evidence_bundle(
            evidence_bundle=coherently_resealed,
            **_detached_evidence_bindings(tampered_selection, authority),
        )


def test_detached_evidence_requires_independently_frozen_selection_hash_for_technical_join(
    tmp_path: Path,
) -> None:
    technical = _technical_qualification()
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(technical, excluded_ids=frozenset({excluded_id}))
    authority = _policy_authority(tmp_path, policy)
    selection, evidence_bundle, _capability = _resolve(technical, policy, authority)

    model_payload = selection.models[0].model_dump()
    model_hash_payload = selection.models[0].model_dump(mode="json")
    forged_root = f"sha256:{_hash('coherently-resealed-root')}"
    model_payload["root_lineage"] = forged_root
    model_hash_payload["root_lineage"] = forged_root
    model_payload["selected_model_sha256"] = canonical_sha256(
        {key: value for key, value in model_hash_payload.items() if key != "selected_model_sha256"}
    )
    tampered_model = AuditSelectedTechnicalModel.model_validate(model_payload)
    tampered_models = (tampered_model, *selection.models[1:])

    selection_payload = selection.model_dump()
    selection_hash_payload = selection.model_dump(mode="json")
    selection_payload["models"] = tampered_models
    selection_hash_payload["models"] = [model.model_dump(mode="json") for model in tampered_models]
    tampered_model_set_sha256 = canonical_sha256(selection_hash_payload["models"])
    selection_payload["selected_model_set_sha256"] = tampered_model_set_sha256
    selection_hash_payload["selected_model_set_sha256"] = tampered_model_set_sha256
    selection_payload["selection_sha256"] = canonical_sha256(
        {key: value for key, value in selection_hash_payload.items() if key != "selection_sha256"}
    )
    tampered_selection = AuditModelSelection.model_validate(selection_payload)
    coherently_resealed = build_audit_model_selection_evidence_bundle(
        selection=tampered_selection,
        policy_artifact=evidence_bundle.policy_artifact,
        policy_evaluation=evidence_bundle.policy_evaluation,
        audit_context=evidence_bundle.audit_context,
        client_constraints=evidence_bundle.client_constraints,
        current_source_observation=evidence_bundle.current_source_observation,
        policy_authority_evidence=evidence_bundle.policy_authority_evidence,
    )

    with pytest.raises(ValueError, match="independently authorized technical evidence"):
        verify_audit_model_selection_evidence_bundle(
            evidence_bundle=coherently_resealed,
            **_detached_evidence_bindings(selection, authority),
        )

    # A caller-derived replacement hash is not authority and therefore proves only structure.
    assert (
        verify_audit_model_selection_evidence_bundle(
            evidence_bundle=coherently_resealed,
            **_detached_evidence_bindings(tampered_selection, authority),
        )
        == coherently_resealed
    )
