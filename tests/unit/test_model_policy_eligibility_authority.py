from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.models.policy_eligibility_authority as policy_authority_module
from mmaudit.models.policy_eligibility import (
    ClientConstraintMode,
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyAuditContext,
    PolicyCriterionDisposition,
    PolicyEligibilityDecision,
    PolicyEligibilityEvaluation,
    PolicyEligibilityRoute,
    PolicyEligibilitySourceReferenceObservation,
    PolicyEvidenceKind,
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
    policy_eligibility_candidate_routes_sha256,
)
from mmaudit.models.policy_eligibility_authority import (
    POLICY_ELIGIBILITY_AUTHORITY_FILENAME,
    POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
    ModelPolicyEligibilityAuthorityEnvelope,
    ModelPolicyEligibilityAuthorityError,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    ModelPolicyEligibilityTrustAnchor,
    PolicyEligibilitySourceObservation,
    TrustedModelPolicyEligibilitySelectionVerification,
    build_model_policy_eligibility_authority_envelope,
    build_model_policy_eligibility_authority_statement,
    build_model_policy_eligibility_trust_anchor,
    build_policy_eligibility_source_commitment,
    build_policy_eligibility_source_observation,
    load_model_policy_eligibility_authority_envelope,
    load_model_policy_eligibility_trust_anchor,
    model_policy_eligibility_authority_statement_bytes,
    trusted_policy_eligibility_ssh_keygen_sha256,
    verify_operator_model_policy_eligibility_authority,
    write_model_policy_eligibility_authority_envelope,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacySourceClassification
from mmaudit.release_io import write_json_evidence

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _PolicyBundle:
    artifact: ModelPolicyEligibilityArtifact
    evaluation: PolicyEligibilityEvaluation
    audit_context: PolicyAuditContext
    client_constraints: ClientPolicyConstraints
    routes: tuple[PolicyEligibilityRoute, ...]


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _bundle(
    *,
    evidence_tag: str = "a",
    context_tag: str = "a",
    constraint_tag: str = "a",
    exact_model_id: str = "openai/gpt-4.1",
    provider_name: str = "Synthetic Provider",
    provider_endpoint: str = "openrouter/provider-a",
    deny_route: bool = False,
) -> _PolicyBundle:
    route = build_policy_eligibility_route(
        exact_model_id=exact_model_id,
        provider_name=provider_name,
        provider_endpoint=provider_endpoint,
    )
    evidence = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.COMMERCIAL_TERMS,
        publisher="Synthetic Provider",
        official_source_url="https://example.invalid/official-policy",
        retrieved_at=BASE_TIME,
        content_sha256=_hash(f"policy-content-{evidence_tag}"),
        byte_count=128,
        source_version="synthetic-v1",
    )
    assessments = tuple(
        build_policy_criterion_assessment(
            criterion=criterion,
            disposition=PolicyCriterionDisposition.PERMITTED,
            evidence_reference_sha256s=(evidence.reference_sha256,),
            assessment_record_sha256=_hash(f"assessment-{evidence_tag}-{criterion.value}"),
        )
        for criterion in sorted(PolicyLegalCriterion, key=lambda item: item.value)
    )
    determination = build_model_policy_eligibility_determination(
        route=route,
        decision=PolicyEligibilityDecision.ELIGIBLE,
        assessments=assessments,
        intended_use=PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
        applicable_client_entity_sha256s=(_hash(f"client-{context_tag}"),),
        applicable_client_jurisdictions=("GB",),
        applicable_operator_entity_sha256s=(_hash("operator-entity"),),
        applicable_operator_jurisdictions=("GB",),
        reviewed_by="synthetic-policy-reviewer",
        reviewed_at=BASE_TIME + timedelta(hours=1),
        effective_at=BASE_TIME + timedelta(hours=2),
        expires_at=BASE_TIME + timedelta(days=15),
        review_record_sha256=_hash(f"review-{evidence_tag}"),
    )
    artifact = build_model_policy_eligibility_artifact(
        created_at=BASE_TIME + timedelta(hours=3),
        official_evidence=(evidence,),
        determinations=(determination,),
    )
    audit_context = build_policy_audit_context(
        audit_scope_sha256=_hash(f"audit-scope-{context_tag}"),
        source_sha256=_hash(f"source-{context_tag}"),
        source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        client_entity_sha256=_hash(f"client-{context_tag}"),
        client_jurisdiction="GB",
        operator_entity_sha256=_hash("operator-entity"),
        operator_jurisdiction="GB",
        intended_use=PolicyUsePurpose.PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT,
    )
    constraints = build_client_policy_constraints(
        audit_context=audit_context,
        mode=ClientConstraintMode.DENY_ONLY,
        provider_names=(),
        exact_model_ids=(route.exact_model_id,) if deny_route else (),
        exact_routes=(),
        reviewed_by="synthetic-client-reviewer",
        reviewed_at=BASE_TIME + timedelta(hours=1),
        effective_at=BASE_TIME + timedelta(hours=2),
        expires_at=BASE_TIME + timedelta(days=10),
        constraint_basis_sha256=_hash(f"constraint-{constraint_tag}"),
    )
    routes = (route,)
    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=constraints,
        audit_context=audit_context,
        technical_routes=routes,
        observed_at=BASE_TIME + timedelta(days=1),
    )
    return _PolicyBundle(
        artifact=artifact,
        evaluation=evaluation,
        audit_context=audit_context,
        client_constraints=constraints,
        routes=routes,
    )


def _source_observation(
    bundle: _PolicyBundle,
    *,
    observed_at: datetime | None = None,
    expires_at: datetime | None = None,
    current_source_content_by_reference: dict[str, str] | None = None,
) -> PolicyEligibilitySourceObservation:
    observed = bundle.evaluation.evaluated_at if observed_at is None else observed_at
    expires = observed + timedelta(hours=12) if expires_at is None else expires_at
    commitments = tuple(
        build_policy_eligibility_source_commitment(
            artifact=bundle.artifact,
            route=route,
            source_reference_observations=_route_source_observations(
                bundle.artifact,
                route,
                current_content_by_reference=current_source_content_by_reference,
            ),
        )
        for route in bundle.evaluation.eligible_routes
    )
    return build_policy_eligibility_source_observation(
        artifact=bundle.artifact,
        observed_at=observed,
        expires_at=expires,
        source_commitments=commitments,
    )


def _route_source_observations(
    artifact: ModelPolicyEligibilityArtifact,
    route: PolicyEligibilityRoute,
    *,
    current_content_by_reference: dict[str, str] | None = None,
) -> tuple[PolicyEligibilitySourceReferenceObservation, ...]:
    evidence_by_reference = {item.reference_sha256: item for item in artifact.official_evidence}
    determination = next(
        item for item in artifact.determinations if item.route.identity == route.identity
    )
    cited_references = tuple(
        sorted(
            {
                reference_sha256
                for assessment in determination.assessments
                for reference_sha256 in assessment.evidence_reference_sha256s
            }
        )
    )
    return tuple(
        build_policy_eligibility_source_reference_observation(
            reference=evidence_by_reference[reference_sha256],
            current_content_sha256=(
                evidence_by_reference[reference_sha256].content_sha256
                if current_content_by_reference is None
                else current_content_by_reference.get(
                    reference_sha256,
                    evidence_by_reference[reference_sha256].content_sha256,
                )
            ),
        )
        for reference_sha256 in cited_references
    )


def _multi_reference_bundle(*, shared_content: bool = False) -> _PolicyBundle:
    base = _bundle()
    first = base.artifact.official_evidence[0]
    second = build_official_policy_evidence_reference(
        kind=PolicyEvidenceKind.ROUTING_PROVIDER_TERMS,
        publisher="Synthetic Routing Provider",
        official_source_url="https://example.invalid/official-routing-policy",
        retrieved_at=BASE_TIME,
        content_sha256=(
            first.content_sha256 if shared_content else _hash("routing-policy-content")
        ),
        byte_count=96,
        source_version="synthetic-v1",
    )
    evidence = tuple(sorted((first, second), key=lambda item: item.reference_sha256))
    reference_sha256s = tuple(item.reference_sha256 for item in evidence)
    original = base.artifact.determinations[0]
    assessments = tuple(
        build_policy_criterion_assessment(
            criterion=assessment.criterion,
            disposition=assessment.disposition,
            evidence_reference_sha256s=reference_sha256s,
            assessment_record_sha256=_hash(
                f"multi-reference-assessment-{assessment.criterion.value}"
            ),
        )
        for assessment in original.assessments
    )
    determination = build_model_policy_eligibility_determination(
        route=original.route,
        decision=original.decision,
        intended_use=original.intended_use,
        applicable_client_entity_sha256s=original.applicable_client_entity_sha256s,
        applicable_client_jurisdictions=original.applicable_client_jurisdictions,
        applicable_operator_entity_sha256s=original.applicable_operator_entity_sha256s,
        applicable_operator_jurisdictions=original.applicable_operator_jurisdictions,
        assessments=assessments,
        reviewed_by=original.reviewed_by,
        reviewed_at=original.reviewed_at,
        effective_at=original.effective_at,
        expires_at=original.expires_at,
        review_record_sha256=_hash("multi-reference-review"),
    )
    artifact = build_model_policy_eligibility_artifact(
        created_at=base.artifact.created_at,
        official_evidence=evidence,
        determinations=(determination,),
    )
    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=base.client_constraints,
        audit_context=base.audit_context,
        technical_routes=base.routes,
        observed_at=base.evaluation.evaluated_at,
    )
    return _PolicyBundle(
        artifact=artifact,
        evaluation=evaluation,
        audit_context=base.audit_context,
        client_constraints=base.client_constraints,
        routes=base.routes,
    )


def _two_route_bundle() -> _PolicyBundle:
    bundle = _bundle()
    first = bundle.artifact.determinations[0]
    second_route = build_policy_eligibility_route(
        exact_model_id="openai/gpt-4.2",
        provider_name="Synthetic Provider",
        provider_endpoint="openrouter/provider-b",
    )
    second = build_model_policy_eligibility_determination(
        route=second_route,
        decision=first.decision,
        intended_use=first.intended_use,
        applicable_client_entity_sha256s=first.applicable_client_entity_sha256s,
        applicable_client_jurisdictions=first.applicable_client_jurisdictions,
        applicable_operator_entity_sha256s=first.applicable_operator_entity_sha256s,
        applicable_operator_jurisdictions=first.applicable_operator_jurisdictions,
        assessments=first.assessments,
        reviewed_by=first.reviewed_by,
        reviewed_at=first.reviewed_at,
        effective_at=first.effective_at,
        expires_at=first.expires_at,
        review_record_sha256=_hash("second-route-review"),
    )
    artifact = build_model_policy_eligibility_artifact(
        created_at=bundle.artifact.created_at,
        official_evidence=bundle.artifact.official_evidence,
        determinations=(first, second),
    )
    routes = (bundle.routes[0], second_route)
    evaluation = evaluate_model_policy_eligibility(
        artifact=artifact,
        client_constraints=bundle.client_constraints,
        audit_context=bundle.audit_context,
        technical_routes=routes,
        observed_at=bundle.evaluation.evaluated_at,
    )
    return _PolicyBundle(
        artifact=artifact,
        evaluation=evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        routes=routes,
    )


def _ssh_keygen() -> Path:
    candidate = Path("/usr/bin/ssh-keygen")
    if not candidate.is_file():
        pytest.skip("fixed system ssh-keygen is unavailable")
    return candidate


def _generate_key(root: Path, *, name: str = "operator") -> tuple[Path, str]:
    key = root / name
    result = subprocess.run(
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
    if result.returncode != 0:
        pytest.skip("system ssh-keygen cannot generate an ephemeral Ed25519 test key")
    public_key = " ".join(key.with_suffix(".pub").read_text(encoding="ascii").split()[:2])
    return key, public_key


def _sign_statement(
    *,
    root: Path,
    key: Path,
    statement: Any,
    namespace: str = POLICY_ELIGIBILITY_AUTHORITY_NAMESPACE,
    name: str = "policy-statement",
) -> bytes:
    message = root / f"{name}.json"
    message.write_bytes(model_policy_eligibility_authority_statement_bytes(statement))
    result = subprocess.run(
        [
            str(_ssh_keygen()),
            "-Y",
            "sign",
            "-f",
            str(key),
            "-n",
            namespace,
            str(message),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        shell=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return message.with_suffix(".json.sig").read_bytes()


def _signed_authority(
    *,
    root: Path,
    bundle: _PolicyBundle,
    signed_at: datetime | None = None,
    expires_at: datetime | None = None,
    source_observation: PolicyEligibilitySourceObservation | None = None,
) -> tuple[
    ModelPolicyEligibilityTrustAnchor,
    ModelPolicyEligibilityAuthorityEnvelope,
    PolicyEligibilitySourceObservation,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    TrustedModelPolicyEligibilitySelectionVerification,
]:
    key, public_key = _generate_key(root)
    anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="synthetic-policy-reviewer",
        public_key=public_key,
        verifier_executable_sha256=trusted_policy_eligibility_ssh_keygen_sha256(),
    )
    signed = bundle.evaluation.evaluated_at if signed_at is None else signed_at
    expires = signed + timedelta(hours=6) if expires_at is None else expires_at
    source = (
        _source_observation(bundle, observed_at=signed)
        if source_observation is None
        else source_observation
    )
    statement = build_model_policy_eligibility_authority_statement(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source,
        trust_anchor=anchor,
        signed_at=signed,
        expires_at=expires,
    )
    envelope = build_model_policy_eligibility_authority_envelope(
        statement=statement,
        detached_signature=_sign_statement(root=root, key=key, statement=statement),
    )
    receipt, capability = verify_operator_model_policy_eligibility_authority(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source,
        envelope=envelope,
        trust_anchor=anchor,
        expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
        expected_operator_principal=anchor.operator_principal,
        observed_at=signed + timedelta(minutes=1),
    )
    return anchor, envelope, source, receipt, capability


def test_signed_policy_authority_returns_exact_receipt_and_opaque_capability(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    anchor, envelope, source, receipt, capability = _signed_authority(root=tmp_path, bundle=bundle)

    required = capability.require_for_policy_selection(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source,
        observed_at=receipt.verified_at + timedelta(hours=1),
    )

    assert required == receipt
    assert receipt.receipt_sha256 == canonical_sha256(
        receipt.model_dump(mode="json", exclude={"receipt_sha256"})
    )
    assert receipt.artifact_sha256 == bundle.artifact.artifact_sha256
    assert receipt.evaluation_sha256 == bundle.evaluation.evaluation_sha256
    assert receipt.audit_context_sha256 == bundle.audit_context.context_sha256
    assert receipt.client_constraints_sha256 == bundle.client_constraints.constraints_sha256
    assert receipt.technical_route_set_sha256 == bundle.evaluation.technical_route_set_sha256
    assert receipt.eligible_route_set_sha256 == bundle.evaluation.eligible_route_set_sha256
    assert receipt.authority_envelope_sha256 == envelope.authority_envelope_sha256
    assert receipt.trust_anchor_sha256 == anchor.trust_anchor_sha256
    assert receipt.initial_source_observation_sha256 == source.observation_sha256
    assert receipt.source_commitment_set_sha256 == source.source_commitment_set_sha256
    assert receipt.purpose == "POLICY_SELECTION_ONLY"
    assert envelope.statement.policy_selection_authorized is True
    assert receipt.policy_selection_authorized is False
    assert receipt.qualification_authorized is False
    assert receipt.source_egress_authorized is False
    assert receipt.general_production_authorized is False
    assert not hasattr(capability, "qualification_authorized")
    assert not hasattr(capability, "source_egress_authorized")
    assert not hasattr(capability, "production_selection_authorized")

    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedModelPolicyEligibilitySelectionVerification()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)


def test_policy_authority_rejects_signature_tamper_wrong_namespace_key_and_principal(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    anchor, envelope, source, _receipt, _capability = _signed_authority(
        root=tmp_path, bundle=bundle
    )

    signature = envelope.detached_signature
    replacement = "A" if signature[40] != "A" else "B"
    corrupted = build_model_policy_eligibility_authority_envelope(
        statement=envelope.statement,
        detached_signature=signature[:40] + replacement + signature[41:],
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="not trusted"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=corrupted,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.signed_at + timedelta(minutes=1),
        )

    wrong_namespace_key, _unused_public = _generate_key(tmp_path, name="namespace-key")
    wrong_namespace = build_model_policy_eligibility_authority_envelope(
        statement=envelope.statement,
        detached_signature=_sign_statement(
            root=tmp_path,
            key=wrong_namespace_key,
            statement=envelope.statement,
            namespace="mmaudit-wrong-policy-namespace-v1",
            name="wrong-namespace",
        ),
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="not trusted"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=wrong_namespace,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.signed_at + timedelta(minutes=1),
        )

    wrong_key, _wrong_public = _generate_key(tmp_path, name="wrong-key")
    wrong_key_envelope = build_model_policy_eligibility_authority_envelope(
        statement=envelope.statement,
        detached_signature=_sign_statement(
            root=tmp_path,
            key=wrong_key,
            statement=envelope.statement,
            name="wrong-key-statement",
        ),
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="not trusted"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=wrong_key_envelope,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.signed_at + timedelta(minutes=1),
        )

    wrong_principal_anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="different-policy-reviewer",
        public_key=anchor.public_key,
        verifier_executable_sha256=anchor.verifier_executable_sha256,
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="differs"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=envelope,
            trust_anchor=wrong_principal_anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.signed_at + timedelta(minutes=1),
        )


def test_policy_authority_rejects_artifact_evaluation_audit_constraints_and_routes(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    anchor, envelope, source, _receipt, capability = _signed_authority(root=tmp_path, bundle=bundle)
    other_artifact = _bundle(evidence_tag="other").artifact
    other_evaluation = _bundle(evidence_tag="other").evaluation
    other_context = _bundle(context_tag="other").audit_context
    other_constraints = _bundle(constraint_tag="other").client_constraints
    other_routes = _bundle(
        exact_model_id="openai/gpt-4.1-mini",
        provider_endpoint="openrouter/provider-b",
    ).routes
    cases = (
        {"artifact": other_artifact},
        {"evaluation": other_evaluation},
        {"audit_context": other_context},
        {"client_constraints": other_constraints},
        {"candidate_routes": other_routes},
    )
    base: dict[str, Any] = {
        "artifact": bundle.artifact,
        "evaluation": bundle.evaluation,
        "audit_context": bundle.audit_context,
        "client_constraints": bundle.client_constraints,
        "candidate_routes": bundle.routes,
        "source_observation": source,
        "envelope": envelope,
        "trust_anchor": anchor,
        "expected_trust_anchor_sha256": anchor.trust_anchor_sha256,
        "expected_operator_principal": anchor.operator_principal,
        "observed_at": envelope.statement.signed_at + timedelta(minutes=2),
    }
    for changed in cases:
        with pytest.raises(ModelPolicyEligibilityAuthorityError, match="differs"):
            verify_operator_model_policy_eligibility_authority(**(base | changed))

    with pytest.raises(ValueError, match="differs"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=other_routes,
            source_observation=source,
            observed_at=envelope.statement.signed_at + timedelta(hours=1),
        )


def test_policy_authority_rejects_future_expiry_boundaries_and_empty_authority(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    anchor, envelope, source, _receipt, capability = _signed_authority(root=tmp_path, bundle=bundle)

    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="future-dated"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=envelope,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.signed_at - timedelta(seconds=1),
        )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="expired"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=envelope,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=envelope.statement.expires_at,
        )
    with pytest.raises(ValueError, match="currently valid"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            observed_at=envelope.statement.expires_at,
        )
    with pytest.raises(
        ModelPolicyEligibilityAuthorityError,
        match=r"future-dated|evaluation window",
    ):
        build_model_policy_eligibility_authority_statement(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            trust_anchor=anchor,
            signed_at=bundle.evaluation.evaluated_at - timedelta(seconds=1),
            expires_at=bundle.evaluation.evaluated_at + timedelta(hours=1),
        )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="evaluation window"):
        build_model_policy_eligibility_authority_statement(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            trust_anchor=anchor,
            signed_at=bundle.evaluation.evaluated_at,
            expires_at=bundle.evaluation.expires_at + timedelta(seconds=1),
        )

    denied = _bundle(deny_route=True)
    assert denied.evaluation.expires_at is None
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="without an expiry"):
        build_model_policy_eligibility_authority_statement(
            artifact=denied.artifact,
            evaluation=denied.evaluation,
            audit_context=denied.audit_context,
            client_constraints=denied.client_constraints,
            candidate_routes=denied.routes,
            source_observation=source,
            trust_anchor=anchor,
            signed_at=denied.evaluation.evaluated_at,
            expires_at=denied.evaluation.evaluated_at + timedelta(hours=1),
        )


def test_self_hashed_policy_evidence_and_receipt_cannot_forge_live_authority(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    _anchor, _envelope, source, receipt, _capability = _signed_authority(
        root=tmp_path, bundle=bundle
    )
    assert bundle.artifact.artifact_sha256
    assert bundle.evaluation.evaluation_sha256
    assert receipt.receipt_sha256
    assert bundle.artifact.production_selection_authorized is False
    assert bundle.evaluation.production_selection_authorized is False
    assert not hasattr(receipt, "require_for_policy_selection")

    forged = object.__new__(TrustedModelPolicyEligibilitySelectionVerification)
    with pytest.raises(ValueError, match="forged"):
        forged.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            observed_at=receipt.verified_at,
        )

    payload = receipt.model_dump(mode="json")
    payload["artifact_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="receipt self-hash"):
        ModelPolicyEligibilityAuthorityVerificationReceipt.model_validate_json(
            json.dumps(payload), strict=True
        )

    assert not hasattr(policy_authority_module, "_build_policy_eligibility_runtime_authority")


def test_coherently_self_hashed_forged_evaluation_fails_deterministic_replay(
    tmp_path: Path,
) -> None:
    denied = _bundle(deny_route=True)
    _key, public_key = _generate_key(tmp_path)
    anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="synthetic-policy-reviewer",
        public_key=public_key,
        verifier_executable_sha256=trusted_policy_eligibility_ssh_keygen_sha256(),
    )
    payload = denied.evaluation.model_dump(mode="json")
    payload["expires_at"] = (
        (denied.evaluation.evaluated_at + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    )
    payload["eligible_routes"] = [denied.routes[0].model_dump(mode="json")]
    payload["eligible_model_ids"] = [denied.routes[0].exact_model_id]
    payload["exclusions"] = []
    payload["eligible_route_set_sha256"] = policy_eligibility_candidate_routes_sha256(denied.routes)
    payload["evaluation_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "evaluation_sha256"}
    )
    forged = PolicyEligibilityEvaluation.model_validate_json(json.dumps(payload), strict=True)
    assert forged.eligible_routes == denied.routes
    assert denied.evaluation.eligible_routes == ()

    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="deterministic"):
        build_model_policy_eligibility_authority_statement(
            artifact=denied.artifact,
            evaluation=forged,
            audit_context=denied.audit_context,
            client_constraints=denied.client_constraints,
            candidate_routes=denied.routes,
            source_observation=_source_observation(_bundle()),
            trust_anchor=anchor,
            signed_at=forged.evaluated_at,
            expires_at=forged.evaluated_at + timedelta(hours=1),
        )


def test_policy_authority_rejects_fresh_self_hashed_anchor_without_expected_pin(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    expected_anchor, _expected_envelope, source, _receipt, _capability = _signed_authority(
        root=tmp_path,
        bundle=bundle,
    )
    fresh_key, fresh_public_key = _generate_key(tmp_path, name="fresh-untrusted-operator")
    fresh_anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal=expected_anchor.operator_principal,
        public_key=fresh_public_key,
        verifier_executable_sha256=expected_anchor.verifier_executable_sha256,
    )
    fresh_statement = build_model_policy_eligibility_authority_statement(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=source,
        trust_anchor=fresh_anchor,
        signed_at=bundle.evaluation.evaluated_at,
        expires_at=bundle.evaluation.evaluated_at + timedelta(hours=6),
    )
    fresh_envelope = build_model_policy_eligibility_authority_envelope(
        statement=fresh_statement,
        detached_signature=_sign_statement(
            root=tmp_path,
            key=fresh_key,
            statement=fresh_statement,
            name="fresh-untrusted-statement",
        ),
    )

    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="independently expected"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            envelope=fresh_envelope,
            trust_anchor=fresh_anchor,
            expected_trust_anchor_sha256=expected_anchor.trust_anchor_sha256,
            expected_operator_principal=expected_anchor.operator_principal,
            observed_at=fresh_statement.signed_at + timedelta(minutes=1),
        )


def test_policy_capability_rejects_unapproved_later_source_observations(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    _anchor, envelope, initial_source, receipt, capability = _signed_authority(
        root=tmp_path,
        bundle=bundle,
    )
    assert (
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=initial_source,
            observed_at=envelope.statement.signed_at + timedelta(minutes=1),
        )
        == receipt
    )
    newer_time = envelope.statement.signed_at + timedelta(hours=1)
    newer = _source_observation(bundle, observed_at=newer_time)
    copied_newer = PolicyEligibilitySourceObservation.model_validate_json(
        newer.model_dump_json(),
        strict=True,
    )
    with pytest.raises(ValueError, match="not independently authorized"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=copied_newer,
            observed_at=newer_time,
        )

    drifted = _source_observation(
        bundle,
        observed_at=newer_time,
        current_source_content_by_reference={
            bundle.artifact.official_evidence[0].reference_sha256: _hash("drifted-policy-source")
        },
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="requires review"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=drifted,
            observed_at=newer_time,
        )

    short_lived = _source_observation(
        bundle,
        observed_at=newer_time,
        expires_at=newer_time + timedelta(minutes=1),
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="stale"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=short_lived,
            observed_at=short_lived.expires_at,
        )

    future = _source_observation(
        bundle,
        observed_at=newer_time + timedelta(hours=1),
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="future-dated"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=future,
            observed_at=newer_time,
        )


def test_source_commitment_preserves_distinct_references_with_shared_content() -> None:
    bundle = _multi_reference_bundle(shared_content=True)
    observations = _route_source_observations(bundle.artifact, bundle.routes[0])

    commitment = build_policy_eligibility_source_commitment(
        artifact=bundle.artifact,
        route=bundle.routes[0],
        source_reference_observations=observations,
    )

    assert len(commitment.source_reference_observations) == 2
    assert len({item.reference_sha256 for item in observations}) == 2
    assert len({item.expected_content_sha256 for item in observations}) == 1
    assert len({item.current_content_sha256 for item in observations}) == 1


def test_source_commitment_rejects_missing_duplicate_reordered_and_expected_swap() -> None:
    bundle = _multi_reference_bundle()
    observations = _route_source_observations(bundle.artifact, bundle.routes[0])
    assert len(observations) == 2

    invalid_inventories = (
        observations[:-1],
        (observations[0], observations[0]),
        tuple(reversed(observations)),
    )
    for invalid in invalid_inventories:
        with pytest.raises(
            ModelPolicyEligibilityAuthorityError,
            match="exactly cover cited official references",
        ):
            build_policy_eligibility_source_commitment(
                artifact=bundle.artifact,
                route=bundle.routes[0],
                source_reference_observations=invalid,
            )

    swapped_payload = observations[0].model_dump(mode="json")
    swapped_payload["expected_content_sha256"] = observations[1].expected_content_sha256
    swapped_payload["observation_sha256"] = canonical_sha256(
        {key: value for key, value in swapped_payload.items() if key != "observation_sha256"}
    )
    swapped_expected = PolicyEligibilitySourceReferenceObservation.model_validate_json(
        json.dumps(swapped_payload),
        strict=True,
    )
    forged_inventory = tuple(
        swapped_expected if index == 0 else observation
        for index, observation in enumerate(observations)
    )
    with pytest.raises(
        ModelPolicyEligibilityAuthorityError,
        match="exactly cover cited official references",
    ):
        build_policy_eligibility_source_commitment(
            artifact=bundle.artifact,
            route=bundle.routes[0],
            source_reference_observations=forged_inventory,
        )


def test_current_content_swap_requires_review_and_cannot_issue_authority(tmp_path: Path) -> None:
    bundle = _multi_reference_bundle()
    evidence = bundle.artifact.official_evidence
    current_by_reference = {
        evidence[0].reference_sha256: evidence[1].content_sha256,
        evidence[1].reference_sha256: evidence[0].content_sha256,
    }
    source = _source_observation(
        bundle,
        current_source_content_by_reference=current_by_reference,
    )
    _key, public_key = _generate_key(tmp_path)
    anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="synthetic-policy-reviewer",
        public_key=public_key,
        verifier_executable_sha256=trusted_policy_eligibility_ssh_keygen_sha256(),
    )

    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="requires review"):
        build_model_policy_eligibility_authority_statement(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=source,
            trust_anchor=anchor,
            signed_at=bundle.evaluation.evaluated_at,
            expires_at=bundle.evaluation.evaluated_at + timedelta(hours=6),
        )


def test_policy_source_observation_cannot_omit_or_reorder_eligible_routes(
    tmp_path: Path,
) -> None:
    bundle = _two_route_bundle()
    _anchor, envelope, full_source, _receipt, capability = _signed_authority(
        root=tmp_path,
        bundle=bundle,
    )
    omitted = build_policy_eligibility_source_observation(
        artifact=bundle.artifact,
        observed_at=full_source.observed_at,
        expires_at=full_source.expires_at,
        source_commitments=(full_source.source_commitments[0],),
    )
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="every eligible route"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=omitted,
            observed_at=envelope.statement.signed_at + timedelta(minutes=2),
        )

    empty = build_policy_eligibility_source_observation(
        artifact=bundle.artifact,
        observed_at=full_source.observed_at,
        expires_at=full_source.expires_at,
        source_commitments=(),
    )
    assert empty.source_commitments == ()
    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="every eligible route"):
        capability.require_for_policy_selection(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=empty,
            observed_at=envelope.statement.signed_at + timedelta(minutes=2),
        )

    with pytest.raises(ValidationError, match="unique, and sorted"):
        build_policy_eligibility_source_observation(
            artifact=bundle.artifact,
            observed_at=full_source.observed_at,
            expires_at=full_source.expires_at,
            source_commitments=tuple(reversed(full_source.source_commitments)),
        )


def test_policy_authority_safe_loaders_reject_linked_shared_and_oversize_inputs(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    anchor, envelope, _source, _receipt, _capability = _signed_authority(
        root=tmp_path, bundle=bundle
    )
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    write_model_policy_eligibility_authority_envelope(evidence_root, envelope)
    trust_path = tmp_path / "policy-trust-anchor.json"
    write_json_evidence(
        evidence_root=tmp_path,
        relative_path=trust_path.name,
        value=anchor,
    )
    assert load_model_policy_eligibility_authority_envelope(evidence_root) == envelope
    assert load_model_policy_eligibility_trust_anchor(trust_path) == anchor

    linked_root = tmp_path / "linked"
    linked_root.mkdir(mode=0o700)
    os.symlink(
        evidence_root / POLICY_ELIGIBILITY_AUTHORITY_FILENAME,
        linked_root / POLICY_ELIGIBILITY_AUTHORITY_FILENAME,
    )
    with pytest.raises(ValueError, match="bounded unshared regular file"):
        load_model_policy_eligibility_authority_envelope(linked_root)

    shared_root = tmp_path / "shared"
    shared_root.mkdir(mode=0o700)
    shared_source = shared_root / "source.json"
    shared_source.write_bytes(envelope.model_dump_json().encode("utf-8"))
    os.link(shared_source, shared_root / POLICY_ELIGIBILITY_AUTHORITY_FILENAME)
    with pytest.raises(ValueError, match="bounded unshared regular file"):
        load_model_policy_eligibility_authority_envelope(shared_root)

    oversize_root = tmp_path / "oversize"
    oversize_root.mkdir(mode=0o700)
    (oversize_root / POLICY_ELIGIBILITY_AUTHORITY_FILENAME).write_bytes(b" " * 262_145)
    with pytest.raises(ValueError, match="bounded unshared regular file"):
        load_model_policy_eligibility_authority_envelope(oversize_root)

    unsafe_anchor = tmp_path / "linked-policy-anchor.json"
    os.symlink(trust_path, unsafe_anchor)
    with pytest.raises(ValueError, match="bounded unshared regular file"):
        load_model_policy_eligibility_trust_anchor(unsafe_anchor)


def test_policy_authority_rejects_verifier_pin_failure(tmp_path: Path) -> None:
    bundle = _bundle()
    key, public_key = _generate_key(tmp_path)
    anchor = build_model_policy_eligibility_trust_anchor(
        operator_principal="synthetic-policy-reviewer",
        public_key=public_key,
        verifier_executable_sha256="0" * 64,
    )
    statement = build_model_policy_eligibility_authority_statement(
        artifact=bundle.artifact,
        evaluation=bundle.evaluation,
        audit_context=bundle.audit_context,
        client_constraints=bundle.client_constraints,
        candidate_routes=bundle.routes,
        source_observation=_source_observation(bundle),
        trust_anchor=anchor,
        signed_at=bundle.evaluation.evaluated_at,
        expires_at=bundle.evaluation.evaluated_at + timedelta(hours=6),
    )
    envelope = build_model_policy_eligibility_authority_envelope(
        statement=statement,
        detached_signature=_sign_statement(root=tmp_path, key=key, statement=statement),
    )

    with pytest.raises(ModelPolicyEligibilityAuthorityError, match="pinned ssh-keygen"):
        verify_operator_model_policy_eligibility_authority(
            artifact=bundle.artifact,
            evaluation=bundle.evaluation,
            audit_context=bundle.audit_context,
            client_constraints=bundle.client_constraints,
            candidate_routes=bundle.routes,
            source_observation=_source_observation(bundle),
            envelope=envelope,
            trust_anchor=anchor,
            expected_trust_anchor_sha256=anchor.trust_anchor_sha256,
            expected_operator_principal=anchor.operator_principal,
            observed_at=statement.signed_at + timedelta(minutes=1),
        )
