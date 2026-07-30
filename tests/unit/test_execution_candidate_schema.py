"""Schema boundaries for deterministic execution-originated findings."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateOriginKind,
    Evidence,
    EvidenceStrength,
    ExecutionEvidenceKind,
    Finding,
    FindingOriginKind,
    FindingStatus,
    InvariantExecutionCandidateProvenance,
    Location,
    LocationValidation,
    Severity,
    VerificationTest,
    execution_origin_location_validation_sha256,
)


def _provenance(
    *,
    suffix: str = "a",
    path: str = "src/SyntheticVault.sol",
    **updates: Any,
) -> InvariantExecutionCandidateProvenance:
    values: dict[str, Any] = {
        "invariant_id": f"invariant-{suffix}",
        "invariant_evidence_sha256": "1" * 64,
        "harness_name": f"SyntheticHarness{suffix.upper()}",
        "harness_spec_sha256": "2" * 64,
        "property_corpus_sha256": "3" * 64,
        "property_ids": (
            f"prop-{suffix * 24}",
            f"prop-{'f' * 24}",
        ),
        "property_hashes": (
            suffix * 64,
            "f" * 64,
        ),
        "execution_result_sha256": "4" * 64,
        "execution_observation_sha256": "5" * 64,
        "executable_sha256": "6" * 64,
        "source_sha256": "7" * 64,
        "compiler_version": "forge 1.5.0 / solc 0.8.30",
        "compiler_sha256": "8" * 64,
        "isolation_backend": "rootless-container",
        "isolation_attestation_sha256": "9" * 64,
        "attempts": 2,
        "successful_attempts": 2,
        "minimized": True,
        "source_locations": (
            Location(
                path=path,
                start_line=11,
                end_line=14,
                symbol="account",
                content_hash=suffix * 64,
            ),
        ),
    }
    values.update(updates)
    return InvariantExecutionCandidateProvenance.sealed(**values)


def _execution_candidate(
    provenance: InvariantExecutionCandidateProvenance,
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        origin_kind=CandidateOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=provenance,
        title="Synthetic invariant counterexample",
        severity=Severity.HIGH,
        confidence=0.9,
        summary="Repeated execution observed an incorrect state transition.",
        impact="The declared accounting invariant does not hold.",
        preconditions=["The synthetic local harness reaches the affected state transition."],
        locations=list(provenance.source_locations),
        attack_path=["A bounded local campaign reaches the violated invariant."],
        evidence=[
            Evidence(
                type="execution",
                source="mmaudit-foundry-invariant",
                description="Repeated local execution produced the same counterexample.",
                rule_id=provenance.invariant_id,
                fingerprint=provenance.provenance_sha256,
            )
        ],
        false_positive_conditions=["The typed invariant does not express intended behavior."],
        recommendation="Correct the state transition and rerun the invariant campaign.",
        verification_test=VerificationTest(
            description="Replay the typed invariant in a fresh isolated workspace."
        ),
        role=None,
        model_family=None,
    )


def _execution_finding(
    *provenances: InvariantExecutionCandidateProvenance,
) -> Finding:
    ordered = tuple(sorted(provenances, key=lambda item: item.provenance_sha256))
    locations_by_key = {
        (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
            location.content_hash or "",
        ): location
        for provenance in ordered
        for location in provenance.source_locations
    }
    return Finding(
        id="finding-execution-origin",
        group_id="group-execution-origin",
        origin_kind=FindingOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=ordered,
        title="Synthetic invariant counterexample",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        confidence=0.9,
        summary="Repeated execution observed an incorrect state transition.",
        impact="The declared accounting invariant does not hold.",
        preconditions=["The synthetic local harness reaches the affected state transition."],
        locations=[locations_by_key[key] for key in sorted(locations_by_key)],
        attack_path=["A bounded local campaign reaches the violated invariant."],
        evidence=[
            Evidence(
                type="execution",
                source="mmaudit-foundry-invariant",
                description="Repeated local execution produced the same counterexample.",
                rule_id=provenance.invariant_id,
                fingerprint=provenance.provenance_sha256,
            )
            for provenance in ordered
        ],
        false_positive_conditions=["The typed invariant does not express intended behavior."],
        recommendation="Correct the state transition and rerun the invariant campaign.",
        verification_test=VerificationTest(
            description="Replay the typed invariant in a fresh isolated workspace."
        ),
        location_validation=LocationValidation(
            valid=True,
            content_hash=execution_origin_location_validation_sha256(ordered),
        ),
        contributing_candidate_ids=[
            f"exec-{provenance.provenance_sha256[:24]}" for provenance in ordered
        ],
        evidence_strength=EvidenceStrength.DETERMINISTIC_EXECUTION_COUNTEREXAMPLE,
    )


def test_execution_provenance_and_candidate_round_trip() -> None:
    provenance = _provenance()
    candidate = _execution_candidate(provenance)

    assert provenance.execution_evidence is ExecutionEvidenceKind.REAL
    assert provenance.replay_confirmed is True
    assert (
        InvariantExecutionCandidateProvenance.model_validate_json(provenance.model_dump_json())
        == provenance
    )
    assert CandidateFinding.model_validate_json(candidate.model_dump_json()) == candidate


def test_execution_provenance_rejects_noncanonical_or_tampered_content() -> None:
    with pytest.raises(ValueError, match="derived"):
        _provenance(provenance_sha256="0" * 64)
    with pytest.raises(ValidationError, match="property IDs"):
        _provenance(property_ids=("prop-" + ("f" * 24), "prop-" + ("a" * 24)))
    with pytest.raises(ValidationError, match="equal length"):
        _provenance(property_hashes=("a" * 64,))
    with pytest.raises(ValidationError, match="every replay attempt"):
        _provenance(attempts=3, successful_attempts=2)
    with pytest.raises(ValidationError, match="content-hashed"):
        _provenance(
            source_locations=(
                Location(
                    path="src/SyntheticVault.sol",
                    start_line=11,
                    end_line=14,
                    symbol="account",
                ),
            )
        )

    payload = _provenance().model_dump(mode="python")
    payload["compiler_version"] = "tampered compiler"
    with pytest.raises(ValidationError, match="hash does not match"):
        InvariantExecutionCandidateProvenance.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("candidate_id", "exec-wrong", "candidate ID"),
        ("role", "model-role", "model role"),
        ("model_family", "model-family", "model role"),
    ],
)
def test_execution_candidate_rejects_origin_identity_tampering(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _execution_candidate(_provenance()).model_dump(mode="python")
    payload[field] = value

    with pytest.raises(ValidationError, match=message):
        CandidateFinding.model_validate(payload)


def test_execution_candidate_requires_exact_locations_and_bound_nonmodel_evidence() -> None:
    candidate = _execution_candidate(_provenance())

    wrong_location = candidate.model_dump(mode="python")
    wrong_location["locations"][0]["start_line"] = 12
    with pytest.raises(ValidationError, match="locations must exactly match"):
        CandidateFinding.model_validate(wrong_location)

    wrong_binding = candidate.model_dump(mode="python")
    wrong_binding["evidence"][0]["fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="bind the exact provenance"):
        CandidateFinding.model_validate(wrong_binding)

    duplicate_execution = candidate.model_dump(mode="python")
    duplicate_execution["evidence"].append(dict(duplicate_execution["evidence"][0]))
    with pytest.raises(ValidationError, match="exactly one execution evidence"):
        CandidateFinding.model_validate(duplicate_execution)

    model_evidence = candidate.model_dump(mode="python")
    model_evidence["evidence"].append(
        {
            "type": "model",
            "source": "reviewer",
            "description": "A model opinion cannot become origin evidence.",
        }
    )
    with pytest.raises(ValidationError, match="cannot contain model evidence"):
        CandidateFinding.model_validate(model_evidence)


def test_model_candidate_defaults_remain_compatible_and_forbid_execution_provenance() -> None:
    candidate = CandidateFinding(
        candidate_id="candidate-model",
        title="Model-reviewed concern",
        severity=Severity.MEDIUM,
        confidence=0.7,
        summary="A model identified a concern for independent validation.",
        impact="The concern may affect expected behavior.",
        preconditions=["The affected path is reachable."],
        locations=[
            Location(
                path="src/SyntheticVault.sol",
                start_line=20,
                end_line=22,
                content_hash="c" * 64,
            )
        ],
        attack_path=["Review the affected path."],
        evidence=[
            Evidence(
                type="model",
                source="specialist",
                description="Structured model review record.",
            )
        ],
        false_positive_conditions=["The reported path is unreachable."],
        recommendation="Validate and remediate the affected path.",
        verification_test=VerificationTest(description="Run a safe local regression test."),
        role="business_logic",
        model_family="author/model-family",
    )

    assert candidate.origin_kind is CandidateOriginKind.MODEL_REVIEW
    assert candidate.execution_provenance is None

    payload = candidate.model_dump(mode="python")
    payload["role"] = None
    with pytest.raises(ValidationError, match="non-empty role and family"):
        CandidateFinding.model_validate(payload)

    payload = candidate.model_dump(mode="python")
    payload["execution_provenance"] = _provenance().model_dump(mode="python")
    with pytest.raises(ValidationError, match="cannot claim execution provenance"):
        CandidateFinding.model_validate(payload)


def test_execution_finding_round_trip_and_exact_origin_bindings() -> None:
    provenance = _provenance()
    finding = _execution_finding(provenance)

    assert Finding.model_validate_json(finding.model_dump_json()) == finding

    missing_group = finding.model_dump(mode="python")
    missing_group["group_id"] = None
    with pytest.raises(ValidationError, match="group ID"):
        Finding.model_validate(missing_group)

    missing_provenance = finding.model_dump(mode="python")
    missing_provenance["execution_provenance"] = ()
    with pytest.raises(ValidationError, match="typed provenance"):
        Finding.model_validate(missing_provenance)

    missing_candidate = finding.model_dump(mode="python")
    missing_candidate["contributing_candidate_ids"] = []
    with pytest.raises(ValidationError, match="provenance-derived candidate ID"):
        Finding.model_validate(missing_candidate)

    wrong_location = finding.model_dump(mode="python")
    wrong_location["locations"][0]["end_line"] = 15
    with pytest.raises(ValidationError, match="locations must exactly match"):
        Finding.model_validate(wrong_location)

    model_only = finding.model_dump(mode="python")
    model_only["evidence"] = [
        Evidence(
            type="model",
            source="synthetic-review",
            description="A model cannot replace deterministic origin evidence.",
        ).model_dump(mode="python")
    ]
    with pytest.raises(ValidationError, match="exactly bind every provenance"):
        Finding.model_validate(model_only)

    invalid_location = finding.model_dump(mode="python")
    invalid_location["location_validation"] = LocationValidation(
        valid=False,
        errors=["synthetic stale source"],
    ).model_dump(mode="python")
    with pytest.raises(ValidationError, match="valid source locations"):
        Finding.model_validate(invalid_location)

    wrong_location_hash = finding.model_dump(mode="python")
    wrong_location_hash["location_validation"]["content_hash"] = "0" * 64
    with pytest.raises(ValidationError, match="differs from its provenance"):
        Finding.model_validate(wrong_location_hash)

    model_strength = finding.model_dump(mode="python")
    model_strength["evidence_strength"] = EvidenceStrength.MODEL_INFERENCE
    with pytest.raises(ValidationError, match="deterministic execution strength"):
        Finding.model_validate(model_strength)

    rejected_invalid = invalid_location
    rejected_invalid["status"] = FindingStatus.REJECTED
    assert Finding.model_validate(rejected_invalid).status is FindingStatus.REJECTED


def test_execution_finding_requires_canonical_provenance_order() -> None:
    first = _provenance(suffix="a", path="src/A.sol")
    second = _provenance(suffix="b", path="src/B.sol")
    finding = _execution_finding(first, second)
    payload = finding.model_dump(mode="python")
    payload["execution_provenance"] = list(reversed(payload["execution_provenance"]))

    with pytest.raises(ValidationError, match="unique and sorted"):
        Finding.model_validate(payload)


def test_nonexecution_finding_forbids_execution_provenance() -> None:
    provenance = _provenance()
    finding = _execution_finding(provenance)
    payload = finding.model_dump(mode="python")
    payload["origin_kind"] = FindingOriginKind.STATIC_ANALYZER
    payload["execution_provenance"] = ()

    static_finding = Finding.model_validate(payload)
    assert static_finding.origin_kind is FindingOriginKind.STATIC_ANALYZER

    payload["execution_provenance"] = (provenance.model_dump(mode="python"),)
    with pytest.raises(ValidationError, match="cannot claim execution provenance"):
        Finding.model_validate(payload)
