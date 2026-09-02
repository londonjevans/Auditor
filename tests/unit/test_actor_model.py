from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import ActorModelConfig
from mmaudit.models.actor_model import (
    ActorAssessmentDisposition,
    ActorCapitalSeniority,
    ActorGovernanceConflictKind,
    ActorLikelihoodAdjustment,
    ActorModel,
    ActorModelApplicability,
    ActorModelInputEvidence,
    ActorModelInputState,
    ActorModelSourceEvidence,
    ActorRemediationFocus,
    ActorRoleOccupancy,
    CandidateActorContext,
    FindingActorAssessment,
)
from mmaudit.models.schemas import (
    Evidence,
    Finding,
    FindingStatus,
    Location,
    LocationValidation,
    Severity,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    VerificationTest,
    solidity_graph_occurrence_sha256,
)
from mmaudit.orchestration.actor_model import (
    ActorModelPathIdentityError,
    actor_model_assessment_quality_gate,
    calibrate_finding,
    load_actor_model,
    reconcile_actor_model_with_graphs,
)
from mmaudit.orchestration.scheduler_runtime import scheduler_analysis_semantic_projection

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "actor_model"
MODEL_PATH = FIXTURE_ROOT / "synthetic_orchard_actor_model.json"
SCENARIOS_PATH = FIXTURE_ROOT / "synthetic_correction_scenarios.json"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _model_payload() -> dict[str, Any]:
    payload = json.loads(MODEL_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _model_from_payload(payload: dict[str, Any]) -> ActorModel:
    return ActorModel.model_validate_json(json.dumps(payload), strict=True)


def _actor_model() -> ActorModel:
    return ActorModel.model_validate_json(MODEL_PATH.read_text(encoding="utf-8"), strict=True)


def _actor_config(path: str, *, max_bytes: int = 1_000_000) -> ActorModelConfig:
    model = _actor_model()
    return ActorModelConfig(
        path=path,
        max_bytes=max_bytes,
        expected_subject_id=model.subject_id,
        expected_model_sha256=model.artifact_sha256,
    )


def _current_actor_input() -> ActorModelInputEvidence:
    raw = MODEL_PATH.read_bytes()
    source = ActorModelSourceEvidence.build(raw=raw, actor_model=_actor_model())
    return ActorModelInputEvidence.build(
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        state=ActorModelInputState.CURRENT,
        configured=True,
        configured_path="tests/fixtures/actor_model/synthetic_orchard_actor_model.json",
        source_evidence=source,
        limitations=(),
    )


def _missing_actor_input() -> ActorModelInputEvidence:
    return ActorModelInputEvidence.build(
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        state=ActorModelInputState.MISSING,
        configured=False,
        configured_path=None,
        source_evidence=None,
        limitations=("Operator actor model was not configured for this synthetic regression.",),
    )


def _actor_input_from_payload(payload: dict[str, Any]) -> ActorModelInputEvidence:
    semantic_payload = {key: value for key, value in payload.items() if key != "artifact_sha256"}
    payload["artifact_sha256"] = _canonical_sha256(semantic_payload)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    actor_model = ActorModel.model_validate_json(raw, strict=True)
    return ActorModelInputEvidence.build(
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        state=ActorModelInputState.CURRENT,
        configured=True,
        configured_path="operator-modified-actor-model.json",
        source_evidence=ActorModelSourceEvidence.build(raw=raw, actor_model=actor_model),
        limitations=(),
    )


def _privilege_graph(
    *identifiers: str,
    provenance: SolidityProvenance = SolidityProvenance.COMPILER,
    confidence: float = 1.0,
) -> SolidityGraphSet:
    nodes = [
        SolidityGraphNode(
            id=identifier,
            kind=SolidityGraphNodeKind.ROLE,
            label=identifier,
            path="tests/fixtures/actor_model/SyntheticOrchard.sol",
            start_line=index,
            end_line=index,
            source_hash="0" * 64,
            provenance=provenance,
            confidence=confidence,
            transformation="synthetic exact role binding",
        )
        for index, identifier in enumerate(identifiers, start=1)
    ]
    occurrences = tuple(
        sorted(
            (
                SolidityGraphRetainedOccurrence(
                    subject_kind=SolidityGraphOccurrenceKind.GRAPH_NODE,
                    subject_sha256=solidity_graph_occurrence_sha256(
                        SolidityGraphOccurrenceKind.GRAPH_NODE,
                        node,
                    ),
                    occurrence_count=1,
                )
                for node in nodes
            ),
            key=lambda item: (item.subject_kind.value, item.subject_sha256),
        )
    )
    return SolidityGraphSet(
        nodes=nodes,
        edges=[],
        retained_occurrences=occurrences,
        analyzed_graphs=[SolidityGraphKind.PRIVILEGE],
    )


def _scenario_payload() -> dict[str, Any]:
    payload = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _finding(
    *,
    finding_id: str,
    severity: Severity,
    actor_context: CandidateActorContext,
) -> Finding:
    return Finding(
        id=finding_id,
        group_id=f"group-{finding_id}",
        title="Synthetic actor-plausibility regression",
        status=FindingStatus.CONFIRMED,
        severity=severity,
        confidence=0.9,
        summary="A synthetic state transition requires explicit actor evidence.",
        impact="The synthetic accounting invariant may be violated.",
        preconditions=["The declared synthetic role can reach the bounded local transition."],
        locations=[
            Location(
                path="tests/fixtures/actor_model/SyntheticOrchard.sol",
                start_line=1,
                end_line=1,
                symbol="syntheticTransition",
            )
        ],
        attack_path=["Exercise only the synthetic local transition."],
        evidence=[
            Evidence(
                type="repository",
                source="synthetic actor-model fixture",
                description="The regression contains no live address or deployable target.",
            )
        ],
        false_positive_conditions=["Operator-authored actor evidence changes before the run."],
        recommendation="Retain the typed actor assumption in defensive review evidence.",
        verification_test=VerificationTest(
            description="Replay the provider-free synthetic actor calibration."
        ),
        location_validation=LocationValidation(valid=True),
        actor_model_applicability=ActorModelApplicability.PRIVILEGED_ACTOR_REQUIRED,
        actor_context=actor_context,
    )


def test_fixture_is_versioned_operator_authored_and_self_hashed() -> None:
    model = _actor_model()
    semantic_payload = model.model_dump(mode="json", exclude={"artifact_sha256"})

    assert model.schema_version == "1.0"
    assert model.authorship == "operator_authored"
    assert model.artifact_sha256 == _canonical_sha256(semantic_payload)

    build_values = {
        field_name: getattr(model, field_name)
        for field_name in ActorModel.model_fields
        if field_name != "artifact_sha256"
    }
    rebuilt = ActorModel.build(**build_values)
    assert rebuilt == model


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("schema_version", "2.0", "Input should be '1.0'"),
        ("authorship", "model_inferred", "Input should be 'operator_authored'"),
        ("artifact_sha256", "0" * 64, "artifact hash differs"),
    ],
)
def test_actor_model_rejects_version_authorship_and_hash_tampering(
    field: str,
    replacement: str,
    message: str,
) -> None:
    payload = _model_payload()
    payload[field] = replacement

    with pytest.raises(ValidationError, match=message):
        _model_from_payload(payload)


@pytest.mark.parametrize(
    ("field_path", "field_name"),
    [
        ((), "schema_version"),
        ((), "authorship"),
        (("roles", 0), "concentrated_with_role_ids"),
    ],
)
def test_actor_model_requires_explicit_version_authorship_and_role_concentration(
    field_path: tuple[str | int, ...],
    field_name: str,
) -> None:
    payload = _model_payload()
    target: Any = payload
    for component in field_path:
        target = target[component]
    target.pop(field_name)

    with pytest.raises(ValidationError, match="Field required"):
        _model_from_payload(payload)


def test_role_occupancy_and_holder_concentration_are_exact() -> None:
    model = _actor_model()
    anchor = model.role("anchor_curator")
    risk_council = model.role("risk_council")
    prospective = model.role("third_party_curator")

    assert anchor is not None
    assert anchor.occupancy is ActorRoleOccupancy.CURRENTLY_HELD
    assert anchor.holder_party_id == "anchor-party"
    assert anchor.concentrated_with_role_ids == ("risk_council",)
    assert risk_council is not None
    assert risk_council.concentrated_with_role_ids == ("anchor_curator",)
    assert prospective is not None
    assert prospective.occupancy is ActorRoleOccupancy.ADMITTED_UNFILLED
    assert prospective.holder_party_id is None
    assert prospective.admitted_holder_class == "approved synthetic third-party curator"


@pytest.mark.parametrize("mutation", ["holder", "concentration"])
def test_actor_model_rejects_inexact_occupancy_or_concentration(mutation: str) -> None:
    payload = _model_payload()
    roles = payload["roles"]
    assert isinstance(roles, list)
    if mutation == "holder":
        prospective = next(role for role in roles if role["role_id"] == "third_party_curator")
        prospective["holder_party_id"] = "anchor-party"
    else:
        anchor = next(role for role in roles if role["role_id"] == "anchor_curator")
        anchor["concentrated_with_role_ids"] = []

    with pytest.raises(ValidationError, match=r"admitted-unfilled|role concentration"):
        _model_from_payload(payload)


def test_capital_waterfall_places_anchor_loss_before_harmed_party() -> None:
    model = _actor_model()
    anchor = model.party("anchor-party")
    harmed_party = model.party("end-user-pool")
    assert anchor is not None
    assert harmed_party is not None

    anchor_capital = anchor.capital_positions[0]
    harmed_capital = harmed_party.capital_positions[0]
    assert anchor_capital.waterfall_id == harmed_capital.waterfall_id
    assert anchor_capital.seniority is ActorCapitalSeniority.FIRST_LOSS
    assert harmed_capital.seniority is ActorCapitalSeniority.SENIOR
    assert anchor_capital.loss_absorption_order is not None
    assert harmed_capital.loss_absorption_order is not None
    assert anchor_capital.loss_absorption_order < harmed_capital.loss_absorption_order
    assert anchor_capital.amount_exact == "100.0"
    assert anchor_capital.amount_unit == harmed_capital.amount_unit == "synthetic-unit"


@pytest.mark.parametrize("mutation", ["missing_order", "unpaired_amount"])
def test_capital_position_rejects_incomplete_loss_or_amount_evidence(mutation: str) -> None:
    payload = _model_payload()
    anchor_position = payload["parties"][0]["capital_positions"][0]
    if mutation == "missing_order":
        anchor_position["loss_absorption_order"] = None
    else:
        anchor_position["amount_unit"] = None

    with pytest.raises(ValidationError, match=r"loss-absorption order|amount and unit"):
        _model_from_payload(payload)


def test_freshness_boundaries_distinguish_current_from_stale() -> None:
    model = _actor_model()

    assert model.is_current(at=datetime(2026, 8, 1, tzinfo=UTC)) is True
    assert model.is_current(at=datetime(2026, 10, 1, tzinfo=UTC)) is True
    assert model.is_current(at=datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)) is True
    assert model.is_current(at=datetime(2027, 1, 1, tzinfo=UTC)) is False
    with pytest.raises(ValueError, match="aware timestamp"):
        model.is_current(at=datetime(2026, 10, 1))


def test_current_and_stale_input_evidence_retain_exact_source_identity() -> None:
    raw = MODEL_PATH.read_bytes()
    model = _actor_model()
    source = ActorModelSourceEvidence.build(raw=raw, actor_model=model)
    current_at = datetime(2026, 10, 1, tzinfo=UTC)
    stale_at = datetime(2027, 1, 2, tzinfo=UTC)

    current = ActorModelInputEvidence.build(
        evaluated_at=current_at,
        state=ActorModelInputState.CURRENT,
        configured=True,
        configured_path="operator-actor-model.json",
        source_evidence=source,
        limitations=(),
    )
    stale = ActorModelInputEvidence.build(
        evaluated_at=stale_at,
        state=ActorModelInputState.STALE,
        configured=True,
        configured_path="operator-actor-model.json",
        source_evidence=source,
        limitations=("Operator-authored actor model expired before this synthetic run.",),
    )

    assert current.source_evidence == stale.source_evidence == source
    assert current.state is ActorModelInputState.CURRENT
    assert current.limitations == ()
    assert stale.state is ActorModelInputState.STALE
    assert stale.limitations
    assert current.evidence_sha256 != stale.evidence_sha256


def test_source_evidence_rejects_a_semantic_model_not_parsed_from_its_raw_bytes() -> None:
    payload = _model_payload()
    payload["subject_name"] = "Different synthetic subject"
    semantic_payload = {key: value for key, value in payload.items() if key != "artifact_sha256"}
    payload["artifact_sha256"] = _canonical_sha256(semantic_payload)
    different_model = _model_from_payload(payload)

    with pytest.raises(ValueError, match="differs from the supplied typed model"):
        ActorModelSourceEvidence.build(raw=MODEL_PATH.read_bytes(), actor_model=different_model)


def test_input_evidence_state_must_match_the_bound_model_validity_interval() -> None:
    source = ActorModelSourceEvidence.build(
        raw=MODEL_PATH.read_bytes(),
        actor_model=_actor_model(),
    )

    with pytest.raises(ValidationError, match="state differs from its validity interval"):
        ActorModelInputEvidence.build(
            evaluated_at=datetime(2027, 1, 1, tzinfo=UTC),
            state=ActorModelInputState.CURRENT,
            configured=True,
            configured_path="operator-actor-model.json",
            source_evidence=source,
            limitations=(),
        )


@pytest.mark.parametrize(
    ("evaluated_at", "expected_state"),
    [
        (datetime(2026, 10, 1, tzinfo=UTC), ActorModelInputState.CURRENT),
        (datetime(2027, 1, 1, tzinfo=UTC), ActorModelInputState.STALE),
    ],
)
def test_bounded_loader_classifies_current_and_expiry_boundary_as_stale(
    tmp_path: Path,
    evaluated_at: datetime,
    expected_state: ActorModelInputState,
) -> None:
    fixture_copy = tmp_path / "operator-actor-model.json"
    fixture_copy.write_bytes(MODEL_PATH.read_bytes())

    evidence = load_actor_model(
        tmp_path,
        _actor_config(fixture_copy.name),
        evaluated_at=evaluated_at,
    )

    assert evidence.state is expected_state
    assert evidence.source_evidence is not None
    assert evidence.source_evidence.actor_model.artifact_sha256 == _actor_model().artifact_sha256
    assert bool(evidence.limitations) is (expected_state is ActorModelInputState.STALE)


def test_bounded_loader_distinguishes_unconfigured_and_future_input(tmp_path: Path) -> None:
    missing = load_actor_model(
        tmp_path,
        ActorModelConfig(),
        evaluated_at=datetime(2026, 7, 1, tzinfo=UTC),
    )
    fixture_copy = tmp_path / "operator-actor-model.json"
    fixture_copy.write_bytes(MODEL_PATH.read_bytes())
    future = load_actor_model(
        tmp_path,
        _actor_config(fixture_copy.name),
        evaluated_at=datetime(2026, 7, 31, 23, 59, 59, tzinfo=UTC),
    )

    assert missing.state is ActorModelInputState.MISSING
    assert missing.configured is False
    assert missing.source_evidence is None
    assert missing.limitations
    assert future.state is ActorModelInputState.FUTURE
    assert future.configured is True
    assert future.source_evidence is not None
    assert future.limitations


@pytest.mark.parametrize("pin", ["subject", "model", "source"])
def test_bounded_loader_rejects_operator_pin_mismatch(tmp_path: Path, pin: str) -> None:
    actor_path = tmp_path / "operator-actor-model.json"
    raw = MODEL_PATH.read_bytes()
    actor_path.write_bytes(raw)
    model = _actor_model()
    values: dict[str, object] = {
        "path": actor_path.name,
        "expected_subject_id": model.subject_id,
        "expected_model_sha256": model.artifact_sha256,
        "expected_source_sha256": hashlib.sha256(raw).hexdigest(),
    }
    values[
        {
            "subject": "expected_subject_id",
            "model": "expected_model_sha256",
            "source": "expected_source_sha256",
        }[pin]
    ] = "different-subject" if pin == "subject" else "0" * 64

    evidence = load_actor_model(
        tmp_path,
        ActorModelConfig.model_validate(values),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert evidence.state is ActorModelInputState.INVALID
    assert evidence.source_evidence is None


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"non_finite":NaN}',
        b'{"operator_note":"sk-or-v1-synthetic-actor-secret-canary-xxxxxxxxxxxxxxxx"}',
    ],
    ids=("duplicate-key", "nonfinite-number", "secret-canary"),
)
def test_bounded_loader_rejects_ambiguous_or_secret_bearing_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    actor_path = tmp_path / "operator-actor-model.json"
    actor_path.write_bytes(raw)

    evidence = load_actor_model(
        tmp_path,
        _actor_config(actor_path.name),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert evidence.state is ActorModelInputState.INVALID
    assert evidence.source_evidence is None
    assert evidence.rejected_source_sha256 == hashlib.sha256(raw).hexdigest()
    assert evidence.rejected_source_bytes == len(raw)
    assert evidence.limitations


def test_bounded_loader_rejects_excessively_recursive_json(tmp_path: Path) -> None:
    raw = b'{"nested":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}"
    actor_path = tmp_path / "operator-actor-model.json"
    actor_path.write_bytes(raw)

    evidence = load_actor_model(
        tmp_path,
        _actor_config(actor_path.name),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert evidence.state is ActorModelInputState.INVALID
    assert evidence.source_evidence is None
    assert evidence.rejected_source_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_bounded_loader_rejects_linked_actor_inputs(tmp_path: Path, link_kind: str) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(MODEL_PATH.read_bytes())
    linked = tmp_path / "operator-actor-model.json"
    if link_kind == "symbolic":
        linked.symlink_to(source.name)
    else:
        os.link(source, linked)

    evidence = load_actor_model(
        tmp_path,
        _actor_config(linked.name),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert evidence.state is ActorModelInputState.INVALID
    assert evidence.source_evidence is None


def test_bounded_loader_enforces_the_configured_byte_ceiling(tmp_path: Path) -> None:
    actor_path = tmp_path / "operator-actor-model.json"
    actor_path.write_bytes(MODEL_PATH.read_bytes())

    evidence = load_actor_model(
        tmp_path,
        _actor_config(actor_path.name, max_bytes=1_024),
        evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
    )

    assert evidence.state is ActorModelInputState.INVALID
    assert evidence.source_evidence is None
    assert evidence.rejected_source_sha256 is None


@pytest.mark.parametrize(
    (
        "actual_directory",
        "configured_directory",
        "actual_filename",
        "configured_filename",
    ),
    [
        (
            "ActorEvidence",
            "actorevidence",
            "Operator-Actor-Model.json",
            "Operator-Actor-Model.json",
        ),
        (
            "Acto\u0301rEvidence",
            "Act\u00f3rEvidence",
            "Operator-Actor-Model.json",
            "Operator-Actor-Model.json",
        ),
        (
            "ActorEvidence",
            "ActorEvidence",
            "Operator-Actor-Model.json",
            "operator-actor-model.json",
        ),
        (
            "ActorEvidence",
            "ActorEvidence",
            "Operato\u0301r-Actor-Model.json",
            "Operat\u00f3r-Actor-Model.json",
        ),
    ],
    ids=(
        "directory-case-alias",
        "directory-unicode-normalization-alias",
        "filename-case-alias",
        "filename-unicode-normalization-alias",
    ),
)
def test_bounded_loader_aborts_on_equivalent_path_alias(
    tmp_path: Path,
    actual_directory: str,
    configured_directory: str,
    actual_filename: str,
    configured_filename: str,
) -> None:
    actual_root = tmp_path / actual_directory
    actual_root.mkdir()
    actual_path = actual_root / actual_filename
    actual_path.write_bytes(MODEL_PATH.read_bytes())
    configured_relative = f"{configured_directory}/{configured_filename}"
    with pytest.raises(ActorModelPathIdentityError, match="case or Unicode-normalization alias"):
        load_actor_model(
            tmp_path,
            _actor_config(configured_relative),
            evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        )


def test_bounded_loader_aborts_when_multiple_equivalent_entries_exist(tmp_path: Path) -> None:
    exact_root = tmp_path / "ActorEvidence"
    equivalent_root = tmp_path / "actorevidence"
    exact_root.mkdir()
    try:
        equivalent_root.mkdir()
    except FileExistsError:
        pytest.skip("filesystem does not support distinct case-equivalent entries")
    actor_path = exact_root / "operator-actor-model.json"
    actor_path.write_bytes(MODEL_PATH.read_bytes())

    with pytest.raises(ActorModelPathIdentityError, match="case or Unicode-normalization alias"):
        load_actor_model(
            tmp_path,
            _actor_config("ActorEvidence/operator-actor-model.json"),
            evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        )


def test_bounded_loader_revalidates_exact_root_visible_path_after_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mmaudit.orchestration import actor_model as actor_model_module

    actor_path = tmp_path / "operator-actor-model.json"
    moved_path = tmp_path / "renamed-after-read.json"
    actor_path.write_bytes(MODEL_PATH.read_bytes())
    original_check = actor_model_module._require_exact_actor_directory_entry
    checks = 0

    def rename_before_fresh_revalidation(
        directory_descriptor: int,
        name: str,
        *,
        missing_is_identity_error: bool = False,
    ) -> None:
        nonlocal checks
        checks += 1
        if checks == 4:
            actor_path.rename(moved_path)
        original_check(
            directory_descriptor,
            name,
            missing_is_identity_error=missing_is_identity_error,
        )

    monkeypatch.setattr(
        actor_model_module,
        "_require_exact_actor_directory_entry",
        rename_before_fresh_revalidation,
    )

    with pytest.raises(ActorModelPathIdentityError, match="root-visible"):
        load_actor_model(
            tmp_path,
            _actor_config(actor_path.name),
            evaluated_at=datetime(2026, 10, 1, tzinfo=UTC),
        )

    assert moved_path.is_file()


def test_graph_reconciliation_surfaces_unfilled_and_unmodeled_code_roles() -> None:
    graphs = _privilege_graph(
        "ANCHOR_CURATOR_ROLE",
        "CURATOR_ROLE",
        "RISK_COUNCIL_ROLE",
        "SERVICER_ROLE",
        "UNMODELED_ROLE",
    )

    findings = reconcile_actor_model_with_graphs(_current_actor_input(), graphs)
    kinds = {finding.kind for finding in findings}

    assert ActorGovernanceConflictKind.CODE_PERMITS_ADMITTED_UNFILLED_ROLE in kinds
    assert ActorGovernanceConflictKind.CODE_ROLE_ABSENT_FROM_ACTOR_MODEL in kinds
    assert ActorGovernanceConflictKind.ACTOR_ROLE_BINDING_ABSENT_FROM_CODE not in kinds
    assert tuple(item.conflict_id for item in findings) == tuple(
        sorted(item.conflict_id for item in findings)
    )
    code_bound = tuple(item for item in findings if item.code_evidence)
    assert code_bound
    assert all(
        item.code_evidence[0].path == "tests/fixtures/actor_model/SyntheticOrchard.sol"
        for item in code_bound
    )
    assert all(item.code_evidence[0].evidence_sha256 for item in code_bound)


def test_graph_reconciliation_records_incomplete_evidence_without_inference() -> None:
    findings = reconcile_actor_model_with_graphs(_current_actor_input(), None)

    assert len(findings) == 1
    assert findings[0].kind is ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE
    assert findings[0].source_finding_ids == ()


@pytest.mark.parametrize(
    "provenance",
    [SolidityProvenance.HEURISTIC, SolidityProvenance.MODEL_SUGGESTED],
)
def test_graph_reconciliation_does_not_promote_untrusted_role_leads(
    provenance: SolidityProvenance,
) -> None:
    graphs = _privilege_graph(
        "CURATOR_ROLE",
        "UNMODELED_ROLE",
        provenance=provenance,
        confidence=0.5,
    )

    findings = reconcile_actor_model_with_graphs(_current_actor_input(), graphs)

    assert any(
        finding.kind is ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE
        for finding in findings
    )
    assert not any(
        finding.kind
        in {
            ActorGovernanceConflictKind.CODE_PERMITS_ADMITTED_UNFILLED_ROLE,
            ActorGovernanceConflictKind.CODE_ROLE_ABSENT_FROM_ACTOR_MODEL,
        }
        for finding in findings
    )
    assert not any(finding.code_evidence for finding in findings)


def test_three_synthetic_correction_scenarios_are_complete_and_typed() -> None:
    actor_model = _actor_model()
    payload = _scenario_payload()
    scenarios = payload["scenarios"]
    assert payload["schema_version"] == "1.0"
    assert payload["fixture_kind"] == "synthetic_actor_correction_scenarios"
    assert [item["scenario_id"] for item in scenarios] == [
        "anchor-first-loss-scope",
        "ordinary-servicer-forbearance",
        "request-cooldown-severity",
    ]

    for scenario in scenarios:
        context = CandidateActorContext.model_validate_json(
            json.dumps(scenario["actor_context"]),
            strict=True,
        )
        role = actor_model.role(context.role_id)
        assert role is not None
        assert context.harmed_party_id is None or actor_model.party(context.harmed_party_id)
        role_constraint_ids = {item.constraint_id for item in role.operational_constraints}
        assert set(context.relevant_constraint_ids) <= role_constraint_ids
        assert scenario["expected_without_actor_model"] == {
            "calibrated_severity": scenario["original_severity"],
            "likelihood_adjustment": "unassessed",
            "requires_limitation": True,
        }

    anchor_scope = scenarios[0]
    alternative = CandidateActorContext.model_validate_json(
        json.dumps(anchor_scope["admitted_alternative_actor_context"]),
        strict=True,
    )
    alternative_role = actor_model.role(alternative.role_id)
    assert alternative_role is not None
    assert alternative_role.occupancy is ActorRoleOccupancy.ADMITTED_UNFILLED
    assert anchor_scope["expected_with_actor_model"]["current_holder_is_first_loss"] is True

    forbearance = CandidateActorContext.model_validate_json(
        json.dumps(scenarios[1]["actor_context"]),
        strict=True,
    )
    assert forbearance.misconduct_required is False
    assert forbearance.ordinary_legitimate_behavior is True
    assert scenarios[1]["expected_with_actor_model"]["likelihood_adjustment"] == "increased"

    cooldown_role = actor_model.role("anchor_curator")
    assert cooldown_role is not None
    cooldown = cooldown_role.operational_constraints[0]
    assert cooldown.constraint_id == "request-anchored-cooldown"
    assert cooldown.duration_seconds == 21 * 24 * 60 * 60
    assert scenarios[2]["expected_with_actor_model"]["calibrated_severity"] == "medium"


def test_ordinary_legitimate_framing_requires_operator_bound_rationale() -> None:
    payload = dict(_scenario_payload()["scenarios"][1]["actor_context"])
    payload.update(
        {
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )

    with pytest.raises(
        ValidationError,
        match="ordinary legitimate behavior requires operator-bound plausibility evidence",
    ):
        CandidateActorContext.model_validate(payload)


def test_economic_exposure_and_role_concentration_change_actor_likelihood() -> None:
    base_payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    base_payload.update(
        {
            "harmed_party_id": None,
            "harmed_party_disposition": "not_applicable",
            "action_against_stated_interest": False,
            "stated_interest": None,
            "relevant_constraint_ids": [],
            "required_concentrated_role_ids": [],
            "relevant_economic_exposures": [],
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )
    neutral_context = CandidateActorContext.model_validate(base_payload)
    neutral = calibrate_finding(
        _finding(
            finding_id="synthetic-neutral-economics",
            severity=Severity.HIGH,
            actor_context=neutral_context,
        ),
        actor_context=neutral_context,
        actor_input=_current_actor_input(),
    ).finding
    assert neutral.actor_assessment is not None
    assert neutral.severity is Severity.HIGH
    assert neutral.actor_assessment.likelihood_adjustment is ActorLikelihoodAdjustment.UNCHANGED

    exposure_payload = {
        **base_payload,
        "relevant_economic_exposures": ["protocol_failure_loss"],
    }
    exposure_context = CandidateActorContext.model_validate(exposure_payload)
    exposure = calibrate_finding(
        _finding(
            finding_id="synthetic-exposure-alignment",
            severity=Severity.HIGH,
            actor_context=exposure_context,
        ),
        actor_context=exposure_context,
        actor_input=_current_actor_input(),
    ).finding
    assert exposure.actor_assessment is not None
    assert exposure.severity is Severity.MEDIUM
    assert (
        exposure.actor_assessment.disposition
        is ActorAssessmentDisposition.ALIGNED_ACTION_UNJUSTIFIED
    )

    concentration_payload = {
        **base_payload,
        "required_concentrated_role_ids": ["risk_council"],
    }
    concentration_context = CandidateActorContext.model_validate(concentration_payload)
    concentration = calibrate_finding(
        _finding(
            finding_id="synthetic-concentrated-authority",
            severity=Severity.HIGH,
            actor_context=concentration_context,
        ),
        actor_context=concentration_context,
        actor_input=_current_actor_input(),
    ).finding
    assert concentration.actor_assessment is not None
    assert concentration.severity is Severity.HIGH
    assert (
        concentration.actor_assessment.likelihood_adjustment is ActorLikelihoodAdjustment.INCREASED
    )


def test_multiparty_constraint_mitigates_only_with_an_independent_holder() -> None:
    same_holder_payload = _model_payload()
    anchor_role = next(
        role for role in same_holder_payload["roles"] if role["role_id"] == "anchor_curator"
    )
    anchor_role["operational_constraints"].append(
        {
            "constraint_id": "same-holder-approval",
            "effect": "requires_multiparty_approval",
            "description": "Synthetic approval by the co-held risk council.",
            "duration_seconds": None,
            "applies_to_permissions": ["review synthetic allocation"],
            "required_approver_role_ids": ["risk_council"],
        }
    )
    same_holder_input = _actor_input_from_payload(same_holder_payload)
    context_payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    context_payload.update(
        {
            "harmed_party_id": None,
            "harmed_party_disposition": "not_applicable",
            "action_against_stated_interest": False,
            "stated_interest": None,
            "relevant_constraint_ids": ["same-holder-approval"],
            "required_concentrated_role_ids": [],
            "relevant_economic_exposures": [],
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )
    context = CandidateActorContext.model_validate(context_payload)
    same_holder = calibrate_finding(
        _finding(
            finding_id="synthetic-same-holder-approval",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=same_holder_input,
    ).finding
    assert same_holder.severity is Severity.HIGH

    independent_payload = json.loads(json.dumps(same_holder_payload))
    roles = {role["role_id"]: role for role in independent_payload["roles"]}
    roles["anchor_curator"]["concentrated_with_role_ids"] = []
    roles["risk_council"]["holder_party_id"] = "originator-party"
    roles["risk_council"]["concentrated_with_role_ids"] = ["servicer"]
    roles["servicer"]["concentrated_with_role_ids"] = ["risk_council"]
    independent = calibrate_finding(
        _finding(
            finding_id="synthetic-independent-approval",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=_actor_input_from_payload(independent_payload),
    ).finding
    assert independent.severity is Severity.MEDIUM


def test_temporal_constraint_requires_duration_and_material_threshold() -> None:
    missing_duration_payload = _model_payload()
    constraint = missing_duration_payload["roles"][0]["operational_constraints"][0]
    constraint["duration_seconds"] = None
    with pytest.raises(ValidationError, match="temporal actor constraints require"):
        _actor_input_from_payload(missing_duration_payload)

    trivial_payload = _model_payload()
    trivial_payload["roles"][0]["operational_constraints"][0]["duration_seconds"] = 1
    context_payload = dict(_scenario_payload()["scenarios"][2]["actor_context"])
    context_payload.update(
        {
            "harmed_party_disposition": "not_applicable",
            "harmed_party_id": None,
        }
    )
    context = CandidateActorContext.model_validate(context_payload)
    calibrated = calibrate_finding(
        _finding(
            finding_id="synthetic-trivial-delay",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=_actor_input_from_payload(trivial_payload),
    ).finding

    assert calibrated.severity is Severity.HIGH
    assert calibrated.actor_assessment is not None
    assert calibrated.actor_assessment.limitation is not None
    assert "materiality threshold" in calibrated.actor_assessment.limitation


def test_capital_alignment_requires_every_shared_waterfall_tranche_to_be_comparable() -> None:
    payload = _model_payload()
    parties = {party["party_id"]: party for party in payload["parties"]}
    parties["end-user-pool"]["capital_positions"][0]["seniority"] = "junior"
    parties["end-user-pool"]["capital_positions"][0]["loss_absorption_order"] = 1
    parties["originator-party"]["capital_positions"][0]["waterfall_id"] = (
        "synthetic-originator-waterfall"
    )
    parties["anchor-party"]["capital_positions"].append(
        {
            "position_id": "synthetic-other-unit-senior",
            "waterfall_id": "synthetic-loss-waterfall",
            "description": "Synthetic material tranche in an incomparable unit.",
            "asset_or_exposure": "synthetic other-unit reserve",
            "amount_description": "9999 synthetic other units",
            "amount_exact": "9999",
            "amount_unit": "other-unit",
            "materiality": "material",
            "seniority": "senior",
            "loss_absorption_order": 2,
        }
    )
    context_payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    context_payload.update(
        {
            "action_against_stated_interest": False,
            "stated_interest": None,
            "relevant_economic_exposures": [],
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )
    context = CandidateActorContext.model_validate(context_payload)
    calibrated = calibrate_finding(
        _finding(
            finding_id="synthetic-mixed-unit-capital",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=_actor_input_from_payload(payload),
    ).finding

    assert calibrated.severity is Severity.HIGH
    assert calibrated.actor_assessment is not None
    assert calibrated.actor_assessment.capital_consumed_before_harmed_party is None
    assert calibrated.actor_assessment.limitation is not None


def test_unresolved_harmed_party_is_not_a_resolved_current_actor_assessment() -> None:
    context_payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    context_payload.update(
        {
            "harmed_party_disposition": "unresolved",
            "harmed_party_id": None,
            "action_against_stated_interest": False,
            "stated_interest": None,
            "relevant_economic_exposures": [],
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )
    context = CandidateActorContext.model_validate(context_payload)
    result = calibrate_finding(
        _finding(
            finding_id="synthetic-unresolved-harmed-party",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=_current_actor_input(),
    )

    assert result.finding.severity is Severity.HIGH
    assert result.finding.actor_assessment is not None
    assert (
        result.finding.actor_assessment.disposition is ActorAssessmentDisposition.CONTEXT_UNVERIFIED
    )
    assert (
        result.governance_findings[0].kind
        is ActorGovernanceConflictKind.FINDING_HARMED_PARTY_UNRESOLVED
    )


def test_actor_context_requires_explicit_code_only_severity_and_harmed_party_basis() -> None:
    payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    payload.pop("severity_basis")
    with pytest.raises(ValidationError, match="Field required"):
        CandidateActorContext.model_validate(payload)

    payload = dict(_scenario_payload()["scenarios"][0]["actor_context"])
    payload["severity_basis"] = "actor_adjusted"
    with pytest.raises(ValidationError, match="code_mechanism_only"):
        CandidateActorContext.model_validate(payload)


@pytest.mark.parametrize(
    "scenario_id",
    [
        "anchor-first-loss-scope",
        "ordinary-servicer-forbearance",
        "request-cooldown-severity",
    ],
)
def test_actor_calibration_reproduces_each_correction_and_missing_model_baseline(
    scenario_id: str,
) -> None:
    scenarios = {item["scenario_id"]: item for item in _scenario_payload()["scenarios"]}
    scenario = scenarios[scenario_id]
    actor_context = CandidateActorContext.model_validate_json(
        json.dumps(scenario["actor_context"]),
        strict=True,
    )
    original_severity = Severity(scenario["original_severity"])
    finding = _finding(
        finding_id=scenario["finding_id"],
        severity=original_severity,
        actor_context=actor_context,
    )

    calibrated = calibrate_finding(
        finding,
        actor_context=actor_context,
        actor_input=_current_actor_input(),
    )
    expected = scenario["expected_with_actor_model"]
    assessment = calibrated.finding.actor_assessment
    assert assessment is not None
    assert calibrated.finding.severity.value == expected["calibrated_severity"]
    assert assessment.original_severity.value == scenario["original_severity"]
    assert assessment.calibrated_severity.value == expected["calibrated_severity"]
    assert assessment.likelihood_adjustment.value == expected["likelihood_adjustment"]
    assert assessment.input_state is ActorModelInputState.CURRENT
    assert assessment.actor_model_sha256 == _actor_model().artifact_sha256
    assert assessment.limitation is None

    if scenario_id == "anchor-first-loss-scope":
        assert assessment.capital_consumed_before_harmed_party is True
        assert assessment.holder_fee_revenue_exposure is not None
        assert assessment.holder_protocol_failure_loss is not None
        assert assessment.concentrated_with_role_ids == ("risk_council",)
        alternative_context = CandidateActorContext.model_validate_json(
            json.dumps(scenario["admitted_alternative_actor_context"]),
            strict=True,
        )
        alternative = calibrate_finding(
            _finding(
                finding_id=f"{scenario['finding_id']}-future-role",
                severity=original_severity,
                actor_context=alternative_context,
            ),
            actor_context=alternative_context,
            actor_input=_current_actor_input(),
        )
        alternative_assessment = alternative.finding.actor_assessment
        assert alternative_assessment is not None
        assert alternative_assessment.role_occupancy is ActorRoleOccupancy.ADMITTED_UNFILLED
        assert alternative_assessment.limitation is not None
        assert alternative.governance_findings
        assert (
            alternative.governance_findings[0].kind
            is ActorGovernanceConflictKind.FINDING_DEPENDS_ON_ADMITTED_UNFILLED_ROLE
        )
    elif scenario_id == "ordinary-servicer-forbearance":
        assert assessment.misconduct_required is False
        assert assessment.ordinary_legitimate_behavior is True
        assert assessment.likelihood_adjustment is ActorLikelihoodAdjustment.INCREASED
        assert assessment.remediation_focus is ActorRemediationFocus.LEGITIMATE_STATE_TRANSITION
    else:
        assert assessment.applied_constraint_ids == ("request-anchored-cooldown",)
        assert assessment.likelihood_adjustment is ActorLikelihoodAdjustment.DECREASED

    uncalibrated = calibrate_finding(
        finding,
        actor_context=actor_context,
        actor_input=_missing_actor_input(),
    )
    missing_assessment = uncalibrated.finding.actor_assessment
    missing_expected = scenario["expected_without_actor_model"]
    assert missing_assessment is not None
    assert uncalibrated.finding.severity is original_severity
    assert missing_assessment.calibrated_severity.value == missing_expected["calibrated_severity"]
    assert (
        missing_assessment.likelihood_adjustment.value == missing_expected["likelihood_adjustment"]
    )
    assert bool(missing_assessment.limitation) is missing_expected["requires_limitation"]
    assert missing_assessment.input_state is ActorModelInputState.MISSING


def test_required_actor_assessment_gate_distinguishes_nonprivileged_from_unstated() -> None:
    scenario = _scenario_payload()["scenarios"][1]
    actor_context = CandidateActorContext.model_validate(scenario["actor_context"])
    privileged = calibrate_finding(
        _finding(
            finding_id="synthetic-resolved-actor",
            severity=Severity.MEDIUM,
            actor_context=actor_context,
        ),
        actor_context=actor_context,
        actor_input=_current_actor_input(),
    ).finding

    untyped_payload = privileged.model_dump(mode="python")
    untyped_payload.update(
        {
            "id": "synthetic-unstated-actor",
            "group_id": "group-synthetic-unstated-actor",
            "actor_model_applicability": ActorModelApplicability.UNSTATED,
            "actor_context": None,
            "actor_assessment": None,
        }
    )
    untyped = Finding.model_validate(untyped_payload)
    untyped = calibrate_finding(
        untyped,
        actor_context=None,
        actor_input=_current_actor_input(),
    ).finding
    unresolved_gate = actor_model_assessment_quality_gate(
        _current_actor_input(),
        (privileged, untyped),
        required=True,
    )
    assert unresolved_gate.required is True
    assert unresolved_gate.passed is False
    assert "synthetic-unstated-actor" in unresolved_gate.detail

    nonprivileged_payload = untyped.model_dump(mode="python")
    nonprivileged_payload.update(
        {
            "id": "synthetic-nonprivileged",
            "group_id": "group-synthetic-nonprivileged",
            "actor_model_applicability": (ActorModelApplicability.NO_PRIVILEGED_ACTOR_REQUIRED),
            "actor_assessment": None,
        }
    )
    nonprivileged = Finding.model_validate(nonprivileged_payload)
    nonprivileged = calibrate_finding(
        nonprivileged,
        actor_context=None,
        actor_input=_current_actor_input(),
    ).finding
    assert nonprivileged.actor_assessment is not None
    assert (
        nonprivileged.actor_assessment.disposition
        is ActorAssessmentDisposition.NOT_APPLICABLE_NONPRIVILEGED
    )
    resolved_gate = actor_model_assessment_quality_gate(
        _current_actor_input(),
        (privileged, nonprivileged),
        required=True,
    )
    assert resolved_gate.passed is True


def test_plausibility_rationale_requires_exact_operator_evidence_custody() -> None:
    scenario = _scenario_payload()["scenarios"][1]
    context_payload = dict(scenario["actor_context"])
    context_payload["plausibility_evidence_reference_ids"] = ["unknown-reference"]
    context = CandidateActorContext.model_validate(context_payload)

    result = calibrate_finding(
        _finding(
            finding_id="synthetic-unknown-rationale-evidence",
            severity=Severity.MEDIUM,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=_current_actor_input(),
    )

    assert result.finding.actor_assessment is not None
    assert (
        result.finding.actor_assessment.disposition is ActorAssessmentDisposition.CONTEXT_UNVERIFIED
    )
    assert (
        result.governance_findings[0].kind
        is ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_PLAUSIBILITY_EVIDENCE
    )


def test_privileged_applicability_rejects_nonprivileged_inner_context() -> None:
    scenario = _scenario_payload()["scenarios"][1]
    context_payload = dict(scenario["actor_context"])
    context_payload.update(
        {
            "privileged_action_required": False,
            "permission": None,
            "ordinary_legitimate_behavior": False,
            "relevant_constraint_ids": [],
            "relevant_economic_exposures": [],
            "plausibility_rationale": None,
            "plausibility_evidence_reference_ids": [],
        }
    )
    context = CandidateActorContext.model_validate(context_payload)

    with pytest.raises(ValidationError, match="must describe privileged conduct"):
        _finding(
            finding_id="synthetic-applicability-bypass",
            severity=Severity.MEDIUM,
            actor_context=context,
        )


def test_scheduler_actor_projection_ignores_only_fresh_observation_custody() -> None:
    first = _current_actor_input()
    second = ActorModelInputEvidence.build(
        evaluated_at=datetime(2026, 10, 2, tzinfo=UTC),
        state=ActorModelInputState.CURRENT,
        configured=True,
        configured_path=first.configured_path,
        source_evidence=first.source_evidence,
        limitations=(),
    )
    stale = ActorModelInputEvidence.build(
        evaluated_at=datetime(2027, 2, 1, tzinfo=UTC),
        state=ActorModelInputState.STALE,
        configured=True,
        configured_path=first.configured_path,
        source_evidence=first.source_evidence,
        limitations=("Synthetic actor-model input is stale.",),
    )

    assert first.evidence_sha256 != second.evidence_sha256
    first_projection = scheduler_analysis_semantic_projection(
        first,
        audited_repository_root=FIXTURE_ROOT,
    )
    second_projection = scheduler_analysis_semantic_projection(
        second,
        audited_repository_root=FIXTURE_ROOT,
    )
    stale_projection = scheduler_analysis_semantic_projection(
        stale,
        audited_repository_root=FIXTURE_ROOT,
    )
    assert first_projection == second_projection
    assert stale_projection != first_projection


def test_stale_assessment_cannot_claim_current_role_without_a_limitation() -> None:
    scenario = _scenario_payload()["scenarios"][0]
    context = CandidateActorContext.model_validate(scenario["actor_context"])
    current = _current_actor_input()
    stale = ActorModelInputEvidence.build(
        evaluated_at=datetime(2027, 2, 1, tzinfo=UTC),
        state=ActorModelInputState.STALE,
        configured=True,
        configured_path=current.configured_path,
        source_evidence=current.source_evidence,
        limitations=("Synthetic actor-model input is stale.",),
    )
    finding = calibrate_finding(
        _finding(
            finding_id="synthetic-stale-assessment",
            severity=Severity.HIGH,
            actor_context=context,
        ),
        actor_context=context,
        actor_input=stale,
    ).finding
    assessment = finding.actor_assessment
    assert assessment is not None
    values = assessment.model_dump(mode="python", exclude={"assessment_sha256"})
    values.update(
        {
            "disposition": ActorAssessmentDisposition.CURRENT_ROLE,
            "likelihood_adjustment": ActorLikelihoodAdjustment.UNCHANGED,
            "limitation": None,
            "remediation_focus": ActorRemediationFocus.REACHABLE_STATE_TRANSITION,
        }
    )

    with pytest.raises(
        ValidationError,
        match="non-current actor assessment disposition differs from input state",
    ):
        FindingActorAssessment.build(**values)
