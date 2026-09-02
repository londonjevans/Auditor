"""Bounded actor-model loading, graph reconciliation, and severity calibration."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from mmaudit.config import ActorModelConfig
from mmaudit.constants import SEVERITY_ORDER
from mmaudit.models.actor_model import (
    ACTOR_CONSTRAINT_MIN_MATERIAL_DURATION_SECONDS,
    ActorAssessmentDisposition,
    ActorCapitalMateriality,
    ActorCodeRoleEvidence,
    ActorConstraintEffect,
    ActorEconomicExposureKind,
    ActorExposureState,
    ActorFindingAssessmentBinding,
    ActorGovernanceConflictKind,
    ActorGovernanceFinding,
    ActorHarmedPartyDisposition,
    ActorLikelihoodAdjustment,
    ActorModel,
    ActorModelApplicability,
    ActorModelEvaluation,
    ActorModelInputEvidence,
    ActorModelInputState,
    ActorModelSourceEvidence,
    ActorOperationalConstraint,
    ActorRemediationFocus,
    ActorRoleOccupancy,
    ActorSeverity,
    CandidateActorContext,
    FindingActorAssessment,
)
from mmaudit.models.schemas import (
    ActorFindingBaseline,
    ActorModelBaselineArtifact,
    AnalysisState,
    Finding,
    FindingOriginKind,
    JudgeDecision,
    QualityGateResult,
    Severity,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphSet,
    SolidityProvenance,
)
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.redaction import SecretSafetyError, redact_text
from mmaudit.repository.secrets import is_sensitive_workspace_path

_MISSING_LIMITATION = (
    "operator actor model was not configured; severity remains a code-only assessment"
)
_INVALID_LIMITATION = (
    "configured operator actor model failed bounded local validation; severity remains code-only"
)
_FUTURE_LIMITATION = (
    "operator actor model is not yet effective at run start; severity remains code-only"
)
_STALE_LIMITATION = "operator actor model was stale at run start; severity remains code-only"
_ACTOR_MODEL_MAX_DIRECTORY_ENTRIES = 100_000


class ActorModelPathIdentityError(ValueError):
    """Raised when actor evidence cannot be bound to one exact directory-entry spelling."""


@dataclass(frozen=True)
class ActorCalibrationResult:
    """One host-derived finding update and any related governance evidence."""

    finding: Finding
    governance_findings: tuple[ActorGovernanceFinding, ...] = ()


def load_actor_model(
    repository_root: Path,
    config: ActorModelConfig,
    *,
    evaluated_at: datetime,
) -> ActorModelInputEvidence:
    """Load a repository-relative actor model without inferring facts from source."""

    if evaluated_at.tzinfo is None:
        raise ValueError("actor-model evaluation requires an aware timestamp")
    if config.path is None:
        return ActorModelInputEvidence.build(
            evaluated_at=evaluated_at,
            state=ActorModelInputState.MISSING,
            configured=False,
            configured_path=None,
            source_evidence=None,
            rejected_source_sha256=None,
            rejected_source_bytes=None,
            limitations=(_MISSING_LIMITATION,),
        )

    raw: bytes | None = None
    try:
        raw = _read_bounded_repository_file(
            repository_root,
            config.path,
            max_bytes=config.max_bytes,
        )
        text = raw.decode("utf-8")
        redact_text(text, fail_on_detected_secret=True, redact=False)
        payload = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(payload, dict):
            raise ValueError("actor-model input must be a JSON object")
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        actor_model = ActorModel.model_validate_json(canonical, strict=True)
        if actor_model.subject_id != config.expected_subject_id:
            raise ValueError("actor-model subject differs from its operator pin")
        if actor_model.artifact_sha256 != config.expected_model_sha256:
            raise ValueError("actor-model semantic hash differs from its operator pin")
        source_sha256 = hashlib.sha256(raw).hexdigest()
        if (
            config.expected_source_sha256 is not None
            and source_sha256 != config.expected_source_sha256
        ):
            raise ValueError("actor-model source hash differs from its operator pin")
        source = ActorModelSourceEvidence.build(raw=raw, actor_model=actor_model)
    except ActorModelPathIdentityError:
        # An alias that the host filesystem resolves but repository discovery spells
        # differently could expose operator-only facts to actor-blind model passes.
        # Abort before discovery instead of degrading this isolation failure to INVALID.
        raise
    except (
        FileNotFoundError,
        IsADirectoryError,
        JSONDecodeError,
        OSError,
        RecursionError,
        SecretSafetyError,
        UnicodeDecodeError,
        ValidationError,
        ValueError,
    ):
        return ActorModelInputEvidence.build(
            evaluated_at=evaluated_at,
            state=ActorModelInputState.INVALID,
            configured=True,
            configured_path=config.path,
            source_evidence=None,
            rejected_source_sha256=(hashlib.sha256(raw).hexdigest() if raw else None),
            rejected_source_bytes=(len(raw) if raw else None),
            limitations=(_INVALID_LIMITATION,),
        )

    limitations: tuple[str, ...]
    if evaluated_at < actor_model.valid_from:
        state = ActorModelInputState.FUTURE
        limitations = (_FUTURE_LIMITATION,)
    elif evaluated_at >= actor_model.valid_until:
        state = ActorModelInputState.STALE
        limitations = (_STALE_LIMITATION,)
    else:
        state = ActorModelInputState.CURRENT
        limitations = ()
    return ActorModelInputEvidence.build(
        evaluated_at=evaluated_at,
        state=state,
        configured=True,
        configured_path=config.path,
        source_evidence=source,
        rejected_source_sha256=None,
        rejected_source_bytes=None,
        limitations=limitations,
    )


def withhold_actor_model_from_discovery(
    discovery: DiscoveryResult,
    configured_path: str | None,
) -> tuple[DiscoveryResult, bool]:
    """Remove operator-only actor evidence before repository maps or prompts exist."""

    if configured_path is None:
        return discovery, False
    normalized = normalize_relative_path(configured_path)
    files = tuple(item for item in discovery.files if item.relative_path != normalized)
    return (
        DiscoveryResult(
            root=discovery.root,
            files=files,
            omitted=tuple(
                item for item in discovery.omitted if not item.startswith(f"{normalized}:")
            ),
            changed_paths=frozenset(path for path in discovery.changed_paths if path != normalized),
            git_commit=discovery.git_commit,
        ),
        all(item.relative_path != normalized for item in files),
    )


def actor_model_quality_gate(
    actor_input: ActorModelInputEvidence,
    *,
    required: bool,
) -> QualityGateResult:
    """Require current operator evidence for a complete severity assessment."""

    passed = actor_input.state is ActorModelInputState.CURRENT
    return QualityGateResult(
        gate="actor_model_current",
        required=required,
        passed=passed or not required,
        detail=f"operator actor-model input state={actor_input.state.value}",
        state=AnalysisState.DETERMINISTIC if passed else AnalysisState.ATTEMPTED_FAILED,
        artifacts=["actor-model-evaluation.json"],
    )


def actor_model_assessment_quality_gate(
    actor_input: ActorModelInputEvidence,
    findings: Iterable[Finding],
    *,
    required: bool,
) -> QualityGateResult:
    """Fail closed when current actor evidence was not consumed by every applicable finding."""

    unresolved_dispositions = {
        ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
        ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
        ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
        ActorAssessmentDisposition.ACTOR_MODEL_STALE,
        ActorAssessmentDisposition.FINDING_ACTOR_UNSTATED,
        ActorAssessmentDisposition.ROLE_UNMODELED,
        ActorAssessmentDisposition.CONTEXT_UNVERIFIED,
    }
    retained = tuple(findings)
    unresolved = tuple(
        finding.id
        for finding in retained
        if finding.actor_assessment is None
        or finding.actor_assessment.disposition in unresolved_dispositions
    )
    complete = actor_input.state is ActorModelInputState.CURRENT and not unresolved
    detail = (
        "every finding has a resolved current actor assessment"
        if complete
        else (
            "unresolved actor assessments=" + ",".join(unresolved)
            if unresolved
            else f"operator actor-model input state={actor_input.state.value}"
        )
    )
    return QualityGateResult(
        gate="actor_model_assessments_complete",
        required=required,
        passed=complete or not required,
        detail=detail,
        state=AnalysisState.DETERMINISTIC if complete else AnalysisState.ATTEMPTED_FAILED,
        artifacts=["actor-model-evaluation.json", "findings.json"],
    )


def reconcile_actor_model_with_graphs(
    actor_input: ActorModelInputEvidence,
    graphs: SolidityGraphSet | None,
) -> tuple[ActorGovernanceFinding, ...]:
    """Surface exact actor/code role disagreements without inferring role holders."""

    source = actor_input.source_evidence
    if actor_input.state is not ActorModelInputState.CURRENT or source is None:
        return ()
    actor_model = source.actor_model
    findings: list[ActorGovernanceFinding] = []
    if (
        graphs is None
        or not graphs.generation_complete
        or SolidityGraphKind.PRIVILEGE not in graphs.analyzed_graphs
    ):
        findings.append(
            ActorGovernanceFinding.build(
                kind=ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE,
                role_id="graph-evidence",
                source_finding_ids=(),
                detail="privilege graph evidence is incomplete; actor/code agreement is unresolved",
                actor_model_sha256=actor_model.artifact_sha256,
            )
        )
        return tuple(findings)

    all_code_roles = tuple(
        sorted(
            (node for node in graphs.nodes if node.kind is SolidityGraphNodeKind.ROLE),
            key=lambda node: (node.label, node.id),
        )
    )
    trusted_provenance = {
        SolidityProvenance.COMPILER,
        SolidityProvenance.STATIC_TOOL,
        SolidityProvenance.FALLBACK,
    }
    code_roles = tuple(
        node
        for node in all_code_roles
        if node.provenance in trusted_provenance and node.confidence == 1.0
    )
    untrusted_code_roles = tuple(node for node in all_code_roles if node not in code_roles)
    if untrusted_code_roles:
        findings.append(
            ActorGovernanceFinding.build(
                kind=ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE,
                role_id="graph-evidence",
                source_finding_ids=(),
                detail=(
                    "privilege graph contains non-authoritative role leads; actor/code agreement "
                    "uses only exact compiler, static-tool, or fallback evidence"
                ),
                actor_model_sha256=actor_model.artifact_sha256,
            )
        )
    declared_identifiers = {
        identifier for role in actor_model.roles for identifier in role.code_identifiers
    }
    for role in actor_model.roles:
        matches = tuple(
            node
            for node in code_roles
            if node.id in role.code_identifiers or node.label in role.code_identifiers
        )
        if not matches:
            unresolved_matches = tuple(
                node
                for node in untrusted_code_roles
                if node.id in role.code_identifiers or node.label in role.code_identifiers
            )
            if unresolved_matches:
                continue
            findings.append(
                ActorGovernanceFinding.build(
                    kind=ActorGovernanceConflictKind.ACTOR_ROLE_BINDING_ABSENT_FROM_CODE,
                    role_id=role.role_id,
                    source_finding_ids=(),
                    detail="operator actor role has no exact retained code-role binding",
                    actor_model_sha256=actor_model.artifact_sha256,
                )
            )
        elif role.occupancy is ActorRoleOccupancy.ADMITTED_UNFILLED:
            findings.append(
                ActorGovernanceFinding.build(
                    kind=(ActorGovernanceConflictKind.CODE_PERMITS_ADMITTED_UNFILLED_ROLE),
                    role_id=role.role_id,
                    source_finding_ids=(),
                    detail="code permits an operator-declared admitted but currently unfilled role",
                    actor_model_sha256=actor_model.artifact_sha256,
                    code_evidence=tuple(_actor_code_role_evidence(node) for node in matches),
                )
            )
    for node in code_roles:
        if node.id in declared_identifiers or node.label in declared_identifiers:
            continue
        synthetic_role_id = f"code-role:{hashlib.sha256(node.id.encode()).hexdigest()[:32]}"
        findings.append(
            ActorGovernanceFinding.build(
                kind=ActorGovernanceConflictKind.CODE_ROLE_ABSENT_FROM_ACTOR_MODEL,
                role_id=synthetic_role_id,
                source_finding_ids=(),
                detail="retained code role is absent from the operator actor-model inventory",
                actor_model_sha256=actor_model.artifact_sha256,
                code_evidence=(_actor_code_role_evidence(node),),
            )
        )
    return _canonical_governance_findings(findings)


def calibrate_finding(
    finding: Finding,
    *,
    actor_context: CandidateActorContext | None,
    actor_input: ActorModelInputEvidence,
) -> ActorCalibrationResult:
    """Apply deterministic actor evidence after conservative consensus severity selection."""

    if actor_context != finding.actor_context:
        raise ValueError("actor calibration context differs from its retained finding")
    baseline = ActorFindingBaseline.build(finding)
    original = finding.severity
    source = actor_input.source_evidence
    if actor_input.state is not ActorModelInputState.CURRENT or source is None:
        disposition = {
            ActorModelInputState.MISSING: ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
            ActorModelInputState.INVALID: ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
            ActorModelInputState.FUTURE: ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
            ActorModelInputState.STALE: ActorAssessmentDisposition.ACTOR_MODEL_STALE,
        }[actor_input.state]
        assessment = _assessment(
            actor_input=actor_input,
            disposition=disposition,
            context=actor_context,
            baseline_finding_sha256=baseline.finding_sha256,
            original=original,
            calibrated=original,
            likelihood=ActorLikelihoodAdjustment.UNASSESSED,
            limitation=actor_input.limitations[0],
        )
        return ActorCalibrationResult(
            finding=finding.model_copy(update={"actor_assessment": assessment})
        )

    actor_model = source.actor_model
    if actor_context is None:
        if (
            finding.actor_model_applicability
            is ActorModelApplicability.NO_PRIVILEGED_ACTOR_REQUIRED
        ):
            assessment = _assessment(
                actor_input=actor_input,
                disposition=ActorAssessmentDisposition.NOT_APPLICABLE_NONPRIVILEGED,
                context=None,
                baseline_finding_sha256=baseline.finding_sha256,
                original=original,
                calibrated=original,
                likelihood=ActorLikelihoodAdjustment.UNCHANGED,
                limitation=None,
            )
            return ActorCalibrationResult(
                finding=finding.model_copy(update={"actor_assessment": assessment})
            )
        missing_context_limitation = (
            "finding did not state a typed actor role and conduct assumption; "
            "severity could not consume the current actor model"
        )
        assessment = _assessment(
            actor_input=actor_input,
            disposition=ActorAssessmentDisposition.FINDING_ACTOR_UNSTATED,
            context=None,
            baseline_finding_sha256=baseline.finding_sha256,
            original=original,
            calibrated=original,
            likelihood=ActorLikelihoodAdjustment.UNASSESSED,
            limitation=missing_context_limitation,
        )
        return ActorCalibrationResult(
            finding=finding.model_copy(update={"actor_assessment": assessment})
        )

    role = actor_model.role(actor_context.role_id)
    if role is None:
        governance = ActorGovernanceFinding.build(
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNMODELED_ROLE,
            role_id=actor_context.role_id,
            source_finding_ids=(finding.id,),
            detail="finding references a role absent from the operator actor model",
            actor_model_sha256=actor_model.artifact_sha256,
        )
        unmodeled_role_limitation = (
            "finding actor role is absent from the current operator actor model"
        )
        assessment = _assessment(
            actor_input=actor_input,
            disposition=ActorAssessmentDisposition.ROLE_UNMODELED,
            context=actor_context,
            baseline_finding_sha256=baseline.finding_sha256,
            original=original,
            calibrated=original,
            likelihood=ActorLikelihoodAdjustment.UNASSESSED,
            limitation=unmodeled_role_limitation,
            governance_conflict_id=governance.conflict_id,
        )
        return ActorCalibrationResult(
            finding=finding.model_copy(update={"actor_assessment": assessment}),
            governance_findings=(governance,),
        )

    holder = actor_model.party(role.holder_party_id) if role.holder_party_id is not None else None
    if actor_context.harmed_party_disposition is ActorHarmedPartyDisposition.UNRESOLVED:
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_HARMED_PARTY_UNRESOLVED,
            detail="finding leaves the economically harmed party unresolved",
            limitation="finding harmed-party identity is unresolved; severity was not changed",
        )
    if (
        actor_context.harmed_party_id is not None
        and actor_model.party(actor_context.harmed_party_id) is None
    ):
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNMODELED_PARTY,
            detail="finding references a harmed party absent from the operator actor model",
            limitation="finding harmed party is absent from the current operator actor model",
        )
    if (
        actor_context.privileged_action_required
        and actor_context.permission not in role.permissions
    ):
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_PERMISSION,
            detail="finding references a permission absent from its operator actor role",
            limitation="finding actor permission is absent from the current operator actor model",
        )

    constraints = {item.constraint_id: item for item in role.operational_constraints}
    unknown_constraints = tuple(
        identifier
        for identifier in actor_context.relevant_constraint_ids
        if identifier not in constraints
    )
    if unknown_constraints:
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_CONSTRAINT,
            detail="finding references an operator constraint absent from its actor role",
            limitation="finding references an unknown actor constraint; severity was not changed",
        )
    unsupported_constraints = tuple(
        identifier
        for identifier in actor_context.relevant_constraint_ids
        if actor_context.permission not in constraints[identifier].applies_to_permissions
    )
    if unsupported_constraints:
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNSUPPORTED_CONSTRAINT,
            detail="finding constraint is not operator-linked to its exact role permission",
            limitation="finding constraint does not apply to the selected actor permission",
        )
    if actor_context.action_against_stated_interest and (
        holder is None or actor_context.stated_interest not in holder.stated_interests
    ):
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_STATED_INTEREST,
            detail="finding references an interest absent from the exact operator-held party",
            limitation="finding stated interest is not bound to the selected role holder",
        )
    allowed_plausibility_evidence = set(role.evidence_reference_ids)
    if holder is not None:
        allowed_plausibility_evidence.update(holder.evidence_reference_ids)
    if not set(actor_context.plausibility_evidence_reference_ids) <= (
        allowed_plausibility_evidence
    ):
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=(ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_PLAUSIBILITY_EVIDENCE),
            detail="finding plausibility rationale cites evidence absent from its actor facts",
            limitation="finding plausibility rationale lacks exact operator-evidence custody",
        )
    if not set(actor_context.required_concentrated_role_ids) <= set(
        role.concentrated_with_role_ids
    ):
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=ActorGovernanceConflictKind.FINDING_REFERENCES_UNKNOWN_CONCENTRATED_ROLE,
            detail="finding requires a role absent from the exact holder concentration",
            limitation="finding role-concentration assumption is not operator-bound",
        )
    unsupported_exposures = tuple(
        exposure
        for exposure in actor_context.relevant_economic_exposures
        if holder is None
        or (
            exposure is ActorEconomicExposureKind.FEE_REVENUE
            and holder.fee_revenue_exposure.state is not ActorExposureState.PRESENT
        )
        or (
            exposure is ActorEconomicExposureKind.PROTOCOL_FAILURE_LOSS
            and holder.protocol_failure_loss.state is not ActorExposureState.PRESENT
        )
    )
    if unsupported_exposures:
        return _unverified_actor_context_result(
            finding=finding,
            actor_input=actor_input,
            actor_context=actor_context,
            role_occupancy=role.occupancy,
            holder_party_id=role.holder_party_id,
            kind=(ActorGovernanceConflictKind.FINDING_REFERENCES_UNSUPPORTED_ECONOMIC_EXPOSURE),
            detail="finding economic alignment is absent from the exact operator-held party",
            limitation="finding economic-exposure assumption is not operator-bound",
        )

    likelihood = (
        ActorLikelihoodAdjustment.INCREASED
        if (not actor_context.misconduct_required or actor_context.required_concentrated_role_ids)
        else ActorLikelihoodAdjustment.UNCHANGED
    )
    disposition = ActorAssessmentDisposition.CURRENT_ROLE
    calibrated = original
    severity_downgrade_required = False
    limitation: str | None = None
    governance_findings: tuple[ActorGovernanceFinding, ...] = ()
    capital_before_harmed = (
        _capital_consumed_before_harmed_party(
            actor_model,
            holder_party_id=role.holder_party_id,
            harmed_party_id=actor_context.harmed_party_id,
        )
        if actor_context.privileged_action_required
        and role.occupancy is ActorRoleOccupancy.CURRENTLY_HELD
        else None
    )
    if (
        actor_context.privileged_action_required
        and role.occupancy is ActorRoleOccupancy.CURRENTLY_HELD
        and actor_context.harmed_party_id is not None
        and capital_before_harmed is None
    ):
        limitation = (
            "material comparable actor/harmed-party capital was unavailable; "
            "capital-seniority plausibility is unresolved"
        )
    if actor_context.ordinary_legitimate_behavior:
        disposition = ActorAssessmentDisposition.ORDINARY_LEGITIMATE_BEHAVIOR
    if (
        actor_context.privileged_action_required
        and role.occupancy is ActorRoleOccupancy.ADMITTED_UNFILLED
    ):
        disposition = ActorAssessmentDisposition.ADMITTED_ROLE_UNFILLED
        severity_downgrade_required = True
        limitation = "role is admitted but currently unfilled; reachability requires activation"
        governance_findings = (
            ActorGovernanceFinding.build(
                kind=(ActorGovernanceConflictKind.FINDING_DEPENDS_ON_ADMITTED_UNFILLED_ROLE),
                role_id=role.role_id,
                source_finding_ids=(finding.id,),
                detail="finding depends on an admitted but currently unfilled privileged role",
                actor_model_sha256=actor_model.artifact_sha256,
            ),
        )
    elif actor_context.privileged_action_required:
        relevant_constraints = tuple(
            constraints[identifier] for identifier in actor_context.relevant_constraint_ids
        )
        material_constraint_present = any(
            _constraint_reduces_execution(
                actor_model,
                role_id=role.role_id,
                holder_party_id=role.holder_party_id,
                constraint=constraint,
            )
            for constraint in relevant_constraints
        )
        if material_constraint_present:
            severity_downgrade_required = True
        elif relevant_constraints and limitation is None:
            limitation = (
                "referenced actor constraints do not meet the host materiality threshold; "
                "severity was not reduced"
            )
        aligned_action = (
            actor_context.action_against_stated_interest
            or capital_before_harmed is True
            or bool(actor_context.relevant_economic_exposures)
        )
        if aligned_action and not actor_context.ordinary_legitimate_behavior:
            if actor_context.plausibility_rationale is None:
                severity_downgrade_required = True
                disposition = ActorAssessmentDisposition.ALIGNED_ACTION_UNJUSTIFIED
            else:
                disposition = ActorAssessmentDisposition.ALIGNED_ACTION_JUSTIFIED

    if severity_downgrade_required:
        calibrated = _lower_severity(original)
    if (
        actor_context.misconduct_required
        and not actor_context.required_concentrated_role_ids
        and SEVERITY_ORDER[calibrated.value] < SEVERITY_ORDER[original.value]
    ):
        likelihood = ActorLikelihoodAdjustment.DECREASED

    assessment = _assessment(
        actor_input=actor_input,
        disposition=disposition,
        context=actor_context,
        baseline_finding_sha256=baseline.finding_sha256,
        original=original,
        calibrated=calibrated,
        likelihood=likelihood,
        limitation=limitation,
        role_occupancy=role.occupancy,
        holder_party_id=role.holder_party_id,
        capital_consumed_before_harmed_party=capital_before_harmed,
        governance_conflict_id=(
            governance_findings[0].conflict_id if governance_findings else None
        ),
        concentrated_with_role_ids=role.concentrated_with_role_ids,
        holder_fee_revenue_exposure=(
            holder.fee_revenue_exposure.state if holder is not None else None
        ),
        holder_protocol_failure_loss=(
            holder.protocol_failure_loss.state if holder is not None else None
        ),
    )
    return ActorCalibrationResult(
        finding=finding.model_copy(update={"severity": calibrated, "actor_assessment": assessment}),
        governance_findings=governance_findings,
    )


def bind_judged_actor_context(
    finding: Finding,
    *,
    judgment: JudgeDecision | None,
    actor_input: ActorModelInputEvidence,
) -> Finding:
    """Bind actor-aware annotation without granting it classification authority."""

    if judgment is not None and (finding.group_id is None or judgment.group_id != finding.group_id):
        raise ValueError("actor judge decision differs from the finding group")
    applicability = (
        judgment.actor_model_applicability
        if judgment is not None
        else ActorModelApplicability.UNSTATED
    )
    context = judgment.actor_context if judgment is not None else None
    if actor_input.state is not ActorModelInputState.CURRENT:
        applicability = ActorModelApplicability.UNSTATED
        context = None
    return Finding.model_validate(
        finding.model_copy(
            update={
                "actor_model_applicability": applicability,
                "actor_context": context,
                "actor_assessment": None,
            }
        ).model_dump(mode="python")
    )


def build_actor_model_evaluation(
    *,
    actor_input: ActorModelInputEvidence,
    findings: Iterable[Finding],
    baseline_artifact: ActorModelBaselineArtifact,
    governance_findings: Iterable[ActorGovernanceFinding],
) -> ActorModelEvaluation:
    """Seal run-level provenance for every final severity-bearing finding."""

    baseline_by_id = {item.finding.id: item for item in baseline_artifact.findings}
    bindings: list[ActorFindingAssessmentBinding] = []
    for finding in findings:
        assessment = finding.actor_assessment
        if assessment is None:
            raise ValueError("actor-model evaluation cannot omit a finding assessment")
        baseline = baseline_by_id.get(finding.id)
        if baseline is None or baseline.finding_sha256 != assessment.baseline_finding_sha256:
            raise ValueError("actor-model evaluation lacks the exact calibration baseline")
        bindings.append(
            ActorFindingAssessmentBinding(
                finding_id=finding.id,
                baseline_finding_sha256=baseline.finding_sha256,
                assessment_sha256=assessment.assessment_sha256,
            )
        )
    if set(baseline_by_id) != {finding.id for finding in findings}:
        raise ValueError("actor-model baseline inventory differs from final findings")
    return ActorModelEvaluation.build(
        evaluated_at=actor_input.evaluated_at,
        input_evidence=actor_input,
        governance_findings=_canonical_governance_findings(governance_findings),
        finding_assessments=tuple(sorted(bindings, key=lambda item: item.finding_id)),
    )


def validate_actor_model_evaluation(
    *,
    findings: Iterable[Finding],
    evaluation: ActorModelEvaluation,
    baseline_artifact: ActorModelBaselineArtifact,
    judge_decisions: Iterable[JudgeDecision] = (),
) -> None:
    """Recompute every actor calibration and reject unbound governance evidence."""

    retained = tuple(findings)
    retained_judgments = tuple(judge_decisions)
    finding_ids = tuple(finding.id for finding in retained)
    if finding_ids != tuple(dict.fromkeys(finding_ids)):
        raise ValueError("actor evaluation finding inventory contains duplicate IDs")
    baseline_by_id = {item.finding.id: item for item in baseline_artifact.findings}
    if set(baseline_by_id) != set(finding_ids):
        raise ValueError("actor-model baseline inventory differs from retained findings")
    judgment_group_ids = tuple(decision.group_id for decision in retained_judgments)
    if judgment_group_ids != tuple(sorted(set(judgment_group_ids))):
        raise ValueError("actor judge decisions must be unique and sorted by group ID")
    grouped_findings: dict[str, Finding] = {}
    for finding in retained:
        if finding.origin_kind is FindingOriginKind.STATIC_ANALYZER:
            continue
        if finding.group_id is None:
            raise ValueError("non-static actor finding lacks a judgment group ID")
        if finding.group_id in grouped_findings:
            raise ValueError("actor finding inventory repeats a judgment group ID")
        grouped_findings[finding.group_id] = finding
    if retained_judgments and set(judgment_group_ids) != set(grouped_findings):
        raise ValueError("actor judge decisions differ from terminal finding groups")
    judgments_by_group = {decision.group_id: decision for decision in retained_judgments}
    expected_bindings = tuple(
        sorted(
            (
                finding.id,
                finding.actor_assessment.baseline_finding_sha256,
                finding.actor_assessment.assessment_sha256,
            )
            for finding in retained
            if finding.actor_assessment is not None
        )
    )
    observed_bindings = tuple(
        (
            binding.finding_id,
            binding.baseline_finding_sha256,
            binding.assessment_sha256,
        )
        for binding in evaluation.finding_assessments
    )
    if len(expected_bindings) != len(retained) or observed_bindings != expected_bindings:
        raise ValueError("actor evaluation bindings differ from retained findings")

    source = evaluation.input_evidence.source_evidence
    expected_model_sha256 = source.actor_model.artifact_sha256 if source is not None else None
    expected_source_governance: list[ActorGovernanceFinding] = []
    for finding in retained:
        assessment = finding.actor_assessment
        if assessment is None:
            raise ValueError("actor evaluation cannot omit a finding assessment")
        baseline_record = baseline_by_id[finding.id]
        if assessment.baseline_finding_sha256 != baseline_record.finding_sha256:
            raise ValueError("actor assessment differs from its retained calibration baseline")
        baseline = baseline_record.finding
        if (
            baseline.actor_model_applicability != finding.actor_model_applicability
            or baseline.actor_context != finding.actor_context
        ):
            raise ValueError("final actor context differs from its retained calibration baseline")
        judgment = (
            judgments_by_group.get(finding.group_id)
            if finding.origin_kind is not FindingOriginKind.STATIC_ANALYZER
            and finding.group_id is not None
            else None
        )
        if evaluation.input_evidence.state is ActorModelInputState.CURRENT and judgment is not None:
            expected_applicability = judgment.actor_model_applicability
            expected_context = judgment.actor_context
        else:
            expected_applicability = ActorModelApplicability.UNSTATED
            expected_context = None
        if (
            baseline.actor_model_applicability is not expected_applicability
            or baseline.actor_context != expected_context
        ):
            raise ValueError("actor finding annotation differs from its retained judge decision")
        recalibrated = calibrate_finding(
            baseline,
            actor_context=baseline.actor_context,
            actor_input=evaluation.input_evidence,
        )
        if (
            recalibrated.finding.severity is not finding.severity
            or recalibrated.finding.actor_assessment != assessment
        ):
            raise ValueError("finding differs from deterministic actor recalibration")
        expected_source_governance.extend(recalibrated.governance_findings)

    governance = evaluation.governance_findings
    if evaluation.input_evidence.state is not ActorModelInputState.CURRENT and governance:
        raise ValueError("non-current actor evidence cannot claim governance findings")
    known_ids = set(finding_ids)
    if any(
        item.actor_model_sha256 != expected_model_sha256
        or not set(item.source_finding_ids) <= known_ids
        for item in governance
    ):
        raise ValueError("actor governance evidence differs from its model or finding inventory")
    observed_source_governance = tuple(item for item in governance if item.source_finding_ids)
    expected_source_governance_tuple = _canonical_governance_findings(expected_source_governance)
    if observed_source_governance != expected_source_governance_tuple:
        raise ValueError("actor governance evidence differs from deterministic recalibration")
    graph_kinds = {
        ActorGovernanceConflictKind.CODE_PERMITS_ADMITTED_UNFILLED_ROLE,
        ActorGovernanceConflictKind.CODE_ROLE_ABSENT_FROM_ACTOR_MODEL,
        ActorGovernanceConflictKind.ACTOR_ROLE_BINDING_ABSENT_FROM_CODE,
        ActorGovernanceConflictKind.GRAPH_EVIDENCE_INCOMPLETE,
    }
    for item in governance:
        if item.source_finding_ids:
            continue
        if item.kind not in graph_kinds:
            raise ValueError("source-free actor governance finding has an invalid kind")
        if (
            item.kind
            in {
                ActorGovernanceConflictKind.CODE_PERMITS_ADMITTED_UNFILLED_ROLE,
                ActorGovernanceConflictKind.CODE_ROLE_ABSENT_FROM_ACTOR_MODEL,
            }
            and not item.code_evidence
        ):
            raise ValueError("code-derived actor governance finding lacks exact code evidence")


def _assessment(
    *,
    actor_input: ActorModelInputEvidence,
    disposition: ActorAssessmentDisposition,
    context: CandidateActorContext | None,
    baseline_finding_sha256: str,
    original: Severity,
    calibrated: Severity,
    likelihood: ActorLikelihoodAdjustment,
    limitation: str | None,
    role_occupancy: ActorRoleOccupancy | None = None,
    holder_party_id: str | None = None,
    capital_consumed_before_harmed_party: bool | None = None,
    governance_conflict_id: str | None = None,
    concentrated_with_role_ids: tuple[str, ...] = (),
    holder_fee_revenue_exposure: ActorExposureState | None = None,
    holder_protocol_failure_loss: ActorExposureState | None = None,
) -> FindingActorAssessment:
    source = actor_input.source_evidence
    return FindingActorAssessment.build(
        input_state=actor_input.state,
        disposition=disposition,
        actor_model_sha256=(source.actor_model.artifact_sha256 if source else None),
        actor_model_source_sha256=(source.source_sha256 if source else None),
        role_id=(context.role_id if context else None),
        severity_basis=(context.severity_basis if context else None),
        harmed_party_disposition=(context.harmed_party_disposition if context else None),
        harmed_party_id=(context.harmed_party_id if context else None),
        role_occupancy=role_occupancy,
        holder_party_id=holder_party_id,
        concentrated_with_role_ids=concentrated_with_role_ids,
        holder_fee_revenue_exposure=holder_fee_revenue_exposure,
        holder_protocol_failure_loss=holder_protocol_failure_loss,
        privileged_action_required=(context.privileged_action_required if context else None),
        permission=(context.permission if context else None),
        baseline_finding_sha256=baseline_finding_sha256,
        original_severity=ActorSeverity(original.value),
        calibrated_severity=ActorSeverity(calibrated.value),
        likelihood_adjustment=likelihood,
        misconduct_required=(context.misconduct_required if context else None),
        ordinary_legitimate_behavior=(context.ordinary_legitimate_behavior if context else None),
        action_against_stated_interest=(
            context.action_against_stated_interest if context else None
        ),
        stated_interest=(context.stated_interest if context else None),
        capital_consumed_before_harmed_party=capital_consumed_before_harmed_party,
        applied_constraint_ids=(context.relevant_constraint_ids if context else ()),
        required_concentrated_role_ids=(context.required_concentrated_role_ids if context else ()),
        relevant_economic_exposures=(context.relevant_economic_exposures if context else ()),
        plausibility_rationale=(context.plausibility_rationale if context else None),
        plausibility_evidence_reference_ids=(
            context.plausibility_evidence_reference_ids if context else ()
        ),
        remediation_focus=_remediation_focus(disposition),
        limitation=limitation,
        governance_conflict_id=governance_conflict_id,
    )


def _unverified_actor_context_result(
    *,
    finding: Finding,
    actor_input: ActorModelInputEvidence,
    actor_context: CandidateActorContext,
    role_occupancy: ActorRoleOccupancy,
    holder_party_id: str | None,
    kind: ActorGovernanceConflictKind,
    detail: str,
    limitation: str,
) -> ActorCalibrationResult:
    source = actor_input.source_evidence
    if source is None:
        raise ValueError("current actor-context conflict lacks source evidence")
    governance = ActorGovernanceFinding.build(
        kind=kind,
        role_id=actor_context.role_id,
        source_finding_ids=(finding.id,),
        detail=detail,
        actor_model_sha256=source.actor_model.artifact_sha256,
    )
    role = source.actor_model.role(actor_context.role_id)
    holder = (
        source.actor_model.party(role.holder_party_id)
        if role is not None and role.holder_party_id is not None
        else None
    )
    assessment = _assessment(
        actor_input=actor_input,
        disposition=ActorAssessmentDisposition.CONTEXT_UNVERIFIED,
        context=actor_context,
        baseline_finding_sha256=ActorFindingBaseline.build(finding).finding_sha256,
        original=finding.severity,
        calibrated=finding.severity,
        likelihood=ActorLikelihoodAdjustment.UNASSESSED,
        limitation=limitation,
        role_occupancy=role_occupancy,
        holder_party_id=holder_party_id,
        governance_conflict_id=governance.conflict_id,
        concentrated_with_role_ids=(role.concentrated_with_role_ids if role else ()),
        holder_fee_revenue_exposure=(
            holder.fee_revenue_exposure.state if holder is not None else None
        ),
        holder_protocol_failure_loss=(
            holder.protocol_failure_loss.state if holder is not None else None
        ),
    )
    return ActorCalibrationResult(
        finding=finding.model_copy(update={"actor_assessment": assessment}),
        governance_findings=(governance,),
    )


def _capital_consumed_before_harmed_party(
    actor_model: ActorModel,
    *,
    holder_party_id: str | None,
    harmed_party_id: str | None,
) -> bool | None:
    if holder_party_id is None or harmed_party_id is None:
        return None
    holder = actor_model.party(holder_party_id)
    harmed = actor_model.party(harmed_party_id)
    if holder is None or harmed is None:
        return None
    holder_material = tuple(
        position
        for position in holder.capital_positions
        if position.materiality is ActorCapitalMateriality.MATERIAL
    )
    harmed_material = tuple(
        position
        for position in harmed.capital_positions
        if position.materiality is ActorCapitalMateriality.MATERIAL
    )
    shared_waterfalls = {position.waterfall_id for position in holder_material} & {
        position.waterfall_id for position in harmed_material
    }
    if not shared_waterfalls:
        return None
    comparisons: list[bool] = []
    for waterfall_id in sorted(shared_waterfalls):
        holder_positions = tuple(
            position for position in holder_material if position.waterfall_id == waterfall_id
        )
        harmed_positions = tuple(
            position for position in harmed_material if position.waterfall_id == waterfall_id
        )
        units = {position.amount_unit for position in (*holder_positions, *harmed_positions)}
        if len(units) != 1 or None in units:
            return None
        if any(
            position.loss_absorption_order is None
            for position in (*holder_positions, *harmed_positions)
        ):
            return None
        comparisons.extend(
            holder_position.loss_absorption_order < harmed_position.loss_absorption_order
            for holder_position in holder_positions
            for harmed_position in harmed_positions
            if holder_position.loss_absorption_order is not None
            and harmed_position.loss_absorption_order is not None
        )
    # Every material tranche in every shared waterfall must be comparable and
    # consumed before every harmed-party tranche. Mixed units are unresolved.
    return all(comparisons) if comparisons else None


def _constraint_reduces_execution(
    actor_model: ActorModel,
    *,
    role_id: str,
    holder_party_id: str | None,
    constraint: ActorOperationalConstraint,
) -> bool:
    if constraint.effect in {
        ActorConstraintEffect.REDUCES_OPPORTUNISTIC_EXECUTION,
        ActorConstraintEffect.LIMITS_ACTION_FREQUENCY,
        ActorConstraintEffect.DELAYS_ACTION,
    }:
        return (
            constraint.duration_seconds is not None
            and constraint.duration_seconds >= ACTOR_CONSTRAINT_MIN_MATERIAL_DURATION_SECONDS
        )
    if constraint.effect is not ActorConstraintEffect.REQUIRES_MULTIPARTY_APPROVAL:
        return False
    approvers = tuple(
        actor_model.role(approver_id)
        for approver_id in constraint.required_approver_role_ids
        if approver_id != role_id
    )
    return bool(approvers) and all(
        approver is not None
        and approver.occupancy is ActorRoleOccupancy.CURRENTLY_HELD
        and approver.holder_party_id is not None
        and approver.holder_party_id != holder_party_id
        for approver in approvers
    )


def _actor_code_role_evidence(node: SolidityGraphNode) -> ActorCodeRoleEvidence:
    return ActorCodeRoleEvidence.build(
        node_id=node.id,
        label=node.label,
        path=node.path,
        start_line=node.start_line,
        end_line=node.end_line,
        source_sha256=node.source_hash,
        provenance=node.provenance.value,
        confidence=node.confidence,
        transformation=node.transformation,
    )


def _lower_severity(severity: Severity) -> Severity:
    ordered = tuple(sorted(Severity, key=lambda item: SEVERITY_ORDER[item.value]))
    index = ordered.index(severity)
    return ordered[max(0, index - 1)]


def _remediation_focus(
    disposition: ActorAssessmentDisposition,
) -> ActorRemediationFocus:
    if disposition is ActorAssessmentDisposition.ORDINARY_LEGITIMATE_BEHAVIOR:
        return ActorRemediationFocus.LEGITIMATE_STATE_TRANSITION
    if disposition is ActorAssessmentDisposition.ADMITTED_ROLE_UNFILLED:
        return ActorRemediationFocus.ROLE_ACTIVATION_CONTROL
    if disposition in {
        ActorAssessmentDisposition.ALIGNED_ACTION_JUSTIFIED,
        ActorAssessmentDisposition.ALIGNED_ACTION_UNJUSTIFIED,
    }:
        return ActorRemediationFocus.ECONOMIC_PLAUSIBILITY
    if disposition in {
        ActorAssessmentDisposition.ACTOR_MODEL_MISSING,
        ActorAssessmentDisposition.ACTOR_MODEL_INVALID,
        ActorAssessmentDisposition.ACTOR_MODEL_FUTURE,
        ActorAssessmentDisposition.ACTOR_MODEL_STALE,
        ActorAssessmentDisposition.FINDING_ACTOR_UNSTATED,
        ActorAssessmentDisposition.ROLE_UNMODELED,
        ActorAssessmentDisposition.CONTEXT_UNVERIFIED,
    }:
        return ActorRemediationFocus.ACTOR_CONTEXT_VERIFICATION
    return ActorRemediationFocus.REACHABLE_STATE_TRANSITION


def _canonical_governance_findings(
    findings: Iterable[ActorGovernanceFinding],
) -> tuple[ActorGovernanceFinding, ...]:
    by_id: dict[str, ActorGovernanceFinding] = {}
    for item in findings:
        if item.conflict_id in by_id:
            raise ValueError("actor governance finding inventory contains a duplicate conflict ID")
        by_id[item.conflict_id] = item
    return tuple(by_id[key] for key in sorted(by_id))


def _read_bounded_repository_file(
    repository_root: Path,
    relative_path: str,
    *,
    max_bytes: int,
) -> bytes:
    normalized = normalize_relative_path(relative_path)
    if is_sensitive_workspace_path(normalized):
        raise ValueError("actor-model input uses a forbidden credential-like filename")
    parts = PurePosixPath(normalized).parts
    if not parts:
        raise ValueError("actor-model input path is empty")
    root = repository_root.resolve(strict=True)
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (
        not isinstance(directory, int)
        or directory <= 0
        or not isinstance(nofollow, int)
        or nofollow <= 0
    ):
        raise ValueError("descriptor-safe actor-model input I/O is unavailable")
    directory_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )
    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current, _metadata = _open_exact_actor_path_component(
                current,
                part,
                flags=directory_flags,
                require_directory=True,
            )
            descriptors.append(current)
        file_descriptor, opened = _open_exact_actor_path_component(
            current,
            parts[-1],
            flags=file_flags,
            require_directory=False,
            max_bytes=max_bytes,
        )
        descriptors.append(file_descriptor)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(file_descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        finished = os.fstat(file_descriptor)
        _validate_actor_file_metadata(finished, max_bytes=max_bytes)
        _require_exact_actor_directory_entry(
            current,
            parts[-1],
            missing_is_identity_error=True,
        )
        try:
            after = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        except OSError as exc:
            raise ActorModelPathIdentityError(
                "actor-model path changed after its post-read spelling check"
            ) from exc
        _validate_actor_file_metadata(after, max_bytes=max_bytes)
        if (
            len(raw) != opened.st_size
            or len(raw) > max_bytes
            or len(
                {
                    _actor_file_identity(opened),
                    _actor_file_identity(finished),
                    _actor_file_identity(after),
                }
            )
            != 1
        ):
            raise ActorModelPathIdentityError(
                "actor-model input identity changed during bounded read"
            )
        _revalidate_exact_actor_path(
            root,
            parts,
            expected=finished,
            max_bytes=max_bytes,
            directory_flags=directory_flags,
            file_flags=file_flags,
        )
        return raw
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_exact_actor_path_component(
    parent_descriptor: int,
    name: str,
    *,
    flags: int,
    require_directory: bool,
    max_bytes: int | None = None,
) -> tuple[int, os.stat_result]:
    """Open one component only when its supplied spelling is a real directory entry."""

    _require_exact_actor_directory_entry(parent_descriptor, name)
    try:
        before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise ActorModelPathIdentityError(
            "actor-model path changed after its exact-spelling check"
        ) from exc
    if require_directory:
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("actor-model path component is not a directory")
    else:
        if max_bytes is None:
            raise ValueError("actor-model file opening requires a byte ceiling")
        _validate_actor_file_metadata(before, max_bytes=max_bytes)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise ActorModelPathIdentityError(
            "actor-model path changed before its exact component could be opened"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if require_directory:
            if not stat.S_ISDIR(opened.st_mode):
                raise ValueError("actor-model path component is not a directory")
        else:
            assert max_bytes is not None
            _validate_actor_file_metadata(opened, max_bytes=max_bytes)
        _require_exact_actor_directory_entry(
            parent_descriptor,
            name,
            missing_is_identity_error=True,
        )
        try:
            after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ActorModelPathIdentityError(
                "actor-model path changed after its exact component was opened"
            ) from exc
        if require_directory:
            if not stat.S_ISDIR(after.st_mode):
                raise ActorModelPathIdentityError(
                    "actor-model directory identity changed during exact traversal"
                )
        else:
            assert max_bytes is not None
            _validate_actor_file_metadata(after, max_bytes=max_bytes)
        if (
            len(
                {
                    _actor_node_identity(before),
                    _actor_node_identity(opened),
                    _actor_node_identity(after),
                }
            )
            != 1
        ):
            raise ActorModelPathIdentityError(
                "actor-model path component identity changed during exact traversal"
            )
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _require_exact_actor_directory_entry(
    directory_descriptor: int,
    name: str,
    *,
    missing_is_identity_error: bool = False,
) -> None:
    """Require exact code-point equality with one bounded directory-entry inventory."""

    requested_key = _actor_path_equivalence_key(name)
    exact_match = False
    equivalent_matches = 0
    try:
        with os.scandir(directory_descriptor) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > _ACTOR_MODEL_MAX_DIRECTORY_ENTRIES:
                    raise ActorModelPathIdentityError(
                        "actor-model path directory exceeds the exact-spelling scan bound"
                    )
                if _actor_path_equivalence_key(entry.name) != requested_key:
                    continue
                equivalent_matches += 1
                exact_match = exact_match or entry.name == name
    except ActorModelPathIdentityError:
        raise
    except OSError as exc:
        raise ActorModelPathIdentityError(
            "actor-model path spelling could not be checked safely"
        ) from exc

    if exact_match and equivalent_matches == 1:
        return
    if equivalent_matches:
        raise ActorModelPathIdentityError(
            "actor-model path uses a case or Unicode-normalization alias"
        )
    if missing_is_identity_error:
        raise ActorModelPathIdentityError("actor-model path spelling changed after exact traversal")
    try:
        os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ActorModelPathIdentityError(
            "actor-model path spelling could not be resolved safely"
        ) from exc
    raise ActorModelPathIdentityError("actor-model path uses a case or Unicode-normalization alias")


def _actor_path_equivalence_key(value: str) -> str:
    """Return only the conservative key used to reject ambiguous path spellings."""

    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", value).casefold())


def _revalidate_exact_actor_path(
    root: Path,
    parts: tuple[str, ...],
    *,
    expected: os.stat_result,
    max_bytes: int,
    directory_flags: int,
    file_flags: int,
) -> None:
    """Reopen the root-visible exact path and require the same final file identity."""

    descriptors: list[int] = []
    try:
        current = os.open(root, directory_flags)
        descriptors.append(current)
        for part in parts[:-1]:
            current, _metadata = _open_exact_actor_path_component(
                current,
                part,
                flags=directory_flags,
                require_directory=True,
            )
            descriptors.append(current)
        file_descriptor, observed = _open_exact_actor_path_component(
            current,
            parts[-1],
            flags=file_flags,
            require_directory=False,
            max_bytes=max_bytes,
        )
        descriptors.append(file_descriptor)
        if _actor_file_identity(observed) != _actor_file_identity(expected):
            raise ActorModelPathIdentityError(
                "actor-model root-visible identity differs after bounded read"
            )
    except ActorModelPathIdentityError:
        raise
    except (OSError, ValueError) as exc:
        raise ActorModelPathIdentityError(
            "actor-model exact root-visible path could not be revalidated"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validate_actor_file_metadata(metadata: os.stat_result, *, max_bytes: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > max_bytes
    ):
        raise ValueError("actor-model input must be one bounded unshared regular file")


def _actor_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _actor_node_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("actor-model input contains duplicate object keys")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


JSONDecodeError = json.JSONDecodeError


__all__ = [
    "ActorCalibrationResult",
    "ActorModelPathIdentityError",
    "actor_model_assessment_quality_gate",
    "actor_model_quality_gate",
    "bind_judged_actor_context",
    "build_actor_model_evaluation",
    "calibrate_finding",
    "load_actor_model",
    "reconcile_actor_model_with_graphs",
    "validate_actor_model_evaluation",
    "withhold_actor_model_from_discovery",
]
