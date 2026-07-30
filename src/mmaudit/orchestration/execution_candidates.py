"""Create review candidates from qualifying deterministic invariant executions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from mmaudit.models.schemas import (
    AnalysisState,
    CandidateFinding,
    CandidateOriginKind,
    DynamicPropertySpec,
    Evidence,
    ExecutionOriginDispositionKind,
    ExecutionOriginRejectionCategory,
    FoundryInvariantHarnessSpec,
    InvariantExecutionCandidateProvenance,
    InvariantExecutionOriginDisposition,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSpec,
    InvariantSuite,
    Location,
    PropertyCorpus,
    Severity,
    SolidityProvenance,
    VerificationTest,
)
from mmaudit.repository.locations import validate_location

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORDED_LIMITATIONS = 64
_MAX_TITLE_CHARACTERS = 240


@dataclass(frozen=True, slots=True)
class ExecutionCandidateBuildResult:
    """Deterministic candidate output with explicit rejected-origin accounting."""

    candidates: tuple[CandidateFinding, ...]
    dispositions: tuple[InvariantExecutionOriginDisposition, ...]
    rejected_counterexample_count: int
    limitations: tuple[str, ...]


def build_invariant_execution_candidates(
    *,
    repository_root: Path,
    invariant_suite: InvariantSuite | None,
    harnesses: list[FoundryInvariantHarnessSpec],
    property_corpus: PropertyCorpus,
    executions: list[InvariantExecutionResult],
) -> ExecutionCandidateBuildResult:
    """Build candidates only from fully joined, replayed REAL counterexamples."""

    raw_counterexamples = [
        (execution_index, result)
        for execution_index, result in enumerate(executions)
        if result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    ]
    if not raw_counterexamples:
        return ExecutionCandidateBuildResult(
            candidates=(),
            dispositions=(),
            rejected_counterexample_count=0,
            limitations=(),
        )

    validated_invariants = _validated_invariants(invariant_suite)
    validated_harnesses = _validated_harnesses(harnesses)
    validated_corpus = _validated_property_corpus(property_corpus)
    candidates: list[CandidateFinding] = []
    dispositions: list[InvariantExecutionOriginDisposition] = []
    limitations: list[str] = []
    seen_candidate_ids: set[str] = set()

    def reject(
        *,
        execution_index: int,
        ordinal: int,
        raw_result: InvariantExecutionResult,
        category: ExecutionOriginRejectionCategory,
        reason: str,
    ) -> None:
        limitation = _limitation(ordinal, reason)
        dispositions.append(
            _rejected_disposition(
                execution_index=execution_index,
                result=raw_result,
                category=category,
                detail=limitation,
            )
        )
        limitations.append(limitation)

    for ordinal, (execution_index, raw_result) in enumerate(raw_counterexamples, start=1):
        result = _validated_execution(raw_result)
        if result is None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.RUNTIME_EVIDENCE,
                reason="invalid typed execution result",
            )
            continue

        execution_error = _execution_qualification_error(result)
        if execution_error is not None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.RUNTIME_EVIDENCE,
                reason=execution_error,
            )
            continue

        invariants = [
            invariant for invariant in validated_invariants if invariant.id == result.invariant_id
        ]
        if len(invariants) != 1:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.INVARIANT_BINDING,
                reason="expected exactly one executable non-model invariant",
            )
            continue
        invariant = invariants[0]
        invariant_error = _invariant_qualification_error(invariant)
        if invariant_error is not None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.INVARIANT_BINDING,
                reason=invariant_error,
            )
            continue

        joined_harnesses = [
            harness
            for harness in validated_harnesses
            if harness.invariant_id == result.invariant_id and harness.name == result.harness_name
        ]
        if len(joined_harnesses) != 1:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.HARNESS_BINDING,
                reason="expected exactly one matching typed harness",
            )
            continue
        harness = joined_harnesses[0]
        if (
            result.harness_spec_sha256 != harness.specification_sha256()
            or result.runs != harness.runs
            or result.depth != harness.depth
            or result.seed != harness.seed
        ):
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.HARNESS_BINDING,
                reason="execution identity differs from its exact typed harness",
            )
            continue
        coverage_error = _harness_coverage_error(result, harness)
        if coverage_error is not None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.HARNESS_BINDING,
                reason=coverage_error,
            )
            continue

        if validated_corpus is None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.PROPERTY_BINDING,
                reason="property corpus failed typed validation",
            )
            continue
        properties = [
            property_spec
            for property_spec in validated_corpus.properties
            if property_spec.invariant_id == invariant.id
            and property_spec.harness_name == harness.name
        ]
        property_error = _property_join_error(
            invariant=invariant,
            harness=harness,
            properties=properties,
        )
        if property_error is not None:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.PROPERTY_BINDING,
                reason=property_error,
            )
            continue

        source_locations = _canonical_source_locations(properties)
        if not source_locations or _location_keys(source_locations) != _location_keys(
            invariant.locations
        ):
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.SOURCE_BINDING,
                reason="property source locations do not exactly match the invariant",
            )
            continue
        if not _locations_validate(repository_root, source_locations):
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.SOURCE_BINDING,
                reason="property source location failed current-source validation",
            )
            continue

        provenance = InvariantExecutionCandidateProvenance.sealed(
            invariant_id=invariant.id,
            invariant_evidence_sha256=invariant.evidence_hash,
            harness_name=harness.name,
            harness_spec_sha256=harness.specification_sha256(),
            property_corpus_sha256=validated_corpus.corpus_hash,
            property_ids=tuple(sorted(property_spec.id for property_spec in properties)),
            property_hashes=tuple(
                sorted(property_spec.property_hash for property_spec in properties)
            ),
            execution_result_sha256=result.canonical_result_sha256(),
            execution_observation_sha256=result.execution_observation_sha256,
            executable_sha256=result.executable_sha256,
            source_sha256=result.source_sha256,
            compiler_version=result.compiler_version,
            compiler_sha256=result.compiler_sha256,
            isolation_backend=result.isolation_backend,
            isolation_attestation_sha256=result.isolation_attestation_sha256,
            attempts=result.attempts,
            successful_attempts=result.successful_attempts,
            minimized=bool(
                result.minimization_evidence is not None
                and result.minimization_evidence.proven_minimal
            ),
            source_locations=source_locations,
        )
        validate_invariant_execution_candidate_provenance(
            provenance,
            invariant_suite=invariant_suite,
            harnesses=harnesses,
            property_corpus=property_corpus,
            executions=executions,
        )
        candidate = _candidate_from_execution(
            invariant=invariant,
            properties=properties,
            provenance=provenance,
        )
        if candidate.candidate_id in seen_candidate_ids:
            reject(
                execution_index=execution_index,
                ordinal=ordinal,
                raw_result=raw_result,
                category=ExecutionOriginRejectionCategory.DUPLICATE_ORIGIN,
                reason="duplicate execution provenance was omitted",
            )
            continue
        seen_candidate_ids.add(candidate.candidate_id)
        candidates.append(candidate)
        dispositions.append(
            InvariantExecutionOriginDisposition(
                execution_index=execution_index,
                invariant_id=result.invariant_id,
                harness_name=result.harness_name,
                execution_result_sha256=provenance.execution_result_sha256,
                kind=ExecutionOriginDispositionKind.ORIGINATED,
                candidate_id=candidate.candidate_id,
                execution_provenance=provenance,
            )
        )

    return ExecutionCandidateBuildResult(
        candidates=tuple(sorted(candidates, key=lambda item: item.candidate_id)),
        dispositions=tuple(sorted(dispositions, key=lambda item: item.execution_index)),
        rejected_counterexample_count=sum(
            disposition.kind is ExecutionOriginDispositionKind.REJECTED
            for disposition in dispositions
        ),
        limitations=_bounded_limitations(limitations),
    )


def validate_invariant_execution_candidate_provenance(
    provenance: InvariantExecutionCandidateProvenance,
    *,
    invariant_suite: InvariantSuite | None,
    harnesses: list[FoundryInvariantHarnessSpec],
    property_corpus: PropertyCorpus,
    executions: list[InvariantExecutionResult],
) -> None:
    """Cross-bind one execution origin to every exact serialized runtime input."""

    provenance = InvariantExecutionCandidateProvenance.model_validate(
        provenance.model_dump(mode="python")
    )
    validated_invariants = _validated_invariants(invariant_suite)
    validated_harnesses = _validated_harnesses(harnesses)
    validated_corpus = _validated_property_corpus(property_corpus)
    validated_executions = [
        result
        for raw_result in executions
        if (result := _validated_execution(raw_result)) is not None
    ]
    invariants = [
        invariant for invariant in validated_invariants if invariant.id == provenance.invariant_id
    ]
    joined_harnesses = [
        harness
        for harness in validated_harnesses
        if harness.invariant_id == provenance.invariant_id
        and harness.name == provenance.harness_name
    ]
    joined_results = [
        result
        for result in validated_executions
        if result.invariant_id == provenance.invariant_id
        and result.harness_name == provenance.harness_name
    ]
    if (
        len(invariants) != 1
        or len(joined_harnesses) != 1
        or len(joined_results) != 1
        or validated_corpus is None
    ):
        raise ValueError(
            "execution provenance lacks one exact invariant, harness, result, or corpus"
        )

    invariant = invariants[0]
    harness = joined_harnesses[0]
    result = joined_results[0]
    if (
        _invariant_qualification_error(invariant) is not None
        or _execution_qualification_error(result) is not None
        or result.harness_spec_sha256 != harness.specification_sha256()
        or result.runs != harness.runs
        or result.depth != harness.depth
        or result.seed != harness.seed
        or _harness_coverage_error(result, harness) is not None
    ):
        raise ValueError("execution provenance runtime evidence is not qualifying")

    properties = [
        property_spec
        for property_spec in validated_corpus.properties
        if property_spec.invariant_id == invariant.id and property_spec.harness_name == harness.name
    ]
    if (
        _property_join_error(
            invariant=invariant,
            harness=harness,
            properties=properties,
        )
        is not None
    ):
        raise ValueError("execution provenance property bindings differ from the runtime corpus")
    source_locations = _canonical_source_locations(properties)
    result_minimized = bool(
        result.minimization_evidence is not None and result.minimization_evidence.proven_minimal
    )
    expected = {
        "invariant_evidence_sha256": invariant.evidence_hash,
        "harness_spec_sha256": harness.specification_sha256(),
        "property_corpus_sha256": validated_corpus.corpus_hash,
        "property_ids": tuple(sorted(property_spec.id for property_spec in properties)),
        "property_hashes": tuple(
            sorted(property_spec.property_hash for property_spec in properties)
        ),
        "execution_result_sha256": result.canonical_result_sha256(),
        "execution_observation_sha256": result.execution_observation_sha256,
        "executable_sha256": result.executable_sha256,
        "source_sha256": result.source_sha256,
        "compiler_version": result.compiler_version,
        "compiler_sha256": result.compiler_sha256,
        "isolation_backend": result.isolation_backend,
        "isolation_attestation_sha256": result.isolation_attestation_sha256,
        "attempts": result.attempts,
        "successful_attempts": result.successful_attempts,
        "minimized": result_minimized,
        "source_locations": source_locations,
    }
    observed = {field: getattr(provenance, field) for field in expected}
    if observed != expected:
        raise ValueError("execution provenance differs from its exact serialized runtime evidence")


def _validated_invariants(suite: InvariantSuite | None) -> list[InvariantSpec]:
    if suite is None:
        return []
    result: list[InvariantSpec] = []
    for invariant in suite.invariants:
        try:
            result.append(InvariantSpec.model_validate(invariant.model_dump(mode="python")))
        except ValueError:
            continue
    return result


def _validated_harnesses(
    harnesses: list[FoundryInvariantHarnessSpec],
) -> list[FoundryInvariantHarnessSpec]:
    result: list[FoundryInvariantHarnessSpec] = []
    for harness in harnesses:
        try:
            result.append(
                FoundryInvariantHarnessSpec.model_validate(harness.model_dump(mode="python"))
            )
        except ValueError:
            continue
    return result


def _validated_property_corpus(corpus: PropertyCorpus) -> PropertyCorpus | None:
    try:
        return PropertyCorpus.model_validate(corpus.model_dump(mode="python"))
    except ValueError:
        return None


def _validated_execution(result: InvariantExecutionResult) -> InvariantExecutionResult | None:
    try:
        return InvariantExecutionResult.model_validate(result.model_dump(mode="python"))
    except ValueError:
        return None


def _execution_qualification_error(result: InvariantExecutionResult) -> str | None:
    if result.has_qualifying_replayed_real_counterexample_evidence():
        return None
    return "execution did not satisfy repeated REAL isolated evidence requirements"


def _invariant_qualification_error(invariant: InvariantSpec) -> str | None:
    if (
        not invariant.executable
        or invariant.provenance is SolidityProvenance.MODEL_SUGGESTED
        or invariant.analysis_state
        not in {AnalysisState.DETERMINISTIC, AnalysisState.FALLBACK_PARSER}
        or not _is_sha256(invariant.evidence_hash)
        or not invariant.locations
        or not invariant.entity_ids
    ):
        return "invariant was not an executable source-bound non-model invariant"
    return None


def _harness_coverage_error(
    result: InvariantExecutionResult,
    harness: FoundryInvariantHarnessSpec,
) -> str | None:
    coverage = result.campaign_coverage
    if coverage is None:
        return "execution campaign coverage was unavailable"
    expected_actions = sorted({action.function_signature for action in harness.actions})
    expected_properties = sorted(
        {property_spec.property_id for property_spec in harness.properties}
    )
    if (
        not expected_actions
        or len(expected_properties) != len(harness.properties)
        or not expected_properties
        or coverage.declared_action_functions != expected_actions
        or coverage.observed_action_functions != expected_actions
        or coverage.declared_state_properties != expected_properties
        or coverage.observed_state_properties != expected_properties
    ):
        return "execution coverage did not exactly match the typed harness portfolio"
    return None


def _property_join_error(
    *,
    invariant: InvariantSpec,
    harness: FoundryInvariantHarnessSpec,
    properties: list[DynamicPropertySpec],
) -> str | None:
    expected_predicates = {
        property_spec.property_id: property_spec for property_spec in harness.properties
    }
    if (
        not properties
        or len(expected_predicates) != len(harness.properties)
        or len(properties) != len(expected_predicates)
        or {property_spec.property_id for property_spec in properties} != set(expected_predicates)
    ):
        return "property corpus did not contain the exact nonempty harness property set"

    expected_entities = sorted(set(invariant.entity_ids))
    source_keys: set[tuple[tuple[str, int, int, str, str], ...]] = set()
    for property_spec in properties:
        if (
            property_spec.invariant_evidence_hash != invariant.evidence_hash
            or property_spec.predicate != expected_predicates[property_spec.property_id]
            or property_spec.provenance is SolidityProvenance.MODEL_SUGGESTED
            or property_spec.analysis_state
            not in {AnalysisState.DETERMINISTIC, AnalysisState.FALLBACK_PARSER}
            or property_spec.covered_entity_ids != expected_entities
            or property_spec.campaign.seed != harness.seed
            or property_spec.campaign.runs != harness.runs
            or property_spec.campaign.depth != harness.depth
            or not property_spec.source_evidence
        ):
            return "property corpus entry differed from its invariant or typed harness"
        source_keys.add(
            tuple(
                _location_key(source.location)
                for source in sorted(
                    property_spec.source_evidence,
                    key=lambda item: item.entity_id,
                )
            )
        )
    if len(source_keys) != 1:
        return "property corpus entries disagreed on exact source evidence"
    return None


def _canonical_source_locations(
    properties: list[DynamicPropertySpec],
) -> tuple[Location, ...]:
    by_key = {
        _location_key(source.location): source.location
        for property_spec in properties
        for source in property_spec.source_evidence
    }
    return tuple(by_key[key] for key in sorted(by_key))


def _locations_validate(repository_root: Path, locations: tuple[Location, ...]) -> bool:
    try:
        return all(
            validate_location(repository_root, location, context_hashes=None).valid
            for location in locations
        )
    except OSError:
        return False


def _candidate_from_execution(
    *,
    invariant: InvariantSpec,
    properties: list[DynamicPropertySpec],
    provenance: InvariantExecutionCandidateProvenance,
) -> CandidateFinding:
    title = _bounded_title(invariant.title)
    return CandidateFinding(
        candidate_id=f"exec-{provenance.provenance_sha256[:24]}",
        title=f"Invariant counterexample: {title}",
        severity=Severity.INFORMATIONAL,
        confidence=min(
            invariant.confidence,
            *(property_spec.confidence for property_spec in properties),
        ),
        cwe=[],
        owasp=[],
        summary=(
            "Repeated isolated execution produced a replay-confirmed counterexample "
            f"to the typed invariant: {title}."
        ),
        impact=(
            "The bounded execution proves the named state property can be violated under "
            "the recorded harness; impact and production reachability remain subject to review."
        ),
        preconditions=[
            "The typed invariant and harness bindings represent the audited deployment context."
        ],
        locations=list(provenance.source_locations),
        source=None,
        sink=None,
        attack_path=["A bounded isolated campaign reached the recorded invariant counterexample."],
        evidence=[
            Evidence(
                type="execution",
                source="mmaudit-foundry-invariant",
                rule_id=invariant.id,
                description=(
                    "REAL Foundry invariant execution replayed the counterexample across "
                    f"{provenance.attempts} fresh machine-validated attempts."
                ),
                fingerprint=provenance.provenance_sha256,
            )
        ],
        compensating_controls=[],
        false_positive_conditions=[
            "The typed invariant or harness does not represent intended production behavior."
        ],
        recommendation=(
            "Review the violated invariant, remediate the incorrect state transition, and "
            "rerun the bounded local campaign."
        ),
        verification_test=VerificationTest(
            description="Rerun the same typed invariant in a fresh isolated local workspace."
        ),
        origin_kind=CandidateOriginKind.DETERMINISTIC_EXECUTION,
        execution_provenance=provenance,
        role=None,
        model_family=None,
        model_votes=[],
    )


def _location_keys(
    locations: list[Location] | tuple[Location, ...],
) -> set[tuple[str, int, int, str, str]]:
    return {_location_key(location) for location in locations}


def _location_key(location: Location) -> tuple[str, int, int, str, str]:
    return (
        location.path,
        location.start_line,
        location.end_line,
        location.symbol or "",
        location.content_hash or "",
    )


def _rejected_disposition(
    *,
    execution_index: int,
    result: InvariantExecutionResult,
    category: ExecutionOriginRejectionCategory,
    detail: str,
) -> InvariantExecutionOriginDisposition:
    """Bind a rejected origin decision to the exact serialized counterexample."""

    return InvariantExecutionOriginDisposition(
        execution_index=execution_index,
        invariant_id=result.invariant_id,
        harness_name=result.harness_name,
        execution_result_sha256=result.canonical_result_sha256(),
        kind=ExecutionOriginDispositionKind.REJECTED,
        rejection_category=category,
        rejection_detail=detail,
    )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _bounded_title(value: str) -> str:
    normalized = " ".join(value.split())
    return normalized[:_MAX_TITLE_CHARACTERS] or "typed security property"


def _limitation(index: int, reason: str) -> str:
    return f"counterexample {index} was not originated: {reason}"


def _bounded_limitations(limitations: list[str]) -> tuple[str, ...]:
    if len(limitations) <= _MAX_RECORDED_LIMITATIONS:
        return tuple(limitations)
    retained = limitations[: _MAX_RECORDED_LIMITATIONS - 1]
    retained.append(
        f"{len(limitations) - len(retained)} additional counterexample rejection(s) were bounded"
    )
    return tuple(retained)
