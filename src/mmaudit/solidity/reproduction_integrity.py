"""Deterministic integrity verification for isolated reproduction evidence."""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

from mmaudit.models.schemas import (
    CandidateFinding,
    GeneratedFoundryTestSpec,
    Location,
    ReproductionIntegrityAssessment,
    ReproductionIntegrityCheck,
    ReproductionIntegrityCheckKind,
    ReproductionIntegrityStatus,
    ReproductionMinimizationEvidence,
    ReproductionReachabilityEvidence,
    ReproductionResult,
    ReproductionSettlementEvidence,
    ReproductionSettlementStatus,
    ReproductionState,
    ReproductionTargetIdentity,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path
from mmaudit.repository.workspace import validate_copyable_workspace

REPRODUCTION_WORKSPACE_EXCLUDED_NAMES = frozenset(
    {
        ".git",
        ".mmaudit",
        "artifacts",
        "broadcast",
        "cache",
        "node_modules",
        "out",
    }
)
_MAX_HASHED_FILES = 100_000
_MAX_HASHED_BYTES = 2 * 1024**3
_POSITIVE_STATES = {
    ReproductionState.REPRODUCED,
    ReproductionState.REPRODUCED_AND_MINIMIZED,
}


def reproduction_repository_sha256(
    repository_root: Path,
    project: SolidityProjectMetadata,
) -> str:
    """Hash the exact bounded project tree copied into reproduction workspaces."""

    repository = repository_root.resolve(strict=True)
    source = (
        repository if project.project_root == "." else repository / project.project_root
    ).resolve(strict=True)
    source.relative_to(repository)
    return reproduction_tree_sha256(source)


def reproduction_tree_sha256(source: Path) -> str:
    """Hash one already-resolved reproduction tree using copy-equivalent exclusions."""

    source = source.resolve(strict=True)
    validate_copyable_workspace(
        source,
        excluded=lambda path: reproduction_workspace_path_excluded(path, source),
        max_files=_MAX_HASHED_FILES,
        max_total_bytes=_MAX_HASHED_BYTES,
    )
    bindings: list[dict[str, str | int]] = []
    total_bytes = 0
    for candidate in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if reproduction_workspace_path_excluded(candidate, source):
            continue
        if candidate.is_dir():
            continue
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("reproduction repository hash requires unique regular files")
        total_bytes += metadata.st_size
        if len(bindings) + 1 > _MAX_HASHED_FILES or total_bytes > _MAX_HASHED_BYTES:
            raise ValueError("reproduction repository hash bounds were exceeded")
        bindings.append(
            {
                "path": normalize_relative_path(candidate.relative_to(source)),
                "size": metadata.st_size,
                "sha256": _file_sha256(candidate),
            }
        )
    return _canonical_sha256(bindings)


def reproduction_workspace_path_excluded(path: Path, source: Path) -> bool:
    """Apply the same secret and generated-tree exclusions to copies and hashes."""

    relative = path.relative_to(source)
    return any(
        part.lower() in REPRODUCTION_WORKSPACE_EXCLUDED_NAMES for part in relative.parts
    ) or is_sensitive_workspace_path(relative, is_dir=path.is_dir())


def verify_reproduction_integrity(
    *,
    repository_root: Path,
    project: SolidityProjectMetadata,
    candidate: CandidateFinding,
    specification: GeneratedFoundryTestSpec,
    result: ReproductionResult,
    index: SoliditySymbolIndex | None,
    targets: dict[str, str],
    expected_generated_test_sha256: str,
) -> ReproductionResult:
    """Attach a hash-linked six-check assessment without executing target code."""

    repository_sha256: str | None = None
    repository_error: str | None = None
    try:
        repository_sha256 = reproduction_repository_sha256(repository_root, project)
    except (OSError, ValueError) as exc:
        repository_error = type(exc).__name__

    target_identities, target_errors = _target_identities(
        specification,
        result,
        targets,
    )
    target_generated_hash_matches = (
        result.generated_test_sha256 == expected_generated_test_sha256
        and bool(result.attempt_evidence)
        and all(
            attempt.generated_test_sha256 == expected_generated_test_sha256
            for attempt in result.attempt_evidence
        )
    )
    target_passed = not target_errors and target_generated_hash_matches
    target_detail = (
        f"bound {len(target_identities)} target(s) to chain, block, address, source contract, "
        "and generated test"
        if target_passed
        else "target identity is incomplete or does not match the generated test"
    )

    reachability, reachability_errors = _reachability_evidence(
        repository_root,
        candidate,
        specification,
        index,
    )
    reachability_passed = not reachability_errors and len(reachability) == len(
        specification.attack_calls
    )
    reachability_detail = (
        f"validated {len(reachability)} attacker-call source citation(s)"
        if reachability_passed
        else "one or more attacker calls lack exact cited public/external source reachability"
    )

    repository_passed = (
        repository_sha256 is not None
        and result.repository_sha256 == repository_sha256
        and bool(result.attempt_evidence)
        and all(
            attempt.repository_sha256 == repository_sha256 for attempt in result.attempt_evidence
        )
    )
    repository_detail = (
        "execution and every clean replay match the current bounded repository hash"
        if repository_passed
        else (
            f"repository hash could not be established: {repository_error}"
            if repository_error
            else "execution repository hash is absent, stale, or inconsistent"
        )
    )

    clean_passed, clean_detail = _clean_replay_check(
        result,
        expected_generated_test_sha256,
        repository_sha256,
    )
    settlement, settlement_passed, settlement_detail = _settlement_check(
        specification,
        result,
        clean_passed=clean_passed,
    )
    minimization, minimization_passed, minimization_detail = _minimization_check(
        specification,
        result,
        repository_sha256,
    )

    check_inputs: list[tuple[ReproductionIntegrityCheckKind, bool, str, Any]] = [
        (
            ReproductionIntegrityCheckKind.TARGET_IDENTITY,
            target_passed,
            target_detail,
            [item.model_dump(mode="json") for item in target_identities],
        ),
        (
            ReproductionIntegrityCheckKind.CITED_REACHABILITY,
            reachability_passed,
            reachability_detail,
            {
                "evidence": [item.model_dump(mode="json") for item in reachability],
                "errors": reachability_errors,
            },
        ),
        (
            ReproductionIntegrityCheckKind.CLEAN_REPLAY,
            clean_passed,
            clean_detail,
            [item.model_dump(mode="json") for item in result.attempt_evidence],
        ),
        (
            ReproductionIntegrityCheckKind.REPOSITORY_HASH,
            repository_passed,
            repository_detail,
            {
                "observed": repository_sha256,
                "recorded": result.repository_sha256,
            },
        ),
        (
            ReproductionIntegrityCheckKind.SETTLEMENT,
            settlement_passed,
            settlement_detail,
            settlement.model_dump(mode="json"),
        ),
        (
            ReproductionIntegrityCheckKind.MINIMIZATION,
            minimization_passed,
            minimization_detail,
            minimization.model_dump(mode="json"),
        ),
    ]
    checks = [
        ReproductionIntegrityCheck(
            check=kind,
            passed=passed,
            detail=detail,
            evidence_sha256=_canonical_sha256(evidence),
        )
        for kind, passed, detail, evidence in check_inputs
    ]
    if all(check.passed for check in checks):
        status = ReproductionIntegrityStatus.VERIFIED
    elif result.state in {*_POSITIVE_STATES, ReproductionState.NOT_REPRODUCED}:
        status = ReproductionIntegrityStatus.REJECTED
    else:
        status = ReproductionIntegrityStatus.INCONCLUSIVE
    assessment_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "status": status,
        "repository_sha256": repository_sha256,
        "targets": [item.model_dump(mode="json") for item in target_identities],
        "reachability": [item.model_dump(mode="json") for item in reachability],
        "settlement": settlement.model_dump(mode="json"),
        "minimization": minimization.model_dump(mode="json"),
        "checks": [item.model_dump(mode="json") for item in checks],
    }
    assessment_payload["integrity_sha256"] = _canonical_sha256(assessment_payload)
    assessment = ReproductionIntegrityAssessment.model_validate(assessment_payload)
    return ReproductionResult.model_validate(
        {
            **result.model_dump(mode="json"),
            "integrity": assessment.model_dump(mode="json"),
        }
    )


def _target_identities(
    specification: GeneratedFoundryTestSpec,
    result: ReproductionResult,
    targets: dict[str, str],
) -> tuple[list[ReproductionTargetIdentity], list[str]]:
    aliases = sorted(
        {
            *(call.target for call in [*specification.setup_calls, *specification.attack_calls]),
            *(
                (specification.financial_settlement.asset_target,)
                if specification.financial_settlement is not None
                and specification.financial_settlement.asset_target is not None
                else ()
            ),
        }
    )
    errors: list[str] = []
    if result.expected_chain_id is None:
        errors.append("expected chain ID is absent")
    if result.required_block_number is None:
        errors.append("required block number is absent")
    identities: list[ReproductionTargetIdentity] = []
    if errors:
        return identities, errors
    assert result.expected_chain_id is not None
    assert result.required_block_number is not None
    for alias in aliases:
        address = targets.get(alias)
        if address is None:
            errors.append(f"target alias is not configured: {alias}")
            continue
        payload = {
            "alias": alias,
            "contract_name": alias,
            "address": address.lower(),
            "chain_id": result.expected_chain_id,
            "block_number": result.required_block_number,
        }
        identities.append(
            ReproductionTargetIdentity(
                **payload,
                binding_sha256=_canonical_sha256(payload),
            )
        )
    return identities, errors


def _reachability_evidence(
    repository_root: Path,
    candidate: CandidateFinding,
    specification: GeneratedFoundryTestSpec,
    index: SoliditySymbolIndex | None,
) -> tuple[list[ReproductionReachabilityEvidence], list[str]]:
    if index is None:
        return [], ["Solidity symbol index is unavailable"]
    cited_ranges = _candidate_citations(candidate)
    evidence: list[ReproductionReachabilityEvidence] = []
    errors: list[str] = []
    for call in specification.attack_calls:
        matching = sorted(
            (
                entity
                for entity in index.entities
                if _entity_matches_call(entity, call.target, call.function_signature)
                and _entity_is_cited(entity, cited_ranges)
            ),
            key=lambda entity: entity.id,
        )
        if not matching:
            errors.append(f"{call.step_id}: no matching cited public/external function")
            continue
        entity = matching[0]
        path = repository_root / normalize_relative_path(entity.path)
        try:
            content = path.resolve(strict=True).read_text(encoding="utf-8")
            observed_hash = line_range_hash(content, entity.start_line, entity.end_line)
        except (OSError, UnicodeError, ValueError):
            errors.append(f"{call.step_id}: cited source is unavailable")
            continue
        if observed_hash != entity.source_hash:
            errors.append(f"{call.step_id}: cited source hash changed")
            continue
        evidence.append(
            ReproductionReachabilityEvidence(
                step_id=call.step_id,
                target=call.target,
                function_signature=call.function_signature,
                entity_id=entity.id,
                location=Location(
                    path=entity.path,
                    start_line=entity.start_line,
                    end_line=entity.end_line,
                    symbol=entity.name,
                    content_hash=entity.source_hash,
                ),
                provenance=entity.provenance,
            )
        )
    return evidence, errors


def _candidate_citations(candidate: CandidateFinding) -> list[tuple[str, int, int]]:
    citations = [
        (location.path, location.start_line, location.end_line) for location in candidate.locations
    ]
    for endpoint in (candidate.source, candidate.sink):
        if endpoint is not None:
            citations.append((endpoint.path, endpoint.line, endpoint.line))
    return sorted(set(citations))


def _entity_matches_call(
    entity: SolidityEntity,
    target: str,
    function_signature: str,
) -> bool:
    return (
        entity.kind is SolidityEntityKind.FUNCTION
        and entity.contract_name == target
        and entity.signature == function_signature
        and entity.visibility in {"public", "external"}
    )


def _entity_is_cited(
    entity: SolidityEntity,
    citations: list[tuple[str, int, int]],
) -> bool:
    return any(
        path == entity.path and max(start_line, entity.start_line) <= min(end_line, entity.end_line)
        for path, start_line, end_line in citations
    )


def _clean_replay_check(
    result: ReproductionResult,
    expected_generated_test_sha256: str,
    repository_sha256: str | None,
) -> tuple[bool, str]:
    attempts = result.attempt_evidence
    if len(attempts) < 2:
        return False, "clean replay requires at least two recorded fresh-workspace attempts"
    if (
        result.attempts != len(attempts)
        or not all(attempt.fresh_workspace for attempt in attempts)
        or repository_sha256 is None
        or any(attempt.repository_sha256 != repository_sha256 for attempt in attempts)
        or any(
            attempt.generated_test_sha256 != expected_generated_test_sha256 for attempt in attempts
        )
    ):
        return False, "clean replay attempt hashes or fresh-workspace evidence are inconsistent"
    states = {attempt.state for attempt in attempts}
    if len(states) != 1:
        return False, "clean replay attempts produced inconsistent outcomes"
    state = next(iter(states))
    if state is ReproductionState.REPRODUCED and result.state in _POSITIVE_STATES:
        return True, f"{len(attempts)} fresh-workspace attempts reproduced the same claim"
    if (
        state is ReproductionState.NOT_REPRODUCED
        and result.state is ReproductionState.NOT_REPRODUCED
    ):
        return True, f"{len(attempts)} fresh-workspace attempts consistently rejected the claim"
    return False, "clean replay outcome does not match the summarized reproduction state"


def _settlement_check(
    specification: GeneratedFoundryTestSpec,
    result: ReproductionResult,
    *,
    clean_passed: bool,
) -> tuple[ReproductionSettlementEvidence, bool, str]:
    assertion_hash = _canonical_sha256(
        [assertion.model_dump(mode="json") for assertion in specification.assertions]
    )
    declared_financial = specification.financial_settlement
    financial_hash = (
        _canonical_sha256(declared_financial.model_dump(mode="json"))
        if declared_financial is not None
        else None
    )
    financial_verified = (
        declared_financial is not None
        and result.financial_settlement == declared_financial
        and result.financial_settlement_verified
    )
    if clean_passed and result.state in _POSITIVE_STATES:
        settlement = ReproductionSettlementEvidence(
            status=ReproductionSettlementStatus.ASSERTIONS_SATISFIED,
            assertions_sha256=assertion_hash,
            assertion_count=len(specification.assertions),
            verified_attempts=result.successful_attempts,
            financial_settlement_sha256=financial_hash,
            financial_settlement_verified=financial_verified,
        )
        passed = result.successful_attempts == result.attempts and (
            declared_financial is None or financial_verified
        )
        return (
            settlement,
            passed,
            (
                "all declared end-state assertions and financial settlement checks "
                "completed on every clean replay"
                if declared_financial is not None and financial_verified
                else (
                    "declared financial settlement lacks complete observed replay evidence"
                    if declared_financial is not None
                    else "all declared end-state assertions completed on every clean replay"
                )
            ),
        )
    if clean_passed and result.state is ReproductionState.NOT_REPRODUCED:
        settlement = ReproductionSettlementEvidence(
            status=ReproductionSettlementStatus.CLAIM_NOT_REPRODUCED,
            assertions_sha256=assertion_hash,
            assertion_count=len(specification.assertions),
            verified_attempts=result.attempts,
            financial_settlement_sha256=financial_hash,
        )
        return settlement, True, "the declared unsafe end state was consistently not reached"
    settlement = ReproductionSettlementEvidence(
        status=ReproductionSettlementStatus.NOT_EXECUTED,
        assertions_sha256=assertion_hash,
        assertion_count=len(specification.assertions),
        verified_attempts=0,
        financial_settlement_sha256=financial_hash,
    )
    return settlement, False, "declared end-state assertions lack a consistent clean replay"


def _minimization_check(
    specification: GeneratedFoundryTestSpec,
    result: ReproductionResult,
    repository_sha256: str | None,
) -> tuple[ReproductionMinimizationEvidence, bool, str]:
    original_ids = [step.step_id for step in specification.attack_calls]
    evidence = result.minimization_evidence or ReproductionMinimizationEvidence(
        original_step_ids=original_ids,
        retained_step_ids=original_ids,
        removal_trials=[],
        strategy="not_attempted",
        proven_minimal=False,
    )
    common = (
        evidence.original_step_ids == original_ids
        and result.original_steps == len(original_ids)
        and result.minimized_steps == len(evidence.retained_step_ids)
    )
    if result.state is ReproductionState.REPRODUCED_AND_MINIMIZED:
        if not common or not evidence.proven_minimal:
            return evidence, False, "minimized state lacks matching minimality evidence"
        if evidence.strategy == "single_step_trivial":
            return evidence, True, "the one-step attacker sequence is trivially minimal"
        retained = evidence.retained_step_ids
        trials = {trial.removed_step_id: trial for trial in evidence.removal_trials}
        proven = (
            evidence.strategy == "bounded_step_deletion"
            and set(trials) == set(retained)
            and repository_sha256 is not None
            and all(
                trial.attempted_step_ids == [step_id for step_id in retained if step_id != removed]
                and trial.state is ReproductionState.NOT_REPRODUCED
                and trial.repository_sha256 == repository_sha256
                for removed, trial in trials.items()
            )
        )
        return (
            evidence,
            proven,
            (
                "every retained step survived a bounded clean deletion check"
                if proven
                else "bounded deletion evidence does not prove the retained sequence minimal"
            ),
        )
    no_minimized_claim = (
        common
        and not evidence.proven_minimal
        and evidence.strategy == "not_attempted"
        and not evidence.removal_trials
    )
    return (
        evidence,
        no_minimized_claim,
        (
            "no minimized result is claimed"
            if no_minimized_claim
            else "result step counts or non-minimization evidence are inconsistent"
        ),
    )


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
