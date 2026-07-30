from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mmaudit.models.schemas import (
    AnalysisState,
    CandidateOriginKind,
    ExecutionEvidenceKind,
    ForkActor,
    FoundryInvariantHarnessSpec,
    InvariantCampaignCoverage,
    InvariantCategory,
    InvariantExecutionAttemptEvidence,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    Location,
    PropertyCorpus,
    Severity,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProvenance,
    SoliditySymbolIndex,
    StatefulActionSpec,
)
from mmaudit.orchestration.execution_candidates import (
    ExecutionCandidateBuildResult,
    build_invariant_execution_candidates,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.solidity.properties import build_property_corpus


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sealed_execution(
    *,
    invariant: InvariantSpec,
    harness: FoundryInvariantHarnessSpec,
) -> InvariantExecutionResult:
    source_sha256 = _sha256("generated invariant source")
    attempts = [
        InvariantExecutionAttemptEvidence(
            attempt=attempt,
            status=InvariantExecutionStatus.COUNTEREXAMPLE,
            source_sha256=source_sha256,
            fresh_workspace=True,
            stdout_sha256=_sha256(f"stdout-{attempt}"),
            stderr_sha256=_sha256(f"stderr-{attempt}"),
            stdout_path=f"private/invariants/attempt-{attempt}/stdout.txt",
            stderr_path=f"private/invariants/attempt-{attempt}/stderr.txt",
            process_exit_code=1,
            machine_output_validated=True,
            campaign_runs=harness.runs,
            campaign_calls=harness.runs * harness.depth,
        )
        for attempt in (1, 2)
    ]
    draft = InvariantExecutionResult(
        invariant_id=invariant.id,
        harness_name=harness.name,
        harness_spec_sha256=harness.specification_sha256(),
        status=InvariantExecutionStatus.COUNTEREXAMPLE,
        execution_evidence=ExecutionEvidenceKind.REAL,
        executable_sha256=_sha256("forge"),
        source_sha256=source_sha256,
        compiler_version="solc 0.8.30",
        compiler_sha256=_sha256("solc"),
        command=["forge", "test", "--offline", "--match-test", "invariant_Accounting"],
        runs=harness.runs,
        depth=harness.depth,
        seed=harness.seed,
        attempts=2,
        successful_attempts=2,
        replay_confirmed=True,
        attempt_evidence=attempts,
        campaign_coverage=InvariantCampaignCoverage(
            declared_action_functions=["deposit()"],
            observed_action_functions=["deposit()"],
            declared_state_properties=["AccountingHolds"],
            observed_state_properties=["AccountingHolds"],
            sequence_depth_bound=harness.depth,
            observed_sequence_lengths=[1],
            attempts_consistent=True,
            observed_campaign_runs=harness.runs,
            observed_campaign_calls=harness.runs * harness.depth,
        ),
        counterexample_summary="The bounded accounting property did not hold.",
        stdout_path="private/invariants/stdout.txt",
        stderr_path="private/invariants/stderr.txt",
        isolation_backend="synthetic-rootless-isolation",
        isolation_attestation_sha256=_sha256("isolation"),
    )
    return InvariantExecutionResult.model_validate(
        {
            **draft.model_dump(mode="python"),
            "execution_observation_sha256": draft.expected_execution_observation_sha256(),
        }
    )


def _reseal_execution(
    result: InvariantExecutionResult,
    **updates: object,
) -> InvariantExecutionResult:
    payload = result.model_dump(mode="python")
    payload.update(updates)
    payload["execution_observation_sha256"] = None
    draft = InvariantExecutionResult.model_validate(payload)
    return InvariantExecutionResult.model_validate(
        {
            **draft.model_dump(mode="python"),
            "execution_observation_sha256": draft.expected_execution_observation_sha256(),
        }
    )


def _inputs(
    tmp_path: Path,
) -> tuple[
    Path,
    InvariantSuite,
    FoundryInvariantHarnessSpec,
    PropertyCorpus,
    InvariantExecutionResult,
]:
    repository = tmp_path / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_text = (
        "pragma solidity 0.8.30;\n"
        "contract Vault {\n"
        "    uint256 public accountedAssets;\n"
        "    function deposit() external { accountedAssets += 1; }\n"
        "}\n"
    )
    source.write_text(source_text, encoding="utf-8")
    source_line = source_text.splitlines(keepends=True)[3]
    location = Location(
        path="src/Vault.sol",
        start_line=4,
        end_line=4,
        symbol="deposit",
        content_hash=_sha256(source_line),
    )
    entity = SolidityEntity(
        id="function:Vault:deposit",
        kind=SolidityEntityKind.FUNCTION,
        name="deposit",
        contract_name="Vault",
        path=location.path,
        start_line=location.start_line,
        end_line=location.end_line,
        byte_start=72,
        byte_end=130,
        source_hash=location.content_hash,
        provenance=SolidityProvenance.COMPILER,
        confidence=1,
        transformation="compiler_ast_entity",
        visibility="external",
        signature="deposit()",
    )
    invariant = InvariantSpec(
        id="inv-accounting",
        title="Observed assets cover internal accounting",
        category=InvariantCategory.ACCOUNTING,
        description="Observed assets must cover the tracked accounting total.",
        locations=[location],
        entity_ids=[entity.id],
        state_variables=["accountedAssets"],
        functions=["deposit"],
        assumptions=["Synthetic local deployment uses the typed Vault binding"],
        provenance=SolidityProvenance.HEURISTIC,
        confidence=0.9,
        template_available=True,
        executable=True,
        analysis_state=AnalysisState.DETERMINISTIC,
        evidence_hash=_sha256("invariant evidence"),
    )
    suite = InvariantSuite(
        invariants=[invariant],
        templates_available_count=1,
        executable_count=1,
    )
    harness = FoundryInvariantHarnessSpec(
        invariant_id=invariant.id,
        name="ObservedAssetAccounting",
        actors=[
            ForkActor(
                name="alice",
                address="0x1000000000000000000000000000000000000001",
                initial_native_balance_wei=10**18,
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="Deposit",
                target="Vault",
                function_signature="deposit()",
                actor_names=["alice"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="AccountingHolds",
                left=InvariantProbe(
                    target="Vault",
                    function_signature="accountedAssets()",
                ),
                relation=InvariantRelation.GTE,
                expected_uint=1,
            )
        ],
        runs=16,
        depth=4,
        seed=7,
        assumptions=["Campaign starts from a clean synthetic deployment"],
    )
    index = SoliditySymbolIndex(
        projects=[],
        entities=[entity],
        ast_sources=[location.path],
    )
    corpus = build_property_corpus(suite, index, [harness])
    assert len(corpus.properties) == 1
    return (
        repository,
        suite,
        harness,
        corpus,
        _sealed_execution(
            invariant=invariant,
            harness=harness,
        ),
    )


def _build(
    repository: Path,
    suite: InvariantSuite,
    harness: FoundryInvariantHarnessSpec,
    corpus: PropertyCorpus,
    execution: InvariantExecutionResult,
) -> ExecutionCandidateBuildResult:
    return build_invariant_execution_candidates(
        repository_root=repository,
        invariant_suite=suite,
        harnesses=[harness],
        property_corpus=corpus,
        executions=[execution],
    )


def test_real_replayed_counterexample_originates_non_model_candidate(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)

    result = _build(repository, suite, harness, corpus, execution)

    assert result.rejected_counterexample_count == 0
    assert result.limitations == ()
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION
    assert candidate.severity is Severity.INFORMATIONAL
    assert candidate.role is None
    assert candidate.model_family is None
    assert candidate.model_votes == []
    assert candidate.execution_provenance is not None
    provenance = candidate.execution_provenance
    assert candidate.candidate_id == f"exec-{provenance.provenance_sha256[:24]}"
    assert provenance.execution_result_sha256 == canonical_sha256(execution.model_dump(mode="json"))
    assert provenance.execution_observation_sha256 == execution.execution_observation_sha256
    assert provenance.property_corpus_sha256 == corpus.corpus_hash
    assert provenance.property_ids == (corpus.properties[0].id,)
    assert provenance.property_hashes == (corpus.properties[0].property_hash,)
    assert list(provenance.source_locations) == suite.invariants[0].locations
    assert candidate.locations == list(provenance.source_locations)
    assert len(candidate.evidence) == 1
    assert candidate.evidence[0].type == "execution"
    assert candidate.evidence[0].fingerprint == provenance.provenance_sha256


def test_passing_safe_control_does_not_originate_or_count_as_rejected(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    passed_attempts = [
        attempt.model_copy(
            update={
                "status": InvariantExecutionStatus.PASSED,
                "process_exit_code": 0,
            }
        )
        for attempt in execution.attempt_evidence
    ]
    safe = _reseal_execution(
        execution,
        status=InvariantExecutionStatus.PASSED,
        attempt_evidence=passed_attempts,
    )

    result = _build(repository, suite, harness, corpus, safe)

    assert result.candidates == ()
    assert result.rejected_counterexample_count == 0
    assert result.limitations == ()


@pytest.mark.parametrize("invalid_kind", ["mock", "unreplayed", "observation_hash"])
def test_unqualified_counterexample_is_rejected_with_bounded_limitation(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    if invalid_kind == "mock":
        execution = _reseal_execution(
            execution,
            execution_evidence=ExecutionEvidenceKind.MOCK,
        )
    elif invalid_kind == "unreplayed":
        execution = _reseal_execution(execution, replay_confirmed=False)
    else:
        execution = execution.model_copy(update={"execution_observation_sha256": "f" * 64})

    result = _build(repository, suite, harness, corpus, execution)

    assert result.candidates == ()
    assert result.rejected_counterexample_count == 1
    assert len(result.limitations) == 1
    assert len(result.limitations[0]) < 200
    assert "not originated" in result.limitations[0]


def test_harness_identity_tampering_prevents_candidate_origin(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    changed_harness = harness.model_copy(update={"seed": harness.seed + 1})

    result = _build(repository, suite, changed_harness, corpus, execution)

    assert result.candidates == ()
    assert result.rejected_counterexample_count == 1
    assert "exact typed harness" in result.limitations[0]


def test_empty_or_tampered_property_join_prevents_candidate_origin(tmp_path: Path) -> None:
    repository, suite, harness, _corpus, execution = _inputs(tmp_path)
    empty_corpus = PropertyCorpus(
        properties=[],
        limitations=[],
        corpus_hash=canonical_sha256(
            {
                "schema_version": "1.0",
                "property_hashes": [],
                "limitations": [],
            }
        ),
    )

    result = _build(repository, suite, harness, empty_corpus, execution)

    assert result.candidates == ()
    assert result.rejected_counterexample_count == 1
    assert "exact nonempty harness property set" in result.limitations[0]


def test_current_source_tampering_prevents_candidate_origin(tmp_path: Path) -> None:
    repository, suite, harness, corpus, execution = _inputs(tmp_path)
    source = repository / "src" / "Vault.sol"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            "accountedAssets += 1",
            "accountedAssets += 2",
        ),
        encoding="utf-8",
    )

    result = _build(repository, suite, harness, corpus, execution)

    assert result.candidates == ()
    assert result.rejected_counterexample_count == 1
    assert "current-source validation" in result.limitations[0]
