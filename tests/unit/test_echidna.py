from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import (
    AnalysisState,
    ForkActor,
    ForkArgument,
    ForkArgumentKind,
    ForkCallStep,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    FoundryInvariantHarnessSpec,
    InvariantCategory,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    SolidityEntityKind,
    StatefulActionSpec,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.engines.echidna import translate_echidna_corpus
from mmaudit.solidity.formal import EchidnaAdapter, FormalRunner
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.properties import build_property_corpus

FIXTURE = Path("tests/fixtures/solidity/echidna_property")


class MockIsolation:
    name = "mocked-test-isolation"

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


def _inputs(root: Path, config) -> tuple:
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index = build_solidity_index(discovery, projects, []).index
    reset = next(
        entity
        for entity in index.entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and entity.contract_name == "Counter"
        and entity.signature == "reset()"
    )
    current = next(
        entity
        for entity in index.entities
        if entity.kind is SolidityEntityKind.FUNCTION
        and entity.contract_name == "Counter"
        and entity.signature == "current()"
    )
    invariant = InvariantSpec(
        id="inv-counter-monotonic",
        title="Counter does not fall below its seeded baseline",
        category=InvariantCategory.STATE_MACHINE,
        description="The synthetic cumulative counter remains at or above its seeded value.",
        template=InvariantTemplate.REWARD_INDEX_MONOTONIC,
        locations=[
            {
                "path": entity.path,
                "start_line": entity.start_line,
                "end_line": entity.end_line,
                "symbol": entity.name,
                "content_hash": entity.source_hash,
            }
            for entity in (reset, current)
        ],
        entity_ids=[reset.id, current.id],
        functions=["reset", "current"],
        assumptions=["Counter is a local no-argument synthetic deployment"],
        provenance=reset.provenance,
        confidence=reset.confidence,
        template_available=True,
        executable=True,
        analysis_state=AnalysisState.FALLBACK_PARSER,
        evidence_hash="c" * 64,
    )
    harness = FoundryInvariantHarnessSpec(
        invariant_id=invariant.id,
        name="CounterMonotonic",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id="SeedCounter",
                actor="attacker",
                target="Counter",
                function_signature="increment(uint256)",
                arguments=[
                    ForkArgument(kind=ForkArgumentKind.UINT256, value="10"),
                ],
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="ResetCounter",
                target="Counter",
                function_signature="reset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="CounterDoesNotDecrease",
                left=InvariantProbe(
                    target="Counter",
                    function_signature="current()",
                ),
                relation=InvariantRelation.GTE,
                compare_to_initial=True,
            )
        ],
        runs=100,
        depth=4,
        seed=11,
    )
    suite = InvariantSuite(
        invariants=[invariant],
        templates_available_count=1,
        executable_count=1,
    )
    corpus = build_property_corpus(suite, index, [harness])
    assert len(corpus.properties) == 1
    return projects, index, suite, corpus


def test_echidna_translation_is_deterministic_bounded_and_compiles(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, corpus = _inputs(root, config_factory())

    first = translate_echidna_corpus(corpus, index, timeout_seconds=9)
    second = translate_echidna_corpus(corpus, index, timeout_seconds=9)

    assert first == second
    assert len(first.property_map) == 1
    generated_name = next(iter(first.property_map))
    assert generated_name.startswith("echidna_")
    assert "new Counter()" in first.source
    assert 'abi.encodeWithSignature("increment(uint256)", 10)' in first.source
    assert 'abi.encodeWithSignature("reset()")' in first.source
    assert f"function {generated_name}()" in first.source
    assert "return leftValue >= initial_" in first.source
    assert "testLimit: 100" in first.configuration
    assert "seqLen: 4" in first.configuration
    assert "seed: 11" in first.configuration
    assert "timeout: 9" in first.configuration
    assert first.limitations == []

    generated = root / "mmaudit-echidna"
    generated.mkdir()
    (generated / "MMAuditEchidna.sol").write_text(first.source, encoding="utf-8")
    forge = shutil.which("forge")
    if forge is not None:
        result = subprocess.run(
            [
                forge,
                "build",
                "--root",
                str(root),
                "--offline",
                "--force",
                "--cache-path",
                str(tmp_path / "cache"),
                "--out",
                str(tmp_path / "out"),
                "mmaudit-echidna/MMAuditEchidna.sol",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert not (root / "cache").exists()
    assert not (root / "out").exists()


def test_mocked_echidna_run_enforces_pins_and_normalizes_replay(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    translation = translate_echidna_corpus(corpus, index, timeout_seconds=3)
    generated_name = next(iter(translation.property_map))
    executable = tmp_path / "mock-echidna"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "Echidna 2.2.7"; exit 0; fi\n'
        'test -f "mmaudit-echidna/MMAuditEchidna.sol" || exit 9\n'
        f"echo '{json.dumps({'tests': [{'name': generated_name, 'status': 'falsified', 'callseq': [{'function': 'reset()'}], 'seed': 11}]})}'\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    adapter = EchidnaAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=3,
            echidna_version="2.2.7",
            echidna_sha256=executable_hash,
        ),
        backend=MockIsolation(),
        adapters=[adapter],
    )

    runs = runner.run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "private",
    )

    assert len(runs) == 1
    run = runs[0]
    assert FormalToolRun.model_validate_json(run.model_dump_json()) == run
    assert run.status is FormalToolStatus.SUCCESS
    assert run.version == "Echidna 2.2.7"
    assert run.executable_sha256 == executable_hash
    assert run.property_corpus_hash == corpus.corpus_hash
    assert run.campaign_seed == 11
    assert run.translated_properties == 1
    assert run.translation_limitations == []
    assert run.command[0] == "[EXTERNAL_TOOL]"
    assert run.coverage["timeout_seconds"] == 3
    assert len(run.evidence) == 1
    evidence = run.evidence[0]
    assert evidence.property_id == corpus.properties[0].id
    assert evidence.result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence.locations == [
        source.location for source in corpus.properties[0].source_evidence
    ]
    assert evidence.counterexample["sequence"] == [{"function": "reset()"}]
    assert evidence.counterexample["replay"] == {
        "seed": 11,
        "runs": 100,
        "depth": 4,
        "clean_workspace_required": True,
    }
    assert Path(tmp_path / "private/echidna/workspace/mmaudit-echidna/property-map.json").exists()


def test_echidna_hash_mismatch_prevents_campaign_execution(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    executable = tmp_path / "mock-echidna"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "Echidna 2.2.7"; exit 0; fi\n'
        'printf executed > "campaign-executed"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    adapter = EchidnaAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            echidna_version="2.2.7",
            echidna_sha256="0" * 64,
        ),
        backend=MockIsolation(),
        adapters=[adapter],
    )

    run = runner.run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "private",
    )[0]

    assert run.status is FormalToolStatus.INCONCLUSIVE
    assert "SHA-256" in (run.failure_reason or "")
    assert not (tmp_path / "private/echidna/workspace/campaign-executed").exists()
    assert run.evidence == []
