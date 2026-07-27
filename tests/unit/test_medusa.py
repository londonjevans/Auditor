from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import (
    DynamicEngineComparison,
    DynamicPropertyOutcome,
    FormalToolRun,
    FormalToolStatus,
)
from mmaudit.solidity.engines.medusa import translate_medusa_corpus
from mmaudit.solidity.formal import (
    FormalRunner,
    MedusaAdapter,
    compare_dynamic_engine_outcomes,
)
from tests.unit.test_echidna import FIXTURE, MockIsolation, _inputs


def test_medusa_translation_reuses_shared_property_and_compiles(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, corpus = _inputs(root, config_factory())

    first = translate_medusa_corpus(corpus, index, timeout_seconds=12)
    second = translate_medusa_corpus(corpus, index, timeout_seconds=12)

    assert first == second
    assert len(first.property_map) == 1
    assert "contract MMAuditMedusaProperties" in first.source
    configuration = json.loads(first.configuration)
    assert configuration["fuzzing"]["seed"] == 11
    assert configuration["fuzzing"]["testLimit"] == 100
    assert configuration["fuzzing"]["callSequenceLength"] == 4
    assert configuration["fuzzing"]["timeout"] == 12
    assert configuration["fuzzing"]["workers"] == 1
    assert configuration["fuzzing"]["targetContracts"] == ["MMAuditMedusaProperties"]

    generated = root / "mmaudit-medusa"
    generated.mkdir()
    (generated / "MMAuditMedusa.sol").write_text(first.source, encoding="utf-8")
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
                "mmaudit-medusa/MMAuditMedusa.sol",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert not (root / "cache").exists()
    assert not (root / "out").exists()


def test_mocked_medusa_run_enforces_pins_and_normalizes_independent_outcome(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    translation = translate_medusa_corpus(corpus, index, timeout_seconds=3)
    generated_name = next(iter(translation.property_map))
    executable = tmp_path / "mock-medusa"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "medusa version 1.3.1"; exit 0; fi\n'
        'test -f "mmaudit-medusa/MMAuditMedusa.sol" || exit 9\n'
        f"echo '{json.dumps({'campaign': {'testCases': [{'property': generated_name, 'result': 'property_test_failed', 'sequence': [{'function': 'reset()'}], 'seed': 11}]}})}'\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    adapter = MedusaAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=3,
            medusa_version="1.3.1",
            medusa_sha256=executable_hash,
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

    assert FormalToolRun.model_validate_json(run.model_dump_json()) == run
    assert run.status is FormalToolStatus.SUCCESS
    assert run.version == "medusa version 1.3.1"
    assert run.executable_sha256 == executable_hash
    assert run.configured_campaign is not None
    assert (run.configured_campaign.runs, run.configured_campaign.depth) == (100, 4)
    assert run.observed_campaign is None
    assert run.executed_property_ids == [corpus.properties[0].id]
    assert run.evidence[0].property_id == corpus.properties[0].id
    assert run.evidence[0].counterexample["sequence"] == [{"function": "reset()"}]
    assert run.evidence[0].artifact_paths == [
        "workspace/mmaudit-medusa/MMAuditMedusa.sol",
        "workspace/mmaudit-medusa/medusa.json",
        "workspace/mmaudit-medusa/property-map.json",
    ]

    echidna_no_counterexample = FormalToolRun(
        tool="echidna",
        status=FormalToolStatus.SUCCESS,
        property_corpus_hash=corpus.corpus_hash,
        campaign_seed=11,
        translated_properties=1,
        executed_property_ids=[corpus.properties[0].id],
    )
    comparison = compare_dynamic_engine_outcomes([echidna_no_counterexample, run])
    assert comparison == [
        DynamicEngineComparison(
            property_id=corpus.properties[0].id,
            outcomes={
                "echidna": DynamicPropertyOutcome.NO_COUNTEREXAMPLE,
                "medusa": DynamicPropertyOutcome.COUNTEREXAMPLE,
            },
            disagreement=True,
        )
    ]
    assert (
        DynamicEngineComparison.model_validate_json(comparison[0].model_dump_json())
        == comparison[0]
    )


def test_medusa_version_mismatch_prevents_campaign_execution(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    executable = tmp_path / "mock-medusa"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "medusa version 1.3.0"; exit 0; fi\n'
        'printf executed > "campaign-executed"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    adapter = MedusaAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            medusa_version="1.3.1",
            medusa_sha256=executable_hash,
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
    assert "version" in (run.failure_reason or "").lower()
    assert not (tmp_path / "private/medusa/workspace/campaign-executed").exists()
    assert run.evidence == []
