from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalResultKind, FormalToolRun, FormalToolStatus
from mmaudit.solidity.engines.kontrol import (
    parse_kontrol_output,
    read_kontrol_plan,
    translate_kontrol_corpus,
)
from mmaudit.solidity.formal import FormalRunner, KontrolAdapter
from tests.unit.test_echidna import FIXTURE, MockIsolation, _inputs


def test_kontrol_translation_is_bounded_assertion_based_and_compiles(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, corpus = _inputs(root, config_factory())

    first = translate_kontrol_corpus(
        corpus,
        index,
        maximum_depth=3,
        maximum_iterations=20,
    )
    second = translate_kontrol_corpus(
        corpus,
        index,
        maximum_depth=3,
        maximum_iterations=20,
    )

    assert first == second
    assert len(first.property_map) == 1
    generated_name = next(iter(first.property_map))
    assert generated_name.startswith("testKontrol_")
    assert first.source_path == (
        f"test/mmaudit-kontrol/MMAuditKontrol_{corpus.corpus_hash[:12]}.t.sol"
    )
    assert f"function {generated_name}() public view {{" in first.source
    assert "assert(leftValue >= initial_" in first.source
    assert "returns (bool)" not in first.source.split(f"function {generated_name}", 1)[1]
    plan = json.loads(first.configuration)
    assert plan["contract"] == "MMAuditKontrolProperties"
    assert plan["function_pattern"] == "testKontrol_.*"
    assert plan["bounds"] == {
        "max_depth": 3,
        "max_iterations": 20,
        "workers": 1,
    }
    assert first.seed is None
    assert first.runs == 20
    assert first.depth == 3
    assert any("bounded Kontrol proof" in assumption for assumption in first.assumptions)

    generated = root / first.source_path
    generated.parent.mkdir(parents=True)
    generated.write_text(first.source, encoding="utf-8")
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
                first.source_path,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    assert not (root / "cache").exists()
    assert not (root / "out").exists()


def test_kontrol_parser_normalizes_only_failed_proofs() -> None:
    property_name = "testKontrol_" + ("a" * 24)
    records = parse_kontrol_output(
        json.dumps(
            {
                "proofs": [
                    {
                        "test": property_name,
                        "status": "passed",
                    },
                    {
                        "test": property_name,
                        "status": "failed",
                        "counterexample": {
                            "model": {"amount": 7},
                            "query_file": "/private/query.k",
                        },
                        "depth": 3,
                        "nodes": 12,
                    },
                ]
            }
        )
    )

    assert len(records) == 1
    assert records[0].property_name == property_name
    assert records[0].counterexample["model"] == {"amount": 7}
    assert "query_file" not in records[0].counterexample
    assert records[0].counterexample["depth"] == 3
    assert records[0].counterexample["nodes"] == 12


def test_mocked_kontrol_run_pins_command_and_preserves_counterexample_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    translation = translate_kontrol_corpus(
        corpus,
        index,
        maximum_depth=3,
        maximum_iterations=5,
    )
    generated_name = next(iter(translation.property_map))
    result_payload = json.dumps(
        {
            "proofs": [
                {
                    "test": generated_name,
                    "status": "failed",
                    "counterexample": {"model": {"choice": 0}},
                    "depth": 3,
                    "iterations": 5,
                }
            ]
        },
        sort_keys=True,
    )
    executable = tmp_path / "mock-kontrol"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "Kontrol version 1.0.0"; exit 0; fi\n'
        f'test -f "{translation.source_path}" || exit 8\n'
        'test -f "mmaudit-kontrol/plan.json" || exit 9\n'
        f"printf '%s\\n' '{result_payload}'\n"
        "exit 1\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    adapter = KontrolAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    run = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=3,
            kontrol_version="1.0.0",
            kontrol_sha256=executable_sha256,
            kontrol_max_depth=3,
            kontrol_max_iterations=5,
        ),
        backend=MockIsolation(),
        adapters=[adapter],
    ).run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "private",
    )[0]

    assert FormalToolRun.model_validate_json(run.model_dump_json()) == run
    assert run.status is FormalToolStatus.SUCCESS
    assert run.machine_output_validated
    assert run.version == "Kontrol version 1.0.0"
    assert run.executable_sha256 == executable_sha256
    assert run.property_corpus_hash == corpus.corpus_hash
    assert run.campaign_seed is None
    assert run.configured_campaign is not None
    assert (run.configured_campaign.runs, run.configured_campaign.depth) == (5, 3)
    assert run.observed_campaign is not None
    assert run.observed_campaign.depth == 3
    assert run.observed_campaign.iterations == 5
    assert run.executed_property_ids == [corpus.properties[0].id]
    assert run.assumptions == translation.assumptions
    assert run.command == [
        "[EXTERNAL_TOOL]",
        "prove",
        "--project-root",
        "[WORKSPACE]",
        "--match-test",
        "MMAuditKontrolProperties.testKontrol_.*",
        "--max-depth",
        "3",
        "--max-iterations",
        "5",
        "--workers",
        "1",
        "--failure-information",
        "--counterexample-information",
    ]
    assert len(run.evidence) == 1
    evidence = run.evidence[0]
    assert evidence.result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence.property_id == corpus.properties[0].id
    assert evidence.counterexample["model"] == {"choice": 0}
    assert evidence.artifact_paths == [
        f"workspace/{translation.source_path}",
        "workspace/mmaudit-kontrol/plan.json",
        "workspace/mmaudit-kontrol/property-map.json",
        "kontrol/stdout.txt",
    ]
    assert str(tmp_path) not in run.model_dump_json()


def test_kontrol_adapter_normalizes_strict_passing_proof(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, corpus = _inputs(root, config_factory())
    translation = translate_kontrol_corpus(
        corpus,
        index,
        maximum_depth=3,
        maximum_iterations=5,
    )
    generated_name = next(iter(translation.property_map))
    output = json.dumps({"proofs": [{"test": generated_name, "status": "proved"}]})
    adapter = KontrolAdapter()

    evidence = adapter.parse_result(output, "", "", index)

    assert len(evidence) == 1
    assert evidence[0].property_id == generated_name
    assert evidence[0].result_kind is FormalResultKind.PROOF
    assert adapter.validates_machine_output(output, "", "")


def test_kontrol_hash_mismatch_prevents_proof_execution(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    executable = tmp_path / "mock-kontrol"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "Kontrol version 1.0.0"; exit 0; fi\n'
        'printf executed > "proof-executed"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    adapter = KontrolAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    run = FormalRunner(
        FormalConfig(
            enabled=True,
            kontrol_version="1.0.0",
            kontrol_sha256="0" * 64,
        ),
        backend=MockIsolation(),
        adapters=[adapter],
    ).run(
        repository_root=root,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=tmp_path / "private",
    )[0]

    assert run.status is FormalToolStatus.INCONCLUSIVE
    assert "sha-256" in (run.failure_reason or "").lower()
    assert run.evidence == []
    assert not (tmp_path / "private/kontrol/workspace/proof-executed").exists()


def test_kontrol_plan_rejects_unbounded_or_untrusted_selectors(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "contract": "RepositorySelectedContract",
                "function_pattern": ".*",
                "bounds": {
                    "max_depth": 100_001,
                    "max_iterations": 1,
                    "workers": 2,
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid"):
        read_kontrol_plan(plan)
