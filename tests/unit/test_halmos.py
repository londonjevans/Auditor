from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalResultKind, FormalToolRun, FormalToolStatus
from mmaudit.solidity.engines.halmos import (
    parse_halmos_json,
    translate_halmos_corpus,
    untrusted_halmos_annotation_limitations,
)
from mmaudit.solidity.formal import FormalRunner, HalmosAdapter
from tests.unit.test_echidna import FIXTURE, MockIsolation, _inputs


def _translation(corpus, index):
    return translate_halmos_corpus(
        corpus,
        index,
        timeout_seconds=15,
        maximum_invariant_depth=4,
        loop_bound=2,
        maximum_width=256,
        maximum_path_depth=512,
        solver_timeout_seconds=10,
        solver_max_memory_mb=2_048,
    )


def _mock_solver(path: Path, *, version: str = "4.15.0") -> str:
    path.write_text(
        f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "Z3 version {version}"; exit 0; fi\n'
        "exit 7\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_halmos_translation_is_assertion_based_bounded_and_compiles(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, corpus = _inputs(root, config_factory())

    first = _translation(corpus, index)
    second = _translation(corpus, index)

    assert first == second
    assert len(first.property_map) == 1
    generated_name = next(iter(first.property_map))
    assert generated_name.startswith("invariant_")
    assert first.source_path == f"src/MMAuditHalmos_{corpus.corpus_hash[:12]}.sol"
    assert f"function {generated_name}() public view {{" in first.source
    assert "assert(leftValue >= initial_" in first.source
    assert "returns (bool)" not in first.source.split(f"function {generated_name}", 1)[1]
    plan = json.loads(first.configuration)
    assert plan["bounds"] == {
        "invariant_depth": 4,
        "loop": 2,
        "path_depth": 512,
        "solver_max_memory_mb": 2_048,
        "solver_timeout_seconds": 10,
        "timeout_seconds": 15,
        "width": 100,
    }
    assert first.seed is None
    assert any("bounded symbolic pass" in assumption for assumption in first.assumptions)

    generated = root / first.source_path
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


def test_halmos_parser_captures_only_counterexample_models() -> None:
    records = parse_halmos_json(
        json.dumps(
            {
                "exitcode": 1,
                "test_results": {
                    "src/MMAuditHalmos.sol:MMAuditHalmosProperties": [
                        {
                            "name": "invariant_safe()",
                            "exitcode": 0,
                            "num_models": 0,
                        },
                        {
                            "name": "invariant_accounting()",
                            "exitcode": 1,
                            "num_models": 1,
                            "models": [
                                {
                                    "result": "sat",
                                    "returncode": 0,
                                    "path_id": 3,
                                    "query_file": "/private/query.smt2",
                                    "model": {
                                        "is_valid": True,
                                        "model": {
                                            "amount": {
                                                "full_name": "amount_uint256",
                                                "value": 10,
                                            }
                                        },
                                    },
                                }
                            ],
                            "num_paths": [4, 3, 0],
                            "time": [1, 1, 0],
                            "num_bounded_loops": 0,
                        },
                    ]
                },
            }
        )
    )

    assert len(records) == 1
    assert records[0].property_name == "invariant_accounting"
    assert records[0].counterexample["num_models"] == 1
    assert records[0].counterexample["path_counts"] == [4, 3, 0]
    assert records[0].counterexample["models"][0]["model"]["is_valid"] is True
    assert "query_file" not in records[0].counterexample["models"][0]


def test_halmos_adapter_retains_explicit_passing_machine_result(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, _ = _inputs(root, config_factory())
    output = json.dumps(
        {
            "exitcode": 0,
            "test_results": {
                "src/MMAuditHalmos.sol:MMAuditHalmosProperties": [
                    {
                        "name": "invariant_safe()",
                        "exitcode": 0,
                        "num_models": 0,
                    }
                ]
            },
        }
    )
    adapter = HalmosAdapter()

    evidence = adapter.parse_result("", "", output, index)

    assert len(evidence) == 1
    assert evidence[0].property_id == "invariant_safe"
    assert evidence[0].result_kind is FormalResultKind.NONE
    assert adapter.validates_machine_output("", "", output)


def test_repository_halmos_option_annotations_are_explicitly_unsupported(
    tmp_path: Path,
    config_factory,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    _, index, _, _ = _inputs(root, config_factory())
    counter = root / "src/Counter.sol"
    counter.write_text(
        counter.read_text(encoding="utf-8") + "\n/// @custom:halmos --ffi\n",
        encoding="utf-8",
    )

    limitations = untrusted_halmos_annotation_limitations(root, index)

    assert limitations == [
        "src/Counter.sol: repository-provided Halmos option annotations are unsupported"
    ]


def test_mocked_halmos_run_pins_engine_and_solver_and_normalizes_result(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    translation = _translation(corpus, index)
    generated_name = next(iter(translation.property_map))
    result_payload = json.dumps(
        {
            "exitcode": 1,
            "test_results": {
                f"{translation.source_path}:MMAuditHalmosProperties": [
                    {
                        "name": f"{generated_name}()",
                        "exitcode": 1,
                        "num_models": 1,
                        "models": [
                            {
                                "result": "sat",
                                "returncode": 0,
                                "path_id": 2,
                                "model": {
                                    "is_valid": True,
                                    "model": {"choice": {"value": 0}},
                                },
                            }
                        ],
                        "num_paths": [3, 2, 0],
                        "num_bounded_loops": 0,
                    }
                ]
            },
        }
    )
    executable = tmp_path / "mock-halmos"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "halmos 0.3.3"; exit 0; fi\n'
        'test -f "mmaudit-halmos/halmos.toml" || exit 8\n'
        f'test -f "{translation.source_path}" || exit 9\n'
        'output=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--json-output" ]; then output="$2"; shift 2; continue; fi\n'
        "  shift\n"
        "done\n"
        'test -n "$output" || exit 10\n'
        f"printf '%s\\n' '{result_payload}' > \"$output\"\n"
        "exit 1\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    solver = tmp_path / "z3"
    solver_hash = _mock_solver(solver)
    monkeypatch.setenv("PATH", f"{tmp_path}:{shutil.which('forge') or ''}")
    adapter = HalmosAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            timeout_seconds=3,
            halmos_version="0.3.3",
            halmos_sha256=executable_hash,
            halmos_solver_version="4.15.0",
            halmos_solver_sha256=solver_hash,
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
    assert run.machine_output_validated
    assert run.version == "halmos 0.3.3"
    assert run.executable_sha256 == executable_hash
    assert [(dependency.name, dependency.version) for dependency in run.dependencies] == [
        ("z3", "Z3 version 4.15.0")
    ]
    assert run.dependencies[0].executable_sha256 == solver_hash
    assert run.campaign_seed is None
    assert run.configured_campaign is not None
    assert (run.configured_campaign.runs, run.configured_campaign.depth) == (100, 4)
    assert run.observed_campaign is not None
    assert run.observed_campaign.paths == 5
    assert run.observed_campaign.depth is None
    assert run.executed_property_ids == [corpus.properties[0].id]
    assert run.result_path == "halmos/result.json"
    assert run.evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert run.evidence[0].property_id == corpus.properties[0].id
    assert run.evidence[0].counterexample["models"][0]["model"]["is_valid"] is True
    assert run.evidence[0].artifact_paths == [
        f"workspace/{translation.source_path}",
        "workspace/mmaudit-halmos/plan.json",
        "workspace/mmaudit-halmos/property-map.json",
        "workspace/mmaudit-halmos/halmos.toml",
        "halmos/result.json",
    ]
    assert "--ffi" not in run.command
    assert run.command[0] == "[EXTERNAL_TOOL]"
    assert str(tmp_path) not in run.model_dump_json()


def test_halmos_solver_hash_mismatch_prevents_target_execution(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    projects, index, suite, corpus = _inputs(root, config_factory())
    executable = tmp_path / "mock-halmos"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo "halmos 0.3.3"; exit 0; fi\n'
        'printf executed > "target-executed"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    solver = tmp_path / "z3"
    _mock_solver(solver)
    monkeypatch.setenv("PATH", str(tmp_path))
    adapter = HalmosAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(
            enabled=True,
            halmos_version="0.3.3",
            halmos_sha256=executable_hash,
            halmos_solver_version="4.15.0",
            halmos_solver_sha256="0" * 64,
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
    assert "z3" in (run.failure_reason or "").lower()
    assert "sha-256" in (run.failure_reason or "").lower()
    assert not (tmp_path / "private/halmos/workspace/target-executed").exists()
    assert run.evidence == []
