from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import CertoraConfig, FormalConfig
from mmaudit.models.schemas import (
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    InvariantSuite,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.solidity.formal import CertoraAdapter, FormalRunner

_API_KEY_ENV = "MMAUDIT_TEST_CERTORA_KEY"


class PassthroughIsolation:
    name = "synthetic-configured-ci-isolation"

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


def _project() -> SolidityProjectMetadata:
    return SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )


def _index() -> SoliditySymbolIndex:
    project = _project()
    return SoliditySymbolIndex(
        projects=[project],
        entities=[
            SolidityEntity(
                id="contract:Vault",
                kind=SolidityEntityKind.CONTRACT,
                name="Vault",
                contract_name="Vault",
                path="src/Vault.sol",
                start_line=2,
                end_line=5,
                byte_start=0,
                byte_end=100,
                source_hash="a" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic_certora_contract",
            ),
            SolidityEntity(
                id="function:Vault:balanceNonNegative",
                kind=SolidityEntityKind.FUNCTION,
                name="balanceNonNegative",
                contract_name="Vault",
                path="src/Vault.sol",
                start_line=4,
                end_line=4,
                byte_start=30,
                byte_end=80,
                source_hash="b" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic_certora_rule_location",
                visibility="public",
            ),
        ],
        ast_sources=["src/Vault.sol"],
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    (root / "src").mkdir(parents=True)
    (root / "spec").mkdir()
    (root / "src" / "Vault.sol").write_text(
        "pragma solidity 0.8.30;\n"
        "contract Vault {\n"
        "    uint256 public balance;\n"
        "    function balanceNonNegative() external view returns (bool) {\n"
        "        return balance <= type(uint256).max;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "spec" / "Vault.spec").write_text(
        "rule balanceNonNegative { assert true; }\n",
        encoding="utf-8",
    )
    return root


def _fake_certora(
    tmp_path: Path,
    *,
    result: dict,
) -> tuple[Path, Path]:
    executable = tmp_path / "certoraRun"
    execution_marker = tmp_path / "certora-executed"
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        '  echo "certoraRun 7.28.0"\n'
        "  exit 0\n"
        "fi\n"
        f": > '{execution_marker}'\n"
        f'printf "%s\\n" "${{{_API_KEY_ENV}}}"\n'
        'output=""\n'
        'while [ "$#" -gt 0 ]; do\n'
        '  if [ "$1" = "--json_output" ]; then\n'
        "    shift\n"
        '    output="$1"\n'
        "    break\n"
        "  fi\n"
        "  shift\n"
        "done\n"
        'test -n "$output"\n'
        f"printf '%s\\n' '{serialized}' > \"$output\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable, execution_marker


def _config(executable: Path) -> FormalConfig:
    return FormalConfig(
        enabled=True,
        run_smtchecker=False,
        run_mythril=False,
        run_echidna=False,
        run_medusa=False,
        run_halmos=False,
        run_kontrol=False,
        certora=CertoraConfig(
            enabled=True,
            cli_version="7.28.0",
            cli_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            source="src/Vault.sol",
            contract="Vault",
            specification="spec/Vault.spec",
            rule="balanceNonNegative",
            assumptions=["Vault state is initialized before rule evaluation"],
            vacuity_check="basic",
            api_key_env_var=_API_KEY_ENV,
        ),
    )


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: dict,
    api_key: str | None,
) -> tuple[FormalToolRun, Path, Path]:
    repository = _repository(tmp_path)
    executable, marker = _fake_certora(tmp_path, result=result)
    adapter = CertoraAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    if api_key is None:
        monkeypatch.delenv(_API_KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(_API_KEY_ENV, api_key)
    private_dir = tmp_path / "private"
    runs = FormalRunner(
        _config(executable),
        backend=PassthroughIsolation(),
        adapters=[adapter],
    ).run(
        repository_root=repository,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=private_dir,
    )
    assert len(runs) == 1
    return runs[0], marker, private_dir


def test_certora_configuration_requires_explicit_safe_operator_fields() -> None:
    with pytest.raises(ValidationError, match="requires CLI trust pins"):
        CertoraConfig(enabled=True)
    with pytest.raises(ValidationError):
        CertoraConfig(
            enabled=False,
            source="../Vault.sol",
        )
    with pytest.raises(ValidationError):
        CertoraConfig.model_validate(
            {
                "enabled": False,
                "api_key": "must-not-be-configured",
            }
        )
    with pytest.raises(ValidationError, match="unique, and sorted"):
        CertoraConfig(
            assumptions=["second", "first"],
        )


def test_configured_certora_proof_preserves_artifacts_and_redacts_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-certora-key-canary"
    run, marker, private_dir = _run(
        tmp_path,
        monkeypatch,
        api_key=canary,
        result={
            "rules": [
                {
                    "rule": "balanceNonNegative",
                    "status": "verified",
                    "vacuity": {"status": "non_vacuous"},
                    "assumptions": ["Rule state is reachable"],
                    "path": "src/Vault.sol",
                    "line": 4,
                }
            ]
        },
    )

    assert marker.is_file()
    assert run.status is FormalToolStatus.SUCCESS
    assert run.version == "certoraRun 7.28.0"
    assert run.executable_sha256
    assert run.command == [
        "[EXTERNAL_TOOL]",
        "src/Vault.sol",
        "--verify",
        "Vault:spec/Vault.spec",
        "--rule",
        "balanceNonNegative",
        "--rule_sanity",
        "basic",
        "--wait_for_results",
        "all",
        "--json_output",
        "[PRIVATE]/result.json",
    ]
    assert len(run.evidence) == 1
    evidence = run.evidence[0]
    assert evidence.result_kind is FormalResultKind.PROOF
    assert evidence.status is FormalToolStatus.SUCCESS
    assert evidence.locations[0].path == "src/Vault.sol"
    assert evidence.locations[0].content_hash == "b" * 64
    assert evidence.assumptions == [
        "Rule state is reachable",
        "Vault state is initialized before rule evaluation",
    ]
    assert run.coverage["vacuity_checks"] == 1
    assert run.specification_artifacts == [
        "workspace/mmaudit-certora/specification-plan.json",
        "workspace/spec/Vault.spec",
    ]
    assert run.assumption_artifacts == ["workspace/mmaudit-certora/assumptions.json"]
    assert run.vacuity_artifacts == ["workspace/mmaudit-certora/vacuity-plan.json"]
    serialized = run.model_dump_json()
    assert canary not in serialized
    stdout = (private_dir / "certora" / "stdout.txt").read_text(encoding="utf-8")
    assert canary not in stdout
    assert "[REDACTED_FORMAL_SECRET]" in stdout
    for relative in (
        "workspace/mmaudit-certora/specification-plan.json",
        "workspace/mmaudit-certora/assumptions.json",
        "workspace/mmaudit-certora/vacuity-plan.json",
    ):
        artifact = private_dir / "certora" / relative
        assert artifact.is_file()
        assert canary not in artifact.read_text(encoding="utf-8")
    assert FormalToolRun.model_validate_json(serialized) == run


def test_certora_missing_key_is_inconclusive_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, marker, _ = _run(
        tmp_path,
        monkeypatch,
        api_key=None,
        result={"rules": []},
    )

    assert not marker.exists()
    assert run.status is FormalToolStatus.INCONCLUSIVE
    assert run.evidence == []
    assert "environment variable is unavailable" in (run.failure_reason or "")
    assert run.specification_artifacts
    assert run.assumption_artifacts
    assert run.vacuity_artifacts


def test_configured_certora_unavailable_status_is_honest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    executable, _ = _fake_certora(tmp_path, result={"rules": []})
    adapter = CertoraAdapter()
    adapter.available = lambda repository_root: None  # type: ignore[method-assign]
    monkeypatch.delenv(_API_KEY_ENV, raising=False)

    runs = FormalRunner(
        _config(executable),
        backend=PassthroughIsolation(),
        adapters=[adapter],
    ).run(
        repository_root=repository,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=tmp_path / "private",
    )

    assert len(runs) == 1
    assert runs[0].status is FormalToolStatus.UNAVAILABLE
    assert runs[0].evidence == []
    assert "unavailable outside" in (runs[0].failure_reason or "")
    assert not (tmp_path / "private").exists()


def test_certora_vacuous_success_remains_inconclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, marker, _ = _run(
        tmp_path,
        monkeypatch,
        api_key="synthetic-certora-key",
        result={
            "rules": [
                {
                    "rule": "balanceNonNegative",
                    "status": "verified",
                    "vacuity": {"status": "vacuous"},
                }
            ]
        },
    )

    assert marker.is_file()
    assert run.status is FormalToolStatus.INCONCLUSIVE
    assert "non-vacuous" in (run.failure_reason or "")
    assert len(run.evidence) == 1
    assert run.evidence[0].status is FormalToolStatus.INCONCLUSIVE
    assert run.evidence[0].result_kind is FormalResultKind.UNKNOWN
    assert run.evidence[0].counterexample["vacuity_status"] == "vacuous"


def test_certora_counterexample_is_normalized_without_vacuity_proof() -> None:
    evidence = CertoraAdapter().parse_result(
        "",
        "",
        json.dumps(
            {
                "rules": [
                    {
                        "rule": "balanceNonNegative",
                        "status": "violated",
                        "counterexample": {"balance": -1},
                        "path": "src/Vault.sol",
                        "line": 4,
                    }
                ]
            }
        ),
        _index(),
    )

    assert len(evidence) == 1
    assert evidence[0].status is FormalToolStatus.SUCCESS
    assert evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence[0].counterexample == {"balance": -1}
