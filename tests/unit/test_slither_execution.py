from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig, ModelRoleConfig, ModelsConfig, SmartContractsConfig
from mmaudit.models.schemas import ScannerStatus
from mmaudit.scanners.runner import configured_scanner_adapters
from mmaudit.scanners.slither import SlitherScanner


class _PassthroughIsolation:
    name = "test-isolation"

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


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def test_slither_empty_nonzero_exit_has_typed_private_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir()
    slither = trusted_bin / "slither"
    _write_executable(
        slither,
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                'if "--version" in sys.argv:',
                '    print("slither 0.11.6")',
                "    raise SystemExit(0)",
                "raise SystemExit(1)",
                "",
            )
        ),
    )
    monkeypatch.setenv("PATH", str(trusted_bin))
    private = tmp_path / "private" / "slither"

    run = SlitherScanner().run(
        target,
        private,
        2,
        backend=_PassthroughIsolation(),
    )

    assert run.status is ScannerStatus.SILENT_FAILURE
    assert run.error == (
        "scanner exited nonzero without machine output or diagnostics; "
        "inspect the named private stderr artifact"
    )
    assert run.process_exit_code == 1
    assert run.raw_output_bytes == 0
    assert run.private_stderr_path == "slither/slither.stderr.txt"
    assert run.private_stderr_sha256 == hashlib.sha256(b"").hexdigest()
    assert run.private_stderr_bytes == 0
    assert (tmp_path / "private" / run.private_stderr_path).read_bytes() == b""
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()


def test_slither_stages_pinned_compiler_and_private_aggregate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    compiler = tmp_path / "trusted-solc"
    _write_executable(compiler, "#!/bin/sh\nexit 0\n")
    compiler_sha256 = hashlib.sha256(compiler.read_bytes()).hexdigest()
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir()
    slither = trusted_bin / "slither"
    _write_executable(
        slither,
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json",
                "import pathlib",
                "import sys",
                'if "--version" in sys.argv:',
                '    print("slither 0.11.6")',
                "    raise SystemExit(0)",
                "entrypoint = pathlib.Path(sys.argv[1])",
                "compiler = pathlib.Path(sys.argv[sys.argv.index('--solc') + 1])",
                "if pathlib.Path.cwd() != entrypoint.resolve().parent or not compiler.is_file():",
                "    raise SystemExit(9)",
                "print(json.dumps({",
                "    'success': True,",
                "    'error': None,",
                "    'results': {'detectors': [{",
                "        'check': 'synthetic-slither-check',",
                "        'impact': 'Low',",
                "        'confidence': 'High',",
                "        'description': 'Synthetic local analyzer evidence.',",
                "        'elements': [{",
                "            'type': 'function',",
                "            'name': 'Vault',",
                "            'source_mapping': {",
                "                'filename_relative': '../workspace/Vault.sol',",
                "                'lines': [1],",
                "            },",
                "        }],",
                "    }]},",
                "}))",
                "",
            )
        ),
    )
    monkeypatch.setenv("PATH", str(trusted_bin))
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(compiler))
    config = SmartContractsConfig(
        solc_version="0.8.30",
        solc_sha256=compiler_sha256,
    )
    private = tmp_path / "private" / "slither"

    run = SlitherScanner(config).run(
        target,
        private,
        2,
        backend=_PassthroughIsolation(),
    )

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.machine_output_validated
    assert run.raw_output_bytes > 0
    assert len(run.findings) == 1
    assert run.findings[0].locations[0].path == "Vault.sol"
    staged_compiler = Path(run.command[run.command.index("--solc") + 1])
    staged_compiler.relative_to(private.resolve(strict=True))
    assert staged_compiler.read_bytes() == compiler.read_bytes()
    assert staged_compiler.stat().st_mode & 0o777 == 0o500
    assert str(compiler) not in run.command
    entrypoint = private / "analysis" / "slither-entrypoint.sol"
    assert entrypoint.read_text(encoding="utf-8") == (
        '// SPDX-License-Identifier: UNLICENSED\nimport "workspace/Vault.sol";\n'
    )
    assert not (target / "slither-entrypoint.sol").exists()
    assert run.private_stderr_path == "slither/slither.stderr.txt"
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()


def test_configured_slither_receives_production_compiler_policy() -> None:
    role = ModelRoleConfig(primary="synthetic/model")
    config = AuditConfig(
        models=ModelsConfig(
            threat_model=role,
            source_audit=role,
            business_logic=role,
            configuration=role,
            verifier=role,
            judge=role,
        ),
        smart_contracts=SmartContractsConfig(
            solc_version="0.8.30",
            solc_sha256="a" * 64,
        ),
    )

    scanner = configured_scanner_adapters(config)["slither"]

    assert isinstance(scanner, SlitherScanner)
    assert scanner.smart_contracts is config.smart_contracts
