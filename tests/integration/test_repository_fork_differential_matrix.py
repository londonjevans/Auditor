from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkSuiteConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    PropertyCorpus,
    RepositoryDifferentialClassification,
    RepositoryDifferentialRunStatus,
    RepositoryExecutionStateKind,
    RepositoryExecutionStateObservationStatus,
    RepositoryFile,
    RepositoryForkEgressStatus,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteWorkspaceLifecycleStatus,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.orchestration import replay as replay_module
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    build_run_evidence_manifest,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayOrchestrator,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.orchestration.verification import RunVerificationStatus, verify_run_evidence
from mmaudit.reporting.json_report import write_json
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
from mmaudit.scanners.fork_matrix import (
    REPOSITORY_FORK_MATRIX_RETURN_CLEANUP_RESERVE_SECONDS,
    ForkMatrixDependencies,
    RepositoryForkMatrixRunner,
    repository_fork_matrix_timeout_budget_seconds,
)
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.reproduction import default_isolation_backend
from tests.unit.test_manifest import _write_required_artifacts

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CLEAN_CHAIN_ID = 31_337
_PINNED_CHAIN_ID = 31_338
_GENESIS_BLOCK_NUMBER = 0
_CLEAN_GENESIS_TIMESTAMP = 1_700_000_000
_PINNED_GENESIS_TIMESTAMP = 1_700_000_001


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _projection_difference_paths(
    expected: object,
    observed: object,
    *,
    path: str = "$",
    limit: int = 32,
) -> tuple[str, ...]:
    if limit <= 0:
        return ()
    if type(expected) is not type(observed):
        return (path,)
    if isinstance(expected, dict) and isinstance(observed, dict):
        differences: list[str] = []
        for key in sorted(set(expected) | set(observed)):
            child_path = f"{path}.{key}"
            if key not in expected or key not in observed:
                differences.append(child_path)
            else:
                differences.extend(
                    _projection_difference_paths(
                        expected[key],
                        observed[key],
                        path=child_path,
                        limit=limit - len(differences),
                    )
                )
            if len(differences) >= limit:
                break
        return tuple(differences)
    if isinstance(expected, list) and isinstance(observed, list):
        differences = []
        if len(expected) != len(observed):
            differences.append(f"{path}.length")
        for index, (expected_item, observed_item) in enumerate(
            zip(expected, observed, strict=False)
        ):
            differences.extend(
                _projection_difference_paths(
                    expected_item,
                    observed_item,
                    path=f"{path}[{index}]",
                    limit=limit - len(differences),
                )
            )
            if len(differences) >= limit:
                break
        return tuple(differences)
    return () if expected == observed else (path,)


def _require_external_tool(name: str) -> tuple[Path, str, str]:
    discovered = shutil.which(name)
    if discovered is None:
        pytest.skip(f"{name} is not installed")
    candidate = Path(discovered)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError:
        pytest.skip(f"{name} could not be resolved as an external executable")
    if (
        not candidate.is_absolute()
        or candidate != resolved
        or candidate.is_symlink()
        or candidate.is_junction()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or resolved.is_relative_to(_REPOSITORY_ROOT)
    ):
        pytest.skip(f"{name} is not an approved external regular executable")
    result = subprocess.run(
        [str(resolved), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "HOME": os.devnull,
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
        },
        shell=False,
    )
    output = (result.stdout or result.stderr).strip().splitlines()
    if result.returncode != 0 or not output:
        pytest.skip(f"{name} version could not be attested")
    return resolved, "\n".join(output)[:1_000], _sha256_file(resolved)


def _require_pinned_solidity_compiler() -> tuple[Path, str, str]:
    raw_solc = os.environ.get("MMAUDIT_TEST_SOLC_EXECUTABLE", "")
    if not raw_solc:
        pytest.skip("MMAUDIT_TEST_SOLC_EXECUTABLE is not configured")
    candidate = Path(raw_solc)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError:
        pytest.skip("the explicit integration-test Solidity compiler is unavailable")
    if (
        not candidate.is_absolute()
        or candidate != resolved
        or candidate.is_symlink()
        or candidate.is_junction()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or resolved.is_relative_to(_REPOSITORY_ROOT)
    ):
        pytest.skip("the explicit integration-test Solidity compiler is not trusted")
    result = subprocess.run(
        [str(resolved), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            "HOME": os.devnull,
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
        },
        shell=False,
    )
    match = re.search(r"\bVersion:\s*([0-9]+\.[0-9]+\.[0-9]+)\b", result.stdout)
    if result.returncode != 0 or match is None:
        pytest.skip("the explicit integration-test Solidity compiler version is invalid")
    return resolved, match.group(1), _sha256_file(resolved)


def _require_local_runtime_capability() -> None:
    if platform.system() not in {"Darwin", "Linux"}:
        pytest.skip("PID-bound local listener attribution is unavailable on this platform")
    if platform.system() == "Darwin":
        lsof = Path("/usr/sbin/lsof")
        try:
            metadata = lsof.lstat()
        except OSError:
            pytest.skip("the trusted Darwin listener-attribution tool is unavailable")
        if (
            lsof.resolve(strict=True) != lsof
            or lsof.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            pytest.skip("the trusted Darwin listener-attribution tool is unavailable")
        if not hasattr(os, "chflags") or getattr(stat, "UF_IMMUTABLE", 0) == 0:
            pytest.skip("Darwin immutable executable-path binding is unavailable")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
    except OSError:
        pytest.skip("numeric-loopback listener creation is unavailable")


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_anvil(endpoint: str) -> None:
    with httpx.Client(timeout=0.5, trust_env=False) as client:
        for request_id in range(1, 101):
            try:
                response = client.post(
                    endpoint,
                    json={
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "eth_chainId",
                        "params": [],
                    },
                )
                payload = response.json()
                if response.status_code == 200 and payload.get("result") == hex(_PINNED_CHAIN_ID):
                    return
            except (httpx.RequestError, ValueError):
                pass
            time.sleep(0.05)
    raise AssertionError("the disposable pinned local Anvil did not become ready")


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait(timeout=5)


def _write_synthetic_repository(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "test" / "audit").mkdir(parents=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\n',
        encoding="utf-8",
    )
    (root / "src" / "StateMarker.sol").write_text(
        "pragma solidity >=0.8.0 <0.9.0; contract StateMarker {}\n",
        encoding="utf-8",
    )
    (root / "test" / "audit" / "StateDifferential.t.sol").write_text(
        "\n".join(
            (
                "pragma solidity >=0.8.0 <0.9.0;",
                "contract StateDifferentialTest {",
                "    function testCleanAndPinnedStateAreDistinct() public view {",
                "        address stateReadTarget = "
                "address(0x1111111111111111111111111111111111111111);",
                "        assert(stateReadTarget.code.length == 0);",
                f"        assert(block.chainid == {_CLEAN_CHAIN_ID});",
                "    }",
                "}",
                "",
            )
        ),
        encoding="utf-8",
    )


def _synthetic_repository_map(root: Path) -> RepositoryMap:
    file_languages = {
        "foundry.toml": "TOML",
        "src/StateMarker.sol": "Solidity",
        "test/audit/StateDifferential.t.sol": "Solidity",
    }
    repository_files: list[RepositoryFile] = []
    for relative_path, language in sorted(file_languages.items()):
        contents = (root / relative_path).read_bytes()
        repository_files.append(
            RepositoryFile(
                path=relative_path,
                size=len(contents),
                lines=len(contents.decode("utf-8").splitlines()),
                sha256=hashlib.sha256(contents).hexdigest(),
                language=language,
            )
        )
    return RepositoryMap(
        root_name=root.name,
        languages={"Solidity": 2, "TOML": 1},
        frameworks=["Foundry"],
        manifests=["foundry.toml"],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=["foundry.toml"],
        sensitive_processing=[],
        security_tests=["test/audit/StateDifferential.t.sol"],
        files=repository_files,
    )


def _write_replay_bundle(
    *,
    run_dir: Path,
    repository_root: Path,
    config: AuditConfig,
    baseline: ScannerRun,
    differential: RepositorySuiteDifferentialRun,
) -> tuple[RunEvidenceManifest, Path]:
    run_dir.mkdir(mode=0o700)
    run_options = AuditRunOptions(
        scanner_only=True,
        skip_codeql=True,
        allow_fork_probing=True,
    )
    empty_overrides = AuditConfigOverrides()
    fork_privacy = RepositoryForkRpcPrivacyEvidence.from_differential(differential)
    privacy = {
        "code_egress_enabled": False,
        "fork_rpc_egress": fork_privacy.model_dump(mode="json"),
    }
    report = AuditReport(
        schema_version="1.0",
        run_id="real-local-fork-differential",
        generated_at=datetime.now(UTC),
        completed=True,
        incomplete_reasons=[],
        repository=_synthetic_repository_map(repository_root),
        configuration_hash=config.stable_hash(),
        model_configuration_hash=config.model_hash(),
        privacy=privacy,
        scanner_runs=[baseline],
        repository_suite_differential=differential,
        usage=[],
        budget_usd=config.execution.budget_usd,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=config.profile,
        metadata={
            "run_options": run_options.model_dump(mode="json"),
            "configuration_provenance": {
                "file_config_sha256": config.stable_hash(),
                "environment_overrides_sha256": empty_overrides.stable_hash(),
                "cli_overrides_sha256": empty_overrides.stable_hash(),
                "run_options_sha256": run_options.stable_hash(),
            },
        },
    )
    _write_required_artifacts(run_dir, report)
    empty_corpus = PropertyCorpus(
        properties=[],
        limitations=[],
        corpus_hash=_canonical_sha256(
            {
                "schema_version": "1.0",
                "property_hashes": [],
                "limitations": [],
            }
        ),
    )
    artifacts: dict[str, dict[str, object]] = {
        "scanner-results.json": {
            "schema_version": "1.0",
            "runs": [baseline.model_dump(mode="json")],
        },
        "solidity-projects.json": {"schema_version": "1.0", "projects": []},
        "solidity-compilation.json": {"schema_version": "1.0", "results": []},
        "solidity-invariants.json": {"schema_version": "1.0", "invariants": None},
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": [],
            "limitations": [],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": empty_corpus.model_dump(mode="json"),
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "harnesses": [],
            "results": [],
        },
        "candidate-findings.json": {"schema_version": "1.0", "findings": []},
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": [],
            "falsification_decisions": [],
        },
        "formal-results.json": {"schema_version": "1.0", "runs": []},
        "solidity-coverage.json": {"schema_version": "1.0", "coverage": None},
        "model-review-coverage.json": {"schema_version": "1.0", "coverage": None},
        "scope-assessment.json": {"schema_version": "1.0", "assessment": None},
    }
    for name, payload in artifacts.items():
        write_json(run_dir / name, payload)
    write_json(run_dir / "repository-suite-differential.json", differential)
    write_json(run_dir / "privacy-fork-rpc-egress.json", fork_privacy)
    write_json(run_dir / "final-findings.json", report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        file_config=config,
        environment_overrides=empty_overrides,
        cli_overrides=empty_overrides,
        run_options=run_options,
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    return manifest, manifest_path


def test_real_local_repository_fork_matrix_is_replay_ready_and_disposes_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    _require_local_runtime_capability()
    forge, forge_version, forge_sha256 = _require_external_tool("forge")
    anvil, anvil_version_output, anvil_sha256 = _require_external_tool("anvil")
    solc, solc_version, solc_sha256 = _require_pinned_solidity_compiler()
    backend = default_isolation_backend("sandbox-exec")
    if backend is None or getattr(backend, "supports_local_fork_rpc", None) is not True:
        pytest.skip("process-attested local-fork isolation is unavailable")

    anvil_version = anvil_version_output.splitlines()[0]
    if re.fullmatch(r"anvil Version: [A-Za-z0-9][A-Za-z0-9.+-]{0,127}", anvil_version) is None:
        pytest.skip("the local Anvil version is not a valid clean-launcher trust pin")
    forge_version_match = re.search(
        r"\bforge Version:\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)\b",
        forge_version,
    )
    if forge_version_match is None:
        pytest.skip("the local Forge version is not a valid scanner trust pin")
    forge_version_pin = forge_version_match.group(1)

    tmp_path.chmod(0o700)
    root = tmp_path / "synthetic-repository"
    _write_synthetic_repository(root)
    root = root.resolve(strict=True)
    baseline_private = (tmp_path / "baseline-private").resolve()
    matrix_private = (tmp_path / "matrix-private").resolve()
    pinned_home = tmp_path / "pinned-home"
    pinned_tmp = tmp_path / "pinned-tmp"
    for path in (baseline_private, matrix_private, pinned_home, pinned_tmp):
        path.mkdir(mode=0o700)
        path.chmod(0o700)

    trusted_path = os.pathsep.join(
        dict.fromkeys((str(forge.parent), str(anvil.parent), "/usr/bin", "/bin"))
    )
    monkeypatch.setenv("PATH", trusted_path)
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(solc))
    monkeypatch.setenv("MMAUDIT_ANVIL_EXECUTABLE", str(anvil))

    port = _unused_loopback_port()
    endpoint = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", endpoint)
    monkeypatch.setenv("MMAUDIT_PINNED_LOCAL_RPC_URL", endpoint)
    pinned_command = (
        str(anvil),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--chain-id",
        str(_PINNED_CHAIN_ID),
        "--number",
        str(_GENESIS_BLOCK_NUMBER),
        "--timestamp",
        str(_PINNED_GENESIS_TIMESTAMP),
        "--hardfork",
        "cancun",
        "--accounts",
        "0",
        "--no-mining",
        "--threads",
        "1",
        "--disable-default-create2-deployer",
        "--no-cors",
        "--quiet",
        "--color",
        "never",
    )
    pinned_environment = {
        "HOME": str(pinned_home),
        "TMPDIR": str(pinned_tmp),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": "/usr/bin:/bin",
    }
    pinned_state_sha256 = _canonical_sha256(
        {
            "anvil_version": anvil_version,
            "anvil_sha256": anvil_sha256,
            "chain_id": _PINNED_CHAIN_ID,
            "block_number": _GENESIS_BLOCK_NUMBER,
            "genesis_timestamp": _PINNED_GENESIS_TIMESTAMP,
            "hardfork": "cancun",
            "accounts": 0,
            "mining": False,
            "network_scope": "numeric_loopback",
        }
    )
    clean_state = RepositoryCleanForkMatrixStateConfig(
        state_id="clean-local",
        expected_chain_id=_CLEAN_CHAIN_ID,
        anvil_executable_env="MMAUDIT_ANVIL_EXECUTABLE",
        anvil_version=anvil_version,
        anvil_sha256=anvil_sha256,
        hardfork="cancun",
        genesis_timestamp=_CLEAN_GENESIS_TIMESTAMP,
        startup_timeout_seconds=8,
        shutdown_timeout_seconds=5,
    )
    pinned_state = RepositoryPinnedForkMatrixStateConfig(
        state_id="pinned-local",
        rpc_url_env="MMAUDIT_PINNED_LOCAL_RPC_URL",
        expected_chain_id=_PINNED_CHAIN_ID,
        pinned_block_number=_GENESIS_BLOCK_NUMBER,
        state_source_sha256=pinned_state_sha256,
    )
    suite = RepositoryForkSuiteConfig(
        profile="explicit",
        foundry_include_paths=("test/audit/*.t.sol",),
        foundry_include_tests=("testCleanAndPinnedStateAreDistinct",),
        hardhat_include_paths=(),
        hardhat_include_tests=(),
        max_selected_files=1,
        max_tests_per_file=1,
        max_total_tests=1,
        per_test_timeout_seconds=45,
        total_timeout_seconds=180,
        fork_matrix_states=(clean_state, pinned_state),
        fork_matrix_repetitions=2,
    )
    smart_contracts = SmartContractsConfig(
        allow_fork_probing=True,
        solc_version=solc_version,
        solc_sha256=solc_sha256,
        foundry_fuzz_runs=4,
        foundry_invariant_runs=2,
        max_fork_probe_seconds=180,
        repository_suite=suite,
    )
    reproduction = ReproductionConfig(
        expected_chain_id=_PINNED_CHAIN_ID,
        pinned_block_number=_GENESIS_BLOCK_NUMBER,
        isolation_backend="sandbox-exec",
        timeout_seconds=180,
    )
    config = config_factory(
        execution={"scanner_timeout_seconds": 180},
        scanners={
            "foundry_fork": {
                "enabled": True,
                "required": True,
                "version": forge_version_pin,
                "sha256": forge_sha256,
            }
        },
        smart_contracts=smart_contracts.model_dump(mode="python"),
        reproduction=reproduction.model_dump(mode="python"),
    )
    repository_sha256 = scanner_workspace_sha256(root, matrix_private)

    pinned_process = subprocess.Popen(
        pinned_command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=pinned_environment,
        shell=False,
        close_fds=True,
        start_new_session=True,
    )
    result: RepositorySuiteDifferentialRun | None = None
    replay: OfflineReplay | None = None
    run_dir: Path | None = None
    manifest: RunEvidenceManifest | None = None
    baseline: ScannerRun | None = None
    serialized_artifact = ""
    serialized_privacy = ""
    differential_projections: list[dict[str, object]] = []
    replay_work = tmp_path / "offline-replay-work"
    try:
        _wait_for_anvil(endpoint)
        baseline = FoundryForkScanner(
            smart_contracts,
            reproduction=reproduction,
            allow_fork_probing=True,
            expected_repository_sha256=repository_sha256,
            repository_exclusion_root=matrix_private,
        ).run(
            root,
            baseline_private,
            suite.total_timeout_seconds,
            backend=backend,
            expected_version=forge_version,
            expected_sha256=forge_sha256,
        )
        assert baseline.status is ScannerStatus.SUCCESS, baseline.error
        assert baseline.execution_evidence is ExecutionEvidenceKind.REAL

        matrix_timeout_budget_seconds = repository_fork_matrix_timeout_budget_seconds(suite)
        direct_matrix_started_at = time.monotonic()
        result = RepositoryForkMatrixRunner(
            smart_contracts,
            reproduction,
            dependencies=ForkMatrixDependencies(
                clean_state_provider=TrustedCleanAnvilLauncher(
                    environment={"MMAUDIT_ANVIL_EXECUTABLE": str(anvil)}
                ),
                environment={"MMAUDIT_PINNED_LOCAL_RPC_URL": endpoint},
            ),
        ).run(
            root,
            matrix_private,
            projects=(),
            repository_sha256=repository_sha256,
            repository_exclusion_root=matrix_private,
            backend=backend,
            baseline_run=baseline,
            absolute_deadline=direct_matrix_started_at + matrix_timeout_budget_seconds,
        )
        direct_matrix_elapsed_seconds = time.monotonic() - direct_matrix_started_at
        assert 0 <= direct_matrix_elapsed_seconds <= matrix_timeout_budget_seconds
        assert result is not None
        if (
            result.status is not RepositoryDifferentialRunStatus.COMPLETE
            and result.matrix is not None
        ):
            pytest.fail(
                "; ".join(
                    f"{attempt.state_id}/{attempt.attempt_index}: "
                    f"{attempt.scanner_run.status.value}: {attempt.scanner_run.error}"
                    for attempt in result.matrix.attempts
                ),
                pytrace=False,
            )
        assert result.status is RepositoryDifferentialRunStatus.COMPLETE

        run_dir = tmp_path / "replay-evidence"
        manifest, manifest_path = _write_replay_bundle(
            run_dir=run_dir,
            repository_root=root,
            config=config,
            baseline=baseline,
            differential=result,
        )
        differential_path = run_dir / "repository-suite-differential.json"
        serialized_artifact = differential_path.read_text(encoding="utf-8")
        emitted = RepositorySuiteDifferentialRun.model_validate_json(serialized_artifact)
        assert emitted == result
        validate_manifest_artifacts(manifest, run_dir)
        verification = verify_run_evidence(
            manifest_path=manifest_path,
            run_dir=run_dir,
            repository_root=root,
            config=config,
            file_config=config,
        )
        assert verification.status is RunVerificationStatus.CURRENT
        differential_binding = next(
            artifact
            for artifact in manifest.artifacts
            if artifact.path == "repository-suite-differential.json"
        )
        assert differential_binding.sha256 == _sha256_file(differential_path)
        assert differential_binding.size == differential_path.stat().st_size

        privacy = RepositoryForkRpcPrivacyEvidence.from_differential(emitted)
        assert privacy.status is RepositoryForkEgressStatus.ENFORCED
        serialized_privacy = privacy.model_dump_json()
        replay_scanner = ScannerRunner(
            config,
            adapters={
                "foundry_fork": FoundryForkScanner(
                    config.smart_contracts,
                    reproduction=config.reproduction,
                )
            },
            backend=backend,
        )
        original_differential_projection = replay_module._repository_differential_projection

        def capture_differential_projection(
            value: RepositorySuiteDifferentialRun,
        ) -> dict[str, object]:
            projection = original_differential_projection(value)
            differential_projections.append(projection)
            return projection

        monkeypatch.setattr(
            replay_module,
            "_repository_differential_projection",
            capture_differential_projection,
        )
        orchestrator = OfflineReplayOrchestrator(scanner_runner=replay_scanner)
        replay_started_at = time.monotonic()
        replay = asyncio.run(
            orchestrator.replay(
                manifest_path=manifest_path,
                run_dir=run_dir,
                repository_root=root,
                work_dir=replay_work,
            )
        )
        replay_elapsed_seconds = time.monotonic() - replay_started_at
        assert (
            0
            <= replay_elapsed_seconds
            <= (
                matrix_timeout_budget_seconds
                + REPOSITORY_FORK_MATRIX_RETURN_CLEANUP_RESERVE_SECONDS
            )
        )
        assert orchestrator.differential_runner is not None
    finally:
        _stop_process_group(pinned_process)

    assert pinned_process.poll() is not None
    assert result is not None
    assert replay is not None
    assert run_dir is not None
    assert manifest is not None
    assert baseline is not None
    assert result.status is RepositoryDifferentialRunStatus.COMPLETE, (
        result.limitations,
        (
            [
                (
                    attempt.state_id,
                    attempt.attempt_index,
                    attempt.scanner_run.status,
                    attempt.workspace_lifecycle.status,
                    attempt.scanner_run.repository_suite_workspace_copy is not None,
                    attempt.scanner_run.execution_observation_sha256 is not None,
                    attempt.scanner_run.error,
                )
                for attempt in result.matrix.attempts
            ]
            if result.matrix is not None
            else []
        ),
        (
            [
                (
                    consensus.state_id,
                    consensus.status,
                    consensus.inconclusive_reasons,
                )
                for consensus in result.matrix.state_consensuses
            ]
            if result.matrix is not None
            else []
        ),
    )
    assert result.matrix is not None
    matrix = result.matrix
    assert len(matrix.states) == 2
    assert [state.kind for state in matrix.states] == [
        RepositoryExecutionStateKind.CLEAN_LOCAL,
        RepositoryExecutionStateKind.PINNED_FORK,
    ]
    assert all(
        state.observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
        for state in matrix.states
    )
    assert matrix.states[0].state_sha256 != matrix.states[1].state_sha256
    assert matrix.comparisons[0].classification is RepositoryDifferentialClassification.DIVERGED
    assert matrix.repository_sha256 == scanner_workspace_sha256(root, root / ".mmaudit")
    assert len(matrix.attempts) == 4
    baseline_selection = baseline.repository_suite_selection
    baseline_policy = baseline.repository_suite_execution_policy
    assert baseline_selection is not None
    assert baseline_policy is not None
    assert (
        matrix.selection_configuration_sha256
        == baseline_selection.configuration_sha256
        == suite.stable_hash()
    )
    expected_execution_configuration_sha256 = (
        RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(baseline_policy)
    )
    assert matrix.execution_configuration_sha256 == expected_execution_configuration_sha256
    assert all(
        attempt.scanner_run.repository_suite_execution_policy is not None
        and attempt.scanner_run.repository_suite_execution_policy.total_timeout_seconds
        == suite.total_timeout_seconds
        and attempt.scanner_run.repository_suite_execution_policy.selection_configuration_sha256
        == baseline_policy.selection_configuration_sha256
        and RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(
            attempt.scanner_run.repository_suite_execution_policy
        )
        == expected_execution_configuration_sha256
        for attempt in matrix.attempts
    )
    last_attempt = matrix.attempts[-1]
    assert last_attempt.state_id == suite.fork_matrix_states[-1].state_id
    assert last_attempt.attempt_index == suite.fork_matrix_repetitions
    assert last_attempt.scanner_run.repository_suite_execution_policy is not None
    assert (
        last_attempt.scanner_run.repository_suite_execution_policy.total_timeout_seconds
        == suite.total_timeout_seconds
    )
    assert len({attempt.workspace_identity_sha256 for attempt in matrix.attempts}) == 4
    assert len({attempt.workspace_freshness_attestation_sha256 for attempt in matrix.attempts}) == 4
    assert all(
        attempt.workspace_lifecycle.status is RepositorySuiteWorkspaceLifecycleStatus.VALIDATED
        for attempt in matrix.attempts
    )
    assert all(
        attempt.workspace_lifecycle.attempt_path_absent
        and attempt.workspace_lifecycle.workspace_path_absent
        and attempt.workspace_lifecycle.private_path_retained is False
        and attempt.workspace_lifecycle.rpc_endpoint_retained is False
        for attempt in matrix.attempts
    )
    assert all(
        attempt.scanner_run.repository_suite_workspace_copy is not None
        and attempt.scanner_run.repository_suite_workspace_copy.copy_matches_source
        and attempt.scanner_run.repository_suite_workspace_copy.source_identity_stable
        and attempt.scanner_run.repository_suite_workspace_copy.workspace_identity_stable
        and (
            attempt.workspace_lifecycle.workspace_copy_evidence_sha256
            == attempt.scanner_run.repository_suite_workspace_copy.copy_evidence_sha256
        )
        for attempt in matrix.attempts
    )
    assert matrix_private.is_dir()
    assert not any(matrix_private.iterdir())
    assert replay_work.is_dir()
    assert not any(replay_work.iterdir())

    restored = RepositorySuiteDifferentialRun.model_validate_json(serialized_artifact)
    assert restored == result
    assert restored.result_sha256 == restored.expected_result_sha256()
    replay_component = next(
        component
        for component in replay.components
        if component.kind is ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL
    )
    if replay.status is not OfflineReplayStatus.REPLAYED:
        components = [
            (
                component.kind.value,
                component.status.value,
                component.expected_state,
                component.observed_state,
                component.limitations,
            )
            for component in replay.components
        ]
        difference_paths = (
            _projection_difference_paths(
                differential_projections[0],
                differential_projections[-1],
            )
            if len(differential_projections) >= 2
            else ("projection-capture-incomplete",)
        )
        pytest.fail(
            f"replay components: {components}; projection differences: "
            f"{', '.join(difference_paths)}",
            pytrace=False,
        )
    assert replay.missing_kinds == []
    assert replay_component.status is ReplayComponentStatus.MATCHED
    assert replay_component.executed
    assert replay_component.execution_evidence is ExecutionEvidenceKind.REAL
    assert replay_component.expected_state == replay_component.observed_state == "complete"
    assert replay_component.expected_sha256 == replay_component.observed_sha256
    assert replay_component.limitations == []
    assert all(
        component.status is ReplayComponentStatus.MATCHED and component.executed
        for component in replay.components
    )
    assert ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL in replay.applicable_kinds
    assert ReplayComponentKind.REPOSITORY_SUITE_DIFFERENTIAL not in replay.missing_kinds
    assert replay.model_provider_contacted is False
    assert replay.remote_network_policy == "denied"
    assert replay.loopback_policy == "local_only"

    serialized_replay = replay.model_dump_json()
    serialized_manifest = manifest.model_dump_json()
    for prohibited in (
        "http://",
        "127.0.0.1",
        str(root),
        str(baseline_private),
        str(matrix_private),
        str(run_dir),
        str(replay_work),
        str(pinned_home),
        str(pinned_tmp),
    ):
        assert prohibited not in serialized_artifact
        assert prohibited not in serialized_privacy
        assert prohibited not in serialized_replay
        assert prohibited not in serialized_manifest
