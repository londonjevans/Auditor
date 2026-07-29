"""Deterministic translation and isolated execution of fork-test specifications."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlparse

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.isolation.container import discover_rootless_container_backend
from mmaudit.isolation.provenance import (
    _seal_builtin_isolation_backend,
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    AttackerCapabilityPolicy,
    CandidateFinding,
    CrossChainMessageCapability,
    ExecutionEvidenceKind,
    FinancialAssetKind,
    FinancialSettlementEvidence,
    ForkArgument,
    ForkArgumentKind,
    ForkAssertionKind,
    ForkCallStep,
    ForkSetupCallStep,
    GeneratedFoundryTestSpec,
    OracleInfluenceCapability,
    ReproductionAttemptEvidence,
    ReproductionMinimizationEvidence,
    ReproductionResult,
    ReproductionState,
    SolidityProjectMetadata,
    SolidityProjectType,
    TransactionOrderingCapability,
)
from mmaudit.repository.workspace import validate_copyable_workspace
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.reproduction_integrity import (
    REPRODUCTION_WORKSPACE_EXCLUDED_NAMES,
    reproduction_repository_sha256,
    reproduction_tree_sha256,
    reproduction_workspace_path_excluded,
)

_FOUNDRY_CHEATCODE_ADDRESS = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"


class IsolationBackend(Protocol):
    """Wrap a trusted command in an operating-system isolation boundary."""

    @property
    def name(self) -> str: ...

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]: ...


@dataclass(frozen=True)
class MacOSSandboxBackend:
    """Use the deprecated but still enforceable macOS sandbox-exec boundary."""

    executable: str
    name: str = "sandbox-exec"
    supports_local_fork_rpc: bool = True

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        network_rule = (
            f'(allow network-outbound (remote tcp "localhost:{rpc_port}"))' if rpc_port > 0 else ""
        )
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            network_rule=network_rule,
        )

    def wrap_allowing_network(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Wrap an explicitly acknowledged build with outbound network access."""

        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            network_rule="(allow network-outbound)",
        )

    def wrap_without_network(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Wrap a local-only compiler command with no network entitlement."""

        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            network_rule="",
        )

    def _wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        network_rule: str,
    ) -> list[str]:
        resolved_private = private_dir.resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(resolved_private)
        profile_path = resolved_private / "sandbox.sb"
        forge_path = Path(command[0]).resolve()
        private_command_files: set[Path] = set()
        for argument in command[1:]:
            candidate = Path(argument)
            if not candidate.is_absolute():
                continue
            try:
                resolved_candidate = candidate.resolve(strict=True)
                resolved_candidate.relative_to(resolved_private)
            except (OSError, ValueError):
                continue
            if resolved_candidate.is_file():
                private_command_files.add(resolved_candidate)
        metadata_paths = sorted(
            {
                *resolved_private.parents,
                *forge_path.parents,
                *(parent for path in private_command_files for parent in path.parents),
            },
            key=str,
        )
        metadata_rules = " ".join(
            f'(literal "{_sandbox_quote(str(path))}")'
            for path in metadata_paths
            if path != Path("/")
        )
        # Compiler frontends legitimately spawn pinned compiler/linker processes.
        # Process execution is therefore allowed inside the boundary; file reads,
        # writes, and network remain deny-by-default, and command construction
        # outside the sandbox remains fixed and typed.
        policy = "\n".join(
            (
                "(version 1)",
                "(deny default)",
                '(import "system.sb")',
                "(allow process-fork)",
                "(allow process-exec)",
                "(allow sysctl-read)",
                # Foundry's macOS HTTP client constructs the system proxy matcher
                # before connecting to the pinned loopback RPC. Permit only the
                # read-only SystemConfiguration broker lookup it requires. The
                # separate network rule still restricts outbound connections to
                # the exact operator-pinned loopback port.
                '(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))',
                '(allow file-read* (subpath "/System") (subpath "/usr") '
                '(subpath "/Library") (subpath "/dev") '
                '(subpath "/private/var/select"))',
                f"(allow file-read-metadata {metadata_rules})",
                f'(allow file-read* (subpath "{_sandbox_quote(str(resolved_workspace))}") '
                f'(subpath "{_sandbox_quote(str(resolved_private))}") '
                f'(literal "{_sandbox_quote(str(forge_path))}") '
                + " ".join(
                    f'(literal "{_sandbox_quote(str(path))}")'
                    for path in sorted(private_command_files, key=str)
                )
                + ")",
                f'(allow file-write* (subpath "{_sandbox_quote(str(resolved_private))}"))',
                network_rule,
            )
        )
        profile_path.write_text(policy, encoding="utf-8")
        return [self.executable, "-f", str(profile_path), *command]


@dataclass(frozen=True)
class BubblewrapBackend:
    """Linux filesystem/process isolation with network denied by default."""

    executable: str
    name: str = "bubblewrap"
    supports_local_fork_rpc: bool = False

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            allow_network=False,
        )

    def wrap_allowing_network(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        """Permit explicitly acknowledged build networking inside filesystem isolation."""

        del rpc_port
        return self._wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            allow_network=True,
        )

    def _wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        allow_network: bool,
    ) -> list[str]:
        resolved_private = private_dir.resolve(strict=True)
        resolved_workspace = workspace.resolve(strict=True)
        resolved_workspace.relative_to(resolved_private)
        arguments = [
            self.executable,
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--disable-userns",
            "--cap-drop",
            "ALL",
        ]
        if not allow_network:
            arguments.append("--unshare-net")
        for system_path in (
            Path("/usr"),
            Path("/bin"),
            Path("/sbin"),
            Path("/lib"),
            Path("/lib64"),
            Path("/opt"),
            Path("/nix/store"),
        ):
            if system_path.exists():
                arguments.extend(["--ro-bind", str(system_path), str(system_path)])
        for system_file in (
            Path("/etc/hosts"),
            Path("/etc/nsswitch.conf"),
            Path("/etc/resolv.conf"),
            Path("/etc/ssl"),
            Path("/etc/pki"),
        ):
            if allow_network and system_file.exists():
                arguments.extend(["--ro-bind", str(system_file), str(system_file)])
        arguments.extend(
            [
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--dir",
                "/tmp",
            ]
        )
        for parent in reversed(resolved_private.parents):
            if parent == Path("/"):
                continue
            arguments.extend(["--dir", str(parent)])
        arguments.extend(
            [
                "--bind",
                str(resolved_private),
                str(resolved_private),
                "--chdir",
                str(resolved_workspace),
                "--",
                *command,
            ]
        )
        return arguments


def default_isolation_backend(
    configured: str,
    *,
    rootless_container_image: str | None = None,
    rootless_container_runtime: Literal["auto", "docker", "podman"] = "auto",
) -> IsolationBackend | None:
    """Return a hardened backend or None; never silently use direct execution."""

    if configured in {"auto", "rootless-container"} and rootless_container_image is not None:
        container = discover_rootless_container_backend(
            rootless_container_image,
            runtime=rootless_container_runtime,
        )
        if container is not None:
            return container
    if configured == "rootless-container":
        return None
    if configured in {"auto", "sandbox-exec"} and platform.system() == "Darwin":
        executable = shutil.which("sandbox-exec")
        if executable:
            try:
                resolved = str(Path(executable).resolve(strict=True))
            except OSError:
                resolved = ""
            if resolved:
                try:
                    return _seal_builtin_isolation_backend(MacOSSandboxBackend(executable=resolved))
                except ValueError:
                    return None
    if configured in {"auto", "bubblewrap"} and platform.system() == "Linux":
        executable = shutil.which("bwrap")
        if executable:
            try:
                resolved = str(Path(executable).resolve(strict=True))
            except OSError:
                resolved = ""
            if resolved:
                try:
                    return _seal_builtin_isolation_backend(BubblewrapBackend(executable=resolved))
                except ValueError:
                    return None
    return None


class ForkReproductionRunner:
    """Translate typed plans and execute only a fixed `forge test` command."""

    def __init__(
        self,
        reproduction: ReproductionConfig,
        smart_contracts: SmartContractsConfig,
        *,
        backend: IsolationBackend | None = None,
        forge_executable: Path | None = None,
    ) -> None:
        self.reproduction = reproduction
        self.smart_contracts = smart_contracts
        self.backend = (
            backend
            if backend is not None
            else default_isolation_backend(
                reproduction.isolation_backend,
                rootless_container_image=reproduction.rootless_container_image,
                rootless_container_runtime=reproduction.rootless_container_runtime,
            )
        )
        self.forge_executable = forge_executable

    @property
    def isolation_available(self) -> bool:
        """Whether a hardened backend was resolved without executing target code."""

        return (
            isolation_execution_evidence(self.backend) is ExecutionEvidenceKind.REAL
            and self.backend is not None
            and bool(getattr(self.backend, "supports_local_fork_rpc", True))
        )

    def run(
        self,
        *,
        repository_root: Path,
        project: SolidityProjectMetadata,
        candidate: CandidateFinding,
        specification: GeneratedFoundryTestSpec,
        private_dir: Path,
    ) -> ReproductionResult:
        started = time.monotonic()
        spec_hash = _specification_hash(specification)
        block_number = (
            specification.required_block_number
            if specification.required_block_number is not None
            else self.reproduction.pinned_block_number
        )
        expected_chain_id = (
            specification.expected_chain_id
            if specification.expected_chain_id is not None
            else self.reproduction.expected_chain_id
        )
        base = {
            "candidate_id": candidate.candidate_id,
            "test_name": specification.name,
            "specification_sha256": spec_hash,
            "original_steps": len(specification.attack_calls),
            "minimized_steps": len(specification.attack_calls),
            "required_block_number": block_number,
            "expected_chain_id": expected_chain_id,
            "assumptions": specification.assumptions,
            "financial_settlement": specification.financial_settlement,
        }
        limitation = self._eligibility_error(project, specification)
        if limitation:
            return ReproductionResult(
                **base,
                state=ReproductionState.GENERATION_FAILED,
                limitations=[limitation],
                duration_seconds=time.monotonic() - started,
            )
        if self.backend is None:
            return ReproductionResult(
                **base,
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                limitations=["no hardened isolation backend is available"],
                duration_seconds=time.monotonic() - started,
            )
        if not getattr(self.backend, "supports_local_fork_rpc", True):
            return ReproductionResult(
                **base,
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                limitations=[
                    f"{self.backend.name} denies network access and cannot reach a host "
                    "loopback fork RPC"
                ],
                duration_seconds=time.monotonic() - started,
                isolation_backend=self.backend.name,
            )
        forge = self.forge_executable or _external_executable(repository_root, "forge")
        if forge is None:
            return ReproductionResult(
                **base,
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                limitations=["forge is not installed outside the audited repository"],
                duration_seconds=time.monotonic() - started,
                isolation_backend=self.backend.name,
            )
        try:
            forge_sha256 = _file_sha256(forge)
        except OSError as exc:
            return ReproductionResult(
                **base,
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                limitations=[f"forge executable hashing failed: {type(exc).__name__}"],
                duration_seconds=time.monotonic() - started,
                isolation_backend=self.backend.name,
            )
        try:
            rpc_url, rpc_port = _local_rpc(
                os.environ.get(self.smart_contracts.fork_rpc_url_env, "")
            )
        except ValueError as exc:
            return ReproductionResult(
                **base,
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                limitations=[str(exc)],
                duration_seconds=time.monotonic() - started,
                isolation_backend=self.backend.name,
            )
        try:
            repository_sha256 = reproduction_repository_sha256(repository_root, project)
            source = translate_foundry_test(
                specification,
                targets=self.reproduction.targets,
                expected_chain_id=expected_chain_id,
            )
        except (OSError, ValueError) as exc:
            return ReproductionResult(
                **base,
                state=ReproductionState.GENERATION_FAILED,
                limitations=[f"safe test generation failed: {type(exc).__name__}: {exc}"],
                duration_seconds=time.monotonic() - started,
                isolation_backend=self.backend.name,
            )
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        attempts = 0
        successful = 0
        final_state = ReproductionState.NOT_ATTEMPTED
        stdout_path: Path | None = None
        stderr_path: Path | None = None
        test_path: Path | None = None
        display_command: list[str] = []
        limitations: list[str] = []
        attempt_evidence: list[ReproductionAttemptEvidence] = []
        outcomes: list[ReproductionState] = []
        run_root = private_dir / spec_hash[:16]
        for attempt in range(1, self.reproduction.repetitions + 1):
            attempt_root = run_root / f"attempt-{attempt}"
            workspace = attempt_root / "workspace"
            try:
                _copy_project(repository_root, project, workspace)
                workspace_sha256 = reproduction_tree_sha256(workspace)
            except (OSError, ValueError) as exc:
                final_state = ReproductionState.GENERATION_FAILED
                limitations.append(
                    f"clean reproduction workspace failed: {type(exc).__name__}: {exc}"
                )
                break
            if workspace_sha256 != repository_sha256:
                final_state = ReproductionState.GENERATION_FAILED
                limitations.append("repository changed while clean replay copies were prepared")
                break
            test_dir = workspace / "test" / "mmaudit_generated"
            test_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            test_path = test_dir / f"{specification.name}.t.sol"
            test_path.write_text(source, encoding="utf-8")
            relative_test = test_path.relative_to(workspace).as_posix()
            command = [
                str(forge),
                "test",
                "--root",
                str(workspace),
                "--match-path",
                relative_test,
                "--match-test",
                f"test_MMAudit_{specification.name}",
                "--fork-url",
                rpc_url,
                "--offline",
                "--color",
                "never",
                "-vvv",
            ]
            if block_number is not None:
                command.extend(["--fork-block-number", str(block_number)])
            display_command = [
                "[FORGE]",
                *("[REDACTED_LOCAL_FORK_RPC]" if item == rpc_url else item for item in command[1:]),
            ]
            attempts += 1
            execution = self._execute(
                command,
                workspace=workspace,
                private_dir=attempt_root,
                rpc_port=rpc_port,
                attempt=attempt,
            )
            stdout_path, stderr_path = execution.stdout_path, execution.stderr_path
            outcomes.append(execution.state)
            attempt_evidence.append(
                ReproductionAttemptEvidence(
                    attempt=attempt,
                    state=execution.state,
                    repository_sha256=workspace_sha256,
                    generated_test_sha256=source_hash,
                    fresh_workspace=True,
                    stdout_sha256=_file_sha256(execution.stdout_path),
                    stderr_sha256=_file_sha256(execution.stderr_path),
                )
            )
            if execution.state is ReproductionState.REPRODUCED:
                successful += 1
                continue
            elif execution.state is ReproductionState.NOT_REPRODUCED:
                continue
            final_state = execution.state
            limitations.extend(execution.limitations)
            break
        else:
            if outcomes and all(state is ReproductionState.REPRODUCED for state in outcomes):
                final_state = (
                    ReproductionState.REPRODUCED_AND_MINIMIZED
                    if len(specification.attack_calls) == 1
                    else ReproductionState.REPRODUCED
                )
            elif outcomes and all(state is ReproductionState.NOT_REPRODUCED for state in outcomes):
                final_state = ReproductionState.NOT_REPRODUCED
            else:
                final_state = ReproductionState.PARTIALLY_REPRODUCED
                limitations.append("clean replay attempts produced inconsistent outcomes")
        regression_path: Path | None = None
        if test_path is not None:
            regression_dir = private_dir / "regression-tests"
            regression_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            regression_path = (
                regression_dir / f"{candidate.candidate_id}-{specification.name}.t.sol"
            )
            shutil.copy2(test_path, regression_path)
        step_ids = [step.step_id for step in specification.attack_calls]
        minimization_evidence = ReproductionMinimizationEvidence(
            original_step_ids=step_ids,
            retained_step_ids=step_ids,
            removal_trials=[],
            strategy=(
                "single_step_trivial"
                if final_state is ReproductionState.REPRODUCED_AND_MINIMIZED
                else "not_attempted"
            ),
            proven_minimal=final_state is ReproductionState.REPRODUCED_AND_MINIMIZED,
        )
        return ReproductionResult(
            **base,
            state=final_state,
            execution_evidence=(
                isolation_execution_evidence(self.backend)
                if attempts > 0
                else ExecutionEvidenceKind.UNVERIFIED
            ),
            executable_sha256=forge_sha256,
            generated_test_sha256=source_hash,
            generated_test_path=(
                str(test_path.relative_to(private_dir)) if test_path is not None else None
            ),
            regression_test_path=(
                str(regression_path.relative_to(private_dir))
                if regression_path is not None
                else None
            ),
            command=display_command,
            attempts=attempts,
            successful_attempts=successful,
            duration_seconds=time.monotonic() - started,
            limitations=list(dict.fromkeys(limitations)),
            stdout_path=(
                str(stdout_path.relative_to(private_dir)) if stdout_path is not None else None
            ),
            stderr_path=(
                str(stderr_path.relative_to(private_dir)) if stderr_path is not None else None
            ),
            isolation_backend=self.backend.name,
            isolation_attestation_sha256=isolation_attestation_sha256(self.backend),
            repository_sha256=repository_sha256,
            attempt_evidence=attempt_evidence,
            minimization_evidence=minimization_evidence,
            financial_settlement_verified=(
                specification.financial_settlement is not None
                and final_state
                in {
                    ReproductionState.REPRODUCED,
                    ReproductionState.REPRODUCED_AND_MINIMIZED,
                }
                and attempts > 0
                and successful == attempts
            ),
        )

    def _eligibility_error(
        self,
        project: SolidityProjectMetadata,
        specification: GeneratedFoundryTestSpec,
    ) -> str | None:
        if project.project_type not in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}:
            return "candidate-specific reproduction currently supports Foundry projects only"
        policy_error = capability_policy_error(specification, self.reproduction)
        if policy_error is not None:
            return policy_error
        unknown_targets = sorted(
            {
                *(
                    call.target
                    for call in [*specification.setup_calls, *specification.attack_calls]
                ),
                *(
                    (specification.financial_settlement.asset_target,)
                    if specification.financial_settlement is not None
                    and specification.financial_settlement.asset_target is not None
                    else ()
                ),
            }
            - set(self.reproduction.targets)
        )
        if unknown_targets:
            return f"test referenced unconfigured target aliases: {', '.join(unknown_targets)}"
        if (
            specification.required_block_number is not None
            and self.reproduction.pinned_block_number is not None
            and specification.required_block_number != self.reproduction.pinned_block_number
        ):
            return "model-specified block number differs from the operator-pinned block"
        if (
            specification.expected_chain_id is not None
            and self.reproduction.expected_chain_id is not None
            and specification.expected_chain_id != self.reproduction.expected_chain_id
        ):
            return "model-specified chain ID differs from the operator-pinned chain"
        return None

    def _execute(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
        attempt: int,
    ) -> _Execution:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        assert self.backend is not None
        wrapped = self.backend.wrap(
            command,
            workspace=workspace,
            private_dir=private_dir,
            rpc_port=rpc_port,
        )
        stdout_path = private_dir / f"attempt-{attempt}.stdout.txt"
        stderr_path = private_dir / f"attempt-{attempt}.stderr.txt"
        environment = sanitized_scanner_environment(private_dir)
        environment.update({"FOUNDRY_FFI": "false", "FOUNDRY_NO_STORAGE_CACHING": "true"})
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        output_exceeded = False
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    wrapped,
                    cwd=workspace,
                    stdout=stdout,
                    stderr=stderr,
                    env=environment,
                    shell=False,
                    start_new_session=os.name != "nt",
                    preexec_fn=_limit_process if os.name != "nt" else None,
                )
                deadline = time.monotonic() + self.reproduction.timeout_seconds
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        stdout_path.stat().st_size > self.reproduction.max_output_bytes
                        or stderr_path.stat().st_size > self.reproduction.max_output_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                _stop_process(process)
            return _Execution(
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=[f"isolated execution failed: {type(exc).__name__}"],
            )
        if timed_out:
            return _Execution(
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=["generated fork test timed out"],
            )
        if output_exceeded:
            return _Execution(
                state=ReproductionState.ENVIRONMENT_BLOCKED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=["generated fork test exceeded the output limit"],
            )
        output = "\n".join(
            (
                stdout_path.read_text(encoding="utf-8", errors="replace"),
                stderr_path.read_text(encoding="utf-8", errors="replace"),
            )
        )
        if return_code == 0:
            return _Execution(
                state=ReproductionState.REPRODUCED,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                limitations=[],
            )
        if any(
            marker in output
            for marker in ("Compiler run failed", "ParserError:", "TypeError:", "DeclarationError:")
        ):
            state = ReproductionState.COMPILE_FAILED
        elif any(
            marker in output.lower()
            for marker in ("connection refused", "failed to get chain id", "sandbox")
        ):
            state = ReproductionState.ENVIRONMENT_BLOCKED
        else:
            state = ReproductionState.NOT_REPRODUCED
        return _Execution(
            state=state,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            limitations=[f"forge test exited with code {return_code}"],
        )


@dataclass(frozen=True)
class _Execution:
    state: ReproductionState
    stdout_path: Path
    stderr_path: Path
    limitations: list[str]


def capability_policy_error(
    specification: GeneratedFoundryTestSpec,
    limits: ReproductionConfig,
) -> str | None:
    """Return a safe reason when a model-declared capability exceeds operator limits."""

    return attacker_capability_policy_error(
        specification.attacker_policy,
        limits,
        attack_transactions=len(specification.attack_calls),
    )


def attacker_capability_policy_error(
    policy: AttackerCapabilityPolicy,
    limits: ReproductionConfig,
    *,
    attack_transactions: int,
) -> str | None:
    """Validate one typed capability policy against operator-configured limits."""

    if len(policy.attacker_controlled_actors) > limits.max_attacker_controlled_actors:
        return "declared attacker-controlled actor count exceeds the operator limit"
    if len(policy.attacker_controlled_contracts) > limits.max_attacker_controlled_contracts:
        return "declared attacker-controlled contract count exceeds the operator limit"
    if policy.starting_native_capital_wei > limits.max_starting_native_capital_wei:
        return "declared attacker starting capital exceeds the operator limit"
    if policy.flash_liquidity_wei > limits.max_flash_liquidity_wei:
        return "declared flash liquidity exceeds the operator limit"
    undeclared_approval_targets = set(policy.token_approval_targets) - set(
        limits.allowed_token_approval_targets
    )
    if undeclared_approval_targets:
        return "declared token approval targets are not operator-approved: " + ", ".join(
            sorted(undeclared_approval_targets)
        )
    if policy.max_time_shift_seconds > limits.max_time_shift_seconds:
        return "declared time shift exceeds the operator limit"
    if policy.max_block_advance > limits.max_block_advance:
        return "declared block advance exceeds the operator limit"
    ordering_rank = {
        TransactionOrderingCapability.NONE: 0,
        TransactionOrderingCapability.SAME_BLOCK: 1,
        TransactionOrderingCapability.MULTI_TRANSACTION: 2,
    }
    if (
        ordering_rank[policy.transaction_ordering]
        > ordering_rank[limits.allowed_transaction_ordering]
    ):
        return "declared transaction-ordering capability is not operator-approved"
    oracle_rank = {
        OracleInfluenceCapability.NONE: 0,
        OracleInfluenceCapability.BOUNDED_MARKET: 1,
        OracleInfluenceCapability.FIXTURE_CONFIGURED: 2,
    }
    if oracle_rank[policy.oracle_influence] > oracle_rank[limits.allowed_oracle_influence]:
        return "declared oracle influence is not operator-approved"
    if policy.governance_rights and not limits.allow_governance_rights:
        return "declared governance rights are not operator-approved"
    undeclared_roles = set(policy.privileged_roles) - set(limits.allowed_privileged_roles)
    if undeclared_roles:
        return "declared privileged roles are not operator-approved: " + ", ".join(
            sorted(undeclared_roles)
        )
    cross_chain_rank = {
        CrossChainMessageCapability.NONE: 0,
        CrossChainMessageCapability.VALID_MESSAGE: 1,
        CrossChainMessageCapability.REORDER_VALID_MESSAGES: 2,
    }
    if (
        cross_chain_rank[policy.cross_chain_messages]
        > cross_chain_rank[limits.allowed_cross_chain_messages]
    ):
        return "declared cross-chain message capability is not operator-approved"
    if attack_transactions > limits.max_attack_transactions:
        return "attack transaction count exceeds the operator limit"
    return None


def translate_foundry_test(
    specification: GeneratedFoundryTestSpec,
    *,
    targets: dict[str, str],
    expected_chain_id: int | None,
) -> str:
    """Translate the declarative DSL into fixed-shape Foundry Solidity."""

    all_calls = [*specification.setup_calls, *specification.attack_calls]
    settlement_target = (
        specification.financial_settlement.asset_target
        if specification.financial_settlement is not None
        else None
    )
    referenced_targets = {
        *(call.target for call in all_calls),
        *((settlement_target,) if settlement_target is not None else ()),
    }
    unknown = referenced_targets - set(targets)
    if unknown:
        raise ValueError(f"unknown target aliases: {', '.join(sorted(unknown))}")
    used_targets = referenced_targets
    if any(targets[name].lower() == _FOUNDRY_CHEATCODE_ADDRESS for name in used_targets):
        raise ValueError("Foundry cheatcode addresses cannot be reproduction targets")
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        "pragma solidity ^0.8.20;",
        'import "forge-std/Test.sol";',
        "",
        f"contract MMAudit_{specification.name} is Test {{",
    ]
    if (
        specification.financial_settlement is not None
        and specification.financial_settlement.asset_kind is FinancialAssetKind.ERC20
    ):
        lines.extend(
            (
                "    function mmauditTokenBalance(address token, address account)",
                "        internal view returns (uint256)",
                "    {",
                "        (bool ok, bytes memory data) = token.staticcall(",
                '            abi.encodeWithSignature("balanceOf(address)", account)',
                "        );",
                '        require(ok && data.length >= 32, "settlement balance probe failed");',
                "        return abi.decode(data, (uint256));",
                "    }",
                "",
            )
        )
    lines.append(f"    function test_MMAudit_{specification.name}() public {{")
    if expected_chain_id is not None:
        lines.append(
            f'        assertEq(block.chainid, {expected_chain_id}, "unexpected fork chain");'
        )
    for actor in specification.actors:
        lines.append(f"        address actor_{actor.name} = {actor.address};")
    for name, address in sorted(targets.items()):
        lines.append(f"        address target_{name} = {address};")
    lines.append("")
    lines.append("        // Setup phase: explicit harness preconditions only.")
    for actor in specification.actors:
        if actor.initial_native_balance_wei:
            lines.append(
                f"        vm.deal(actor_{actor.name}, {actor.initial_native_balance_wei});"
            )
    for setup_call in specification.setup_calls:
        lines.extend(_external_call_lines(setup_call, require_success=True))
    settlement = specification.financial_settlement
    if settlement is not None:
        starting_expression = _financial_balance_expression(settlement)
        lines.extend(
            (
                "",
                "        // Financial settlement: exact observed pre-state.",
                f"        uint256 mmauditStartingAssets = {starting_expression};",
                f"        assertEq(mmauditStartingAssets, {settlement.starting_assets}, "
                '"settlement starting assets mismatch");',
            )
        )
    lines.append("")
    lines.append("        // Attack phase: declared actor calls only.")
    balance_addresses = sorted(
        {
            assertion.address
            for assertion in specification.assertions
            if assertion.address is not None
        }
    )
    for index, address in enumerate(balance_addresses):
        lines.append(f"        uint256 balance_before_{index} = address({address}).balance;")
    for attack_call in specification.attack_calls:
        lines.extend(_external_call_lines(attack_call, require_success=False))
    for assertion in specification.assertions:
        lines.extend(_assertion_lines(assertion, balance_addresses))
    if settlement is not None:
        ending_expression = _financial_balance_expression(settlement)
        lines.extend(
            (
                "",
                "        // Financial settlement: exact observed post-state and cashflow.",
                f"        uint256 mmauditEndingAssets = {ending_expression};",
                f"        assertEq(mmauditEndingAssets, {settlement.ending_assets}, "
                '"settlement ending assets mismatch");',
                f'        emit log_named_uint("MMAUDIT_STARTING_ASSETS", '
                f"{settlement.starting_assets});",
                f'        emit log_named_uint("MMAUDIT_BORROWED_ASSETS", '
                f"{settlement.borrowed_assets});",
                f'        emit log_named_uint("MMAUDIT_REPAID_ASSETS", '
                f"{settlement.repaid_assets});",
                f'        emit log_named_uint("MMAUDIT_GROSS_ASSETS_RECEIVED", '
                f"{settlement.gross_assets_received});",
                f'        emit log_named_uint("MMAUDIT_FEES_PAID", {settlement.fees_paid});',
                f'        emit log_named_uint("MMAUDIT_SLIPPAGE_LOSS", '
                f"{settlement.slippage_loss});",
                f'        emit log_named_uint("MMAUDIT_ENDING_ASSETS", '
                f"{settlement.ending_assets});",
                f'        emit log_named_int("MMAUDIT_NET_IMPACT", '
                f"int256({settlement.net_impact}));",
            )
        )
    lines.extend(("    }", "}", ""))
    source = "\n".join(lines)
    attack_source = source.split("// Attack phase: declared actor calls only.", 1)[1]
    forbidden_attack_operations = (
        "vm.deal",
        "vm.store",
        "vm.load",
        "vm.etch",
        "vm.warp",
        "vm.roll",
        "vm.sign",
        "vm.broadcast",
        "vm.startBroadcast",
        "vm.ffi",
    )
    if any(operation in attack_source for operation in forbidden_attack_operations):
        raise ValueError("generated attack phase violated the fixed call-only template")
    return source


def _financial_balance_expression(settlement: FinancialSettlementEvidence) -> str:
    if settlement.asset_kind is FinancialAssetKind.NATIVE:
        return f"actor_{settlement.actor}.balance"
    assert settlement.asset_target is not None
    return f"mmauditTokenBalance(target_{settlement.asset_target}, actor_{settlement.actor})"


def _external_call_lines(
    call: ForkCallStep | ForkSetupCallStep,
    *,
    require_success: bool,
) -> list[str]:
    arguments = ", ".join(_argument_literal(argument) for argument in call.arguments)
    comma = ", " if arguments else ""
    lines = [
        f"        vm.prank(actor_{call.actor});",
        f"        (bool success_{call.step_id}, bytes memory return_{call.step_id}) = "
        f"target_{call.target}.call{{value: {call.value_wei}}}("
        f'abi.encodeWithSignature("{call.function_signature}"{comma}{arguments}));',
    ]
    if require_success:
        lines.append(
            f'        assertTrue(success_{call.step_id}, "setup call {call.step_id} failed");'
        )
    return lines


def _argument_literal(argument: ForkArgument) -> str:
    value = argument.value
    if argument.kind is ForkArgumentKind.UINT256:
        parsed = int(value, 10)
        if parsed < 0 or parsed >= 2**256:
            raise ValueError("uint256 argument is out of range")
        return f"uint256({parsed})"
    if argument.kind is ForkArgumentKind.INT256:
        parsed = int(value, 10)
        if parsed < -(2**255) or parsed >= 2**255:
            raise ValueError("int256 argument is out of range")
        return f"int256({parsed})"
    if argument.kind is ForkArgumentKind.ADDRESS:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
            raise ValueError("address argument must be a literal address")
        return f"address({value})"
    if argument.kind is ForkArgumentKind.BOOL:
        if value not in {"true", "false"}:
            raise ValueError("bool argument must be true or false")
        return value
    if argument.kind is ForkArgumentKind.BYTES32:
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
            raise ValueError("bytes32 argument must contain exactly 32 bytes")
        return f"bytes32({value})"
    if argument.kind is ForkArgumentKind.BYTES:
        if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
            raise ValueError("bytes argument must be even-length hexadecimal")
        return f'hex"{value[2:]}"'
    if len(value.encode()) > 1_024 or any(ord(character) < 32 for character in value):
        raise ValueError("string argument contains unsafe data")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _assertion_lines(assertion: object, balance_addresses: list[str]) -> list[str]:
    from mmaudit.models.schemas import ForkAssertion

    if not isinstance(assertion, ForkAssertion):
        raise TypeError("invalid assertion")
    if assertion.kind is ForkAssertionKind.CALL_SUCCEEDS:
        return [f'        assertTrue(success_{assertion.step_id}, "call did not succeed");']
    if assertion.kind is ForkAssertionKind.CALL_REVERTS:
        return [f'        assertFalse(success_{assertion.step_id}, "call did not revert");']
    if assertion.kind is ForkAssertionKind.RETURN_UINT_GTE:
        return [
            f'        assertTrue(success_{assertion.step_id}, "call did not succeed");',
            f"        assertGe(abi.decode(return_{assertion.step_id}, (uint256)), "
            f"{assertion.expected_uint});",
        ]
    if assertion.kind is ForkAssertionKind.RETURN_BOOL_EQUALS:
        expected = "true" if assertion.expected_bool else "false"
        return [
            f'        assertTrue(success_{assertion.step_id}, "call did not succeed");',
            f"        assertEq(abi.decode(return_{assertion.step_id}, (bool)), {expected});",
        ]
    assert assertion.address is not None
    index = balance_addresses.index(assertion.address)
    if assertion.kind is ForkAssertionKind.NATIVE_BALANCE_GAIN_GTE:
        return [
            f"        assertGe(address({assertion.address}).balance, "
            f"balance_before_{index} + {assertion.expected_uint});"
        ]
    return [
        f"        assertGe(balance_before_{index}, "
        f"address({assertion.address}).balance + {assertion.expected_uint});"
    ]


def _copy_project(
    repository_root: Path,
    project: SolidityProjectMetadata,
    workspace: Path,
) -> None:
    source = (
        repository_root if project.project_root == "." else repository_root / project.project_root
    )
    source = source.resolve(strict=True)
    source.relative_to(repository_root.resolve(strict=True))
    validate_copyable_workspace(
        source,
        excluded=lambda path: reproduction_workspace_path_excluded(path, source),
    )
    shutil.copytree(
        source,
        workspace,
        ignore=lambda directory, names: _dynamic_workspace_ignore(
            directory,
            names,
            source=source,
        ),
    )


def _dynamic_workspace_ignore(
    directory: str,
    names: list[str],
    *,
    source: Path,
) -> set[str]:
    return {
        name
        for name in names
        if name.lower() in REPRODUCTION_WORKSPACE_EXCLUDED_NAMES
        or reproduction_workspace_path_excluded(Path(directory) / name, source)
    }


def _external_executable(repository_root: Path, name: str) -> Path | None:
    raw = shutil.which(name)
    if raw is None:
        return None
    resolved = Path(raw).resolve(strict=True)
    try:
        resolved.relative_to(repository_root.resolve(strict=True))
    except ValueError:
        return resolved
    return None


def _local_rpc(value: str) -> tuple[str, int]:
    if not value:
        raise ValueError("local fork RPC environment variable is not set")
    parsed = urlparse(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("fork reproduction requires a plain HTTP loopback RPC endpoint")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("local fork RPC URL must not contain credentials or query data")
    port = parsed.port
    if port is None:
        raise ValueError("local fork RPC URL must include an explicit port")
    return value, port


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _specification_hash(specification: GeneratedFoundryTestSpec) -> str:
    payload = json.dumps(
        specification.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _sandbox_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _limit_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
        resource.setrlimit(resource.RLIMIT_FSIZE, (50_000_000, 50_000_000))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    except (ImportError, OSError, ValueError):
        return


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
