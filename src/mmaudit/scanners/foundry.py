"""Foundry fork-test adapter for defensive smart-contract probing."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from mmaudit.config import SmartContractsConfig
from mmaudit.isolation.provenance import (
    isolation_attestation_sha256,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    FoundryTestExecutionSummary,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.scanners.base import (
    ScannerAdapter,
    ScannerIsolationBackend,
    _file_sha256,
    copy_scanner_workspace,
    isolated_executable_version,
    make_finding,
    sanitized_scanner_environment,
    scanner_trust_pin_error,
)


class FoundryForkScanner(ScannerAdapter):
    """Run existing Foundry audit tests against an explicitly configured fork RPC."""

    name = "foundry_fork"
    executable = "forge"
    finding_exit_codes = frozenset({0, 1})
    max_stdout_bytes = 50_000_000
    max_stderr_bytes = 10_000_000

    def __init__(
        self,
        config: SmartContractsConfig,
        *,
        allow_fork_probing: bool = False,
    ) -> None:
        self.config = config
        self.allow_fork_probing = allow_fork_probing

    def with_runtime_allowance(self, allow_fork_probing: bool) -> FoundryForkScanner:
        return FoundryForkScanner(self.config, allow_fork_probing=allow_fork_probing)

    def build_command(self, root: Path, private_dir: Path) -> list[str]:
        del root, private_dir
        command = [
            self.executable,
            "test",
            "--fork-url",
            self._fork_rpc_url(),
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--json",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def display_command(self) -> list[str]:
        command = [
            self.executable,
            "test",
            "--fork-url",
            "[REDACTED_FORK_RPC_URL]",
            "--match-path",
            self.config.foundry_match_path,
            "--fuzz-runs",
            str(self.config.foundry_fuzz_runs),
            "--json",
            "-vv",
        ]
        if self.config.foundry_match_test:
            command.extend(["--match-test", self.config.foundry_match_test])
        return command

    def parse(self, root: Path, stdout: str, private_dir: Path) -> list[ScannerFinding]:
        del private_dir
        findings: list[ScannerFinding] = []
        for suite_name, suite in _foundry_suites(stdout).items():
            current_path = suite_name.rsplit(":", maxsplit=1)[0]
            test_results = suite["test_results"]
            assert isinstance(test_results, dict)
            for test_signature, result in test_results.items():
                assert isinstance(test_signature, str)
                assert isinstance(result, dict)
                if _foundry_status(result) != "FAIL":
                    continue
                test_name = test_signature.partition("(")[0]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name) is None:
                    raise ValueError("Forge JSON contains an invalid test name")
                location = _find_test_location(root, current_path, test_name)
                raw_reason = result.get("reason")
                reason = _clean_reason(
                    raw_reason
                    if isinstance(raw_reason, str) and raw_reason
                    else "Foundry fork test failed"
                )
                finding = make_finding(
                    root=root,
                    scanner=self.name,
                    rule_id="foundry-fork-test-failure",
                    title=f"Fork reproduction test failed: {test_name}",
                    severity=Severity.HIGH,
                    message=reason,
                    path=current_path,
                    start_line=location[0],
                    end_line=location[1],
                    metadata={
                        "class": "fork_reproduction",
                        "fork_only": True,
                        "test_name": test_name,
                        "fork_rpc_url_env": self.config.fork_rpc_url_env,
                    },
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun:
        private_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = sanitized_scanner_environment(private_dir)
        start = datetime.now(UTC)
        monotonic_start = time.monotonic()
        skip_reason = self._skip_reason(root)
        if skip_reason is not None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.SKIPPED,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=skip_reason,
            )
        executable = shutil.which(self.executable)
        if executable is None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.UNAVAILABLE,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="forge is not installed",
            )
        if backend is None:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.UNAVAILABLE,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="hardened fork-test isolation is unavailable; tests were not executed",
            )
        executable_path = Path(executable).resolve(strict=True)
        try:
            executable_path.relative_to(root.resolve(strict=True))
        except ValueError:
            pass
        else:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="refusing forge executable resolved from inside audited repository",
            )
        try:
            executable_sha256 = _file_sha256(executable_path)
        except OSError as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"could not hash forge executable: {type(exc).__name__}",
            )
        workspace = private_dir / "workspace"
        version: str | None = None
        try:
            _reject_unsafe_foundry_configuration(root)
            _rpc_url, rpc_port = self._fork_rpc()
            copy_scanner_workspace(root, workspace, private_dir)
            command = self.build_command(workspace, private_dir)
            command[0] = str(executable_path)
            command = backend.wrap(
                command,
                workspace=workspace,
                private_dir=private_dir,
                rpc_port=rpc_port,
            )
            version = isolated_executable_version(
                executable_path,
                environment,
                backend,
                workspace,
                private_dir,
            )
            trust_error = scanner_trust_pin_error(
                version=version,
                executable_sha256=executable_sha256,
                expected_version=expected_version,
                expected_sha256=expected_sha256,
            )
            if trust_error is not None:
                return ScannerRun(
                    scanner=self.name,
                    status=ScannerStatus.FAILED,
                    version=version,
                    executable_sha256=executable_sha256,
                    command=self.display_command(),
                    started_at=start,
                    finished_at=datetime.now(UTC),
                    duration_seconds=time.monotonic() - monotonic_start,
                    error=trust_error,
                    isolation_backend=str(getattr(backend, "name", "")) or None,
                )
        except (OSError, ValueError) as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"unsafe or invalid fork probe configuration: {type(exc).__name__}",
            )
        raw_path = private_dir / "foundry-fork.json"
        error_path = private_dir / "foundry-fork.stderr.txt"
        environment["ETH_RPC_URL"] = self._fork_rpc_url()
        environment["FOUNDRY_FFI"] = "false"
        environment["FOUNDRY_INVARIANT_RUNS"] = str(self.config.foundry_invariant_runs)
        environment["FOUNDRY_NO_STORAGE_CACHING"] = "true"
        if profile := os.environ.get("FOUNDRY_PROFILE"):
            environment["FOUNDRY_PROFILE"] = profile
        timeout = min(timeout_seconds, self.config.max_fork_probe_seconds)
        timed_out = False
        output_exceeded = False
        process: subprocess.Popen[bytes] | None = None
        try:
            with raw_path.open("wb") as stdout_handle, error_path.open("wb") as stderr_handle:
                process = subprocess.Popen(
                    command,
                    cwd=workspace,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    env=environment,
                    shell=False,
                    start_new_session=os.name != "nt",
                    creationflags=(
                        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                        if os.name == "nt"
                        else 0
                    ),
                    preexec_fn=_limit_process if os.name != "nt" else None,
                )
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _stop_process(process)
                        break
                    if (
                        raw_path.stat().st_size > self.max_stdout_bytes
                        or error_path.stat().st_size > self.max_stderr_bytes
                    ):
                        output_exceeded = True
                        _stop_process(process)
                        break
                    time.sleep(0.05)
                return_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                _stop_process(process)
            return_code = process.returncode if process is not None else -1
        except OSError as exc:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"fork probe process failed: {type(exc).__name__}",
            )
        if timed_out:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.TIMED_OUT,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error=f"fork probe exceeded {timeout:.0f}s timeout",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            )
        if output_exceeded:
            return ScannerRun(
                scanner=self.name,
                status=ScannerStatus.FAILED,
                version=version,
                command=self.display_command(),
                started_at=start,
                finished_at=datetime.now(UTC),
                duration_seconds=time.monotonic() - monotonic_start,
                error="fork probe output exceeded the private output limit",
                raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            )
        parse_error: str | None = None
        findings: list[ScannerFinding] = []
        foundry_summary: FoundryTestExecutionSummary | None = None
        try:
            stdout = raw_path.read_text(encoding="utf-8")
            foundry_summary = _foundry_execution_summary(stdout)
            findings = self.parse(workspace, stdout, private_dir)
        except (UnicodeError, ValueError) as exc:
            parse_error = f"invalid Forge JSON execution output: {type(exc).__name__}"
        status = (
            ScannerStatus.SUCCESS
            if (
                return_code in self.finding_exit_codes
                and foundry_summary is not None
                and parse_error is None
            )
            else ScannerStatus.FAILED
        )
        run = ScannerRun(
            scanner=self.name,
            status=status,
            execution_evidence=(
                isolation_execution_evidence(backend)
                if status is ScannerStatus.SUCCESS
                else ExecutionEvidenceKind.UNVERIFIED
            ),
            version=version,
            executable_sha256=executable_sha256,
            command=self.display_command(),
            started_at=start,
            finished_at=datetime.now(UTC),
            duration_seconds=time.monotonic() - monotonic_start,
            findings=findings,
            error=(
                None
                if status is ScannerStatus.SUCCESS
                else (
                    parse_error
                    or (
                        "Forge JSON contained no structured test results"
                        if return_code in self.finding_exit_codes and foundry_summary is None
                        else f"forge exited with code {return_code}"
                    )
                )
            ),
            raw_output_path=str(raw_path.relative_to(private_dir.parent)),
            raw_output_sha256=_file_sha256(raw_path),
            raw_output_bytes=raw_path.stat().st_size,
            process_exit_code=return_code,
            isolation_backend=str(getattr(backend, "name", "")) or None,
            isolation_attestation_sha256=isolation_attestation_sha256(backend),
            machine_output_validated=parse_error is None and foundry_summary is not None,
            foundry_summary=foundry_summary,
        )
        return ScannerRun.model_validate(
            {
                **run.model_dump(mode="json"),
                "execution_observation_sha256": run.expected_execution_observation_sha256(),
            }
        )

    def _skip_reason(self, root: Path) -> str | None:
        if not self.config.enabled:
            return "smart-contract probing disabled by configuration"
        if not (self.allow_fork_probing or self.config.allow_fork_probing):
            return "fork probing not acknowledged; pass --allow-fork or set smart_contracts.allow_fork_probing"
        if not _looks_like_foundry_project(root):
            return "no Foundry smart-contract project detected"
        if not list(root.glob(self.config.foundry_match_path)):
            return f"no Foundry tests matched {self.config.foundry_match_path}"
        return None

    def _fork_rpc_url(self) -> str:
        return self._fork_rpc()[0]

    def _fork_rpc(self) -> tuple[str, int]:
        value = os.environ.get(self.config.fork_rpc_url_env, "")
        if not value:
            raise ValueError(f"{self.config.fork_rpc_url_env} is not set")
        parsed = urlparse(value)
        if parsed.scheme != "http" or not parsed.netloc:
            raise ValueError("fork RPC URL must be a plain HTTP URL")
        if self.config.require_local_fork_rpc and parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("fork RPC URL must point to a local fork endpoint")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("fork RPC URL must not contain credentials or query data")
        if parsed.port is None:
            raise ValueError("fork RPC URL must contain an explicit port")
        return value, parsed.port


def _looks_like_foundry_project(root: Path) -> bool:
    return (root / "foundry.toml").is_file() or any(
        path.suffix == ".sol"
        for path in [*root.glob("src/**/*.sol"), *root.glob("contracts/**/*.sol")]
    )


def _reject_unsafe_foundry_configuration(root: Path) -> None:
    foundry_config = root / "foundry.toml"
    if foundry_config.is_file():
        payload = tomllib.loads(foundry_config.read_text(encoding="utf-8", errors="replace"))
        if _toml_contains_true(payload, "ffi"):
            raise ValueError("Foundry FFI is enabled; refusing to execute fork tests")
    for path in root.glob("**/*.sol"):
        try:
            relative = PurePosixPath(path.relative_to(root).as_posix())
        except ValueError:
            continue
        if (
            ".git" in relative.parts
            or ".mmaudit" in relative.parts
            or "node_modules" in relative.parts
        ):
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        if "vm.ffi" in content:
            raise ValueError("Foundry test uses vm.ffi; refusing to execute fork tests")


def _toml_contains_true(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return any(
            (name == key and item is True) or _toml_contains_true(item, key)
            for name, item in value.items()
        )
    if isinstance(value, list):
        return any(_toml_contains_true(item, key) for item in value)
    return False


def _find_test_location(root: Path, raw_path: str, test_name: str) -> tuple[int, int]:
    path = root / raw_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return (1, 1)
    pattern = re.compile(rf"\bfunction\s+{re.escape(test_name)}\b")
    for index, line in enumerate(lines, start=1):
        if pattern.search(line):
            return (index, _find_block_end(lines, index))
    return (1, min(1, len(lines)))


def _find_block_end(lines: list[str], start_line: int) -> int:
    depth = 0
    seen_open = False
    for index in range(start_line, len(lines) + 1):
        line = lines[index - 1]
        depth += line.count("{")
        if "{" in line:
            seen_open = True
        depth -= line.count("}")
        if seen_open and depth <= 0:
            return index
    return start_line


def _clean_reason(value: str) -> str:
    sanitized = "".join(character if ord(character) >= 32 else " " for character in value)
    return " ".join(sanitized.split())[:500]


def _foundry_execution_summary(stdout: str) -> FoundryTestExecutionSummary | None:
    """Count only typed Forge JSON results; repository log text is never classified."""

    classified = {"unit": 0, "fuzz": 0, "invariant": 0}
    outcomes = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    fuzz_cases = 0
    invariant_runs = 0
    invariant_calls = 0

    for suite in _foundry_suites(stdout).values():
        test_results = suite["test_results"]
        assert isinstance(test_results, dict)
        for result in test_results.values():
            assert isinstance(result, dict)
            status = _foundry_status(result)
            kind, metadata = _foundry_kind(result)
            outcomes[status] += 1
            classified[kind] += 1
            if kind == "fuzz":
                fuzz_cases += _foundry_nonnegative_integer(metadata, "runs")
            elif kind == "invariant":
                invariant_runs += _foundry_nonnegative_integer(metadata, "runs")
                invariant_calls += _foundry_nonnegative_integer(metadata, "calls")

    if not any(classified.values()):
        return None
    return FoundryTestExecutionSummary(
        unit_tests=classified["unit"],
        fuzz_tests=classified["fuzz"],
        invariant_tests=classified["invariant"],
        passed_tests=outcomes["PASS"],
        failed_tests=outcomes["FAIL"],
        skipped_tests=outcomes["SKIP"],
        fuzz_cases=fuzz_cases,
        invariant_runs=invariant_runs,
        invariant_calls=invariant_calls,
    )


def _foundry_suites(stdout: str) -> dict[str, dict[str, Any]]:
    """Load the bounded Forge JSON suite map and reject ambiguous structures."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Forge JSON contains a duplicate object key")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Forge JSON contains a non-finite number: {value}")

    try:
        payload = json.loads(
            stdout,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Forge output is not one JSON document") from exc
    if not isinstance(payload, dict):
        raise ValueError("Forge JSON root must be a suite object")
    if len(payload) > 10_000:
        raise ValueError("Forge JSON suite count exceeds the execution bound")

    suites: dict[str, dict[str, Any]] = {}
    total_tests = 0
    for suite_name, raw_suite in sorted(payload.items()):
        if (
            not isinstance(suite_name, str)
            or not suite_name
            or len(suite_name) > 2_000
            or any(ord(character) < 32 or ord(character) == 127 for character in suite_name)
            or ":" not in suite_name
        ):
            raise ValueError("Forge JSON contains an invalid suite identifier")
        raw_path, contract_name = suite_name.rsplit(":", maxsplit=1)
        path = PurePosixPath(raw_path)
        if (
            not raw_path
            or not contract_name
            or path.is_absolute()
            or path.as_posix() != raw_path
            or "\\" in raw_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Forge JSON suite identifier is not repository-relative")
        if not isinstance(raw_suite, dict):
            raise ValueError("Forge JSON suite must be an object")
        test_results = raw_suite.get("test_results")
        if not isinstance(test_results, dict):
            raise ValueError("Forge JSON suite is missing test_results")
        total_tests += len(test_results)
        if total_tests > 200_000:
            raise ValueError("Forge JSON test count exceeds the execution bound")
        for test_name, result in test_results.items():
            if (
                not isinstance(test_name, str)
                or not test_name
                or len(test_name) > 1_000
                or any(ord(character) < 32 or ord(character) == 127 for character in test_name)
                or not isinstance(result, dict)
            ):
                raise ValueError("Forge JSON contains an invalid test result")
            _foundry_status(result)
            _foundry_kind(result)
        suites[suite_name] = raw_suite
    return suites


def _foundry_status(result: dict[str, Any]) -> str:
    raw_status = result.get("status")
    statuses = {
        "Success": "PASS",
        "Failure": "FAIL",
        "Skipped": "SKIP",
    }
    if not isinstance(raw_status, str) or raw_status not in statuses:
        raise ValueError("Forge JSON contains an unknown test status")
    return statuses[raw_status]


def _foundry_kind(result: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    raw_kind = result.get("kind")
    if not isinstance(raw_kind, dict) or len(raw_kind) != 1:
        raise ValueError("Forge JSON test kind must contain one typed variant")
    kind_name, metadata = next(iter(raw_kind.items()))
    normalized = {
        "Unit": "unit",
        "Fuzz": "fuzz",
        "Invariant": "invariant",
    }.get(kind_name)
    if normalized is None or not isinstance(metadata, dict):
        raise ValueError("Forge JSON contains an unsupported test kind")
    if normalized == "fuzz":
        _foundry_nonnegative_integer(metadata, "runs")
    elif normalized == "invariant":
        _foundry_nonnegative_integer(metadata, "runs")
        _foundry_nonnegative_integer(metadata, "calls")
    return normalized, metadata


def _foundry_nonnegative_integer(metadata: dict[str, Any], field: str) -> int:
    value = metadata.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 2**63 - 1:
        raise ValueError(f"Forge JSON {field} must be a bounded non-negative integer")
    return value


def _limit_process() -> None:
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
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
