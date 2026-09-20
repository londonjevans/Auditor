"""Owned raw solc transcripts for Forge's otherwise discarded compilation.

These records bind bytes and process observations, not execution, coverage,
qualification, or release authority. Managed namespace/toolchain adoption remains
the responsibility of the existing caller; a launcher is never a solc identity.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

from pydantic import ConfigDict, Field

from mmaudit.models.schemas import (
    RepositorySuiteFramework,
    RepositorySuiteTestDescriptor,
    StrictModel,
)
from mmaudit.scanners.fork_rpc import local_fork_rpc_port
from mmaudit.scanners.foundry_inventory import FoundrySourceInput, _normalized_source_path
from mmaudit.scanners.read_only_rpc import DETERMINISTIC_FORK_GAS_PRICE_WEI
from mmaudit.solidity import solc_capture_worker as worker
from mmaudit.solidity.compiler_source import CompilerSourceMap

if TYPE_CHECKING:
    from mmaudit.scanners.foundry_debugger import FoundryDebuggerLimits, FoundryDebuggerObservation


class SolcCaptureLimits(StrictModel):
    """Per-stream and complete-session limits; never USD or ledger policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    max_invocations: int = Field(default=16, ge=1, le=128)
    max_stdin_bytes: int = Field(default=16_000_000, ge=1, le=64_000_000)
    max_stdout_bytes: int = Field(default=48_000_000, ge=1, le=64_000_000)
    max_stderr_bytes: int = Field(default=1_000_000, ge=1, le=4_000_000)
    max_total_stream_bytes: int = Field(default=64_000_000, ge=1, le=128_000_000)


@dataclass(frozen=True, slots=True)
class CapturedSolcInvocation:
    """Exact raw streams and arguments; a zero exit code is not compilation success."""

    sequence: int
    received_argv: tuple[str, ...]
    compiler_argv: tuple[str, ...]
    compiler_exit_code: int
    stdin: bytes = field(repr=False)
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    transcript_sha256: str
    evidence_authority: Literal["UNATTESTED_COMPILER_TRANSCRIPT"] = "UNATTESTED_COMPILER_TRANSCRIPT"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: object) -> bytes:
    return json.dumps(raw, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _directory(path: Path) -> worker.DirectoryIdentity:
    return worker.directory_identity(path)


@dataclass(frozen=True, slots=True)
class SolcCaptureSession:
    """An owned prepared capture, including original byte populations and code pins."""

    root: Path
    helper_root: Path
    launcher: Path
    compiler: Path
    compiler_sha256: str
    interpreter: Path
    interpreter_sha256: str
    workspace: Path
    sources: tuple[FoundrySourceInput, ...] = field(repr=False)
    limits: SolcCaptureLimits
    deadline_monotonic: float
    input_pins: tuple[tuple[str, str], ...]
    directory_identity: worker.DirectoryIdentity
    calls_identity: worker.DirectoryIdentity
    workspace_identity: worker.DirectoryIdentity
    file_identities: tuple[tuple[Path, int, worker.FileIdentity], ...]
    runtime_file_pins: tuple[tuple[Path, str, worker.FileIdentity], ...]
    owner_launch_receipt_path: Path | None

    def require_inputs_unchanged(self) -> None:
        """Recheck exact helper, tool, source and directory inputs; no repinning."""
        worker._check_deadline(self.deadline_monotonic)
        if (
            _directory(self.root) != self.directory_identity
            or _directory(self.root / "calls") != self.calls_identity
            or _directory(self.workspace) != self.workspace_identity
        ):
            raise ValueError("compiler capture directory identity changed")
        for path, maximum, expected in self.file_identities:
            worker._check_deadline(self.deadline_monotonic)
            if worker.file_snapshot(path, maximum)[1] != expected:
                raise ValueError("compiler capture file or lexical ancestor was replaced")
        for name, pin in self.input_pins:
            if _sha(worker.file_bytes(self.helper_root / name, 2_000_000)) != pin:
                raise ValueError("compiler capture helper input changed")
        for path, pin in (
            (self.compiler, self.compiler_sha256),
            (self.interpreter, self.interpreter_sha256),
        ):
            if _sha(worker.file_bytes(path, 200_000_000)) != pin:
                raise ValueError("compiler capture executable changed")
        for source in self.sources:
            raw = worker.file_bytes(self.workspace / source.path, 100_000_000)
            if raw != source.content or _sha(raw) != source.source_sha256:
                raise ValueError("original compiler capture source changed")
        for path, pin, identity in self.runtime_file_pins:
            worker._check_deadline(self.deadline_monotonic)
            raw, current = worker.file_snapshot(path, 16_000_000)
            if current != identity or _sha(raw) != pin:
                raise ValueError("compiler capture runtime file changed or was replaced")
        worker._check_deadline(self.deadline_monotonic)

    def require_runtime_observation(self, raw: bytes) -> None:
        """Bind imported-file observations without promoting them to runtime authority."""
        value = worker.decode(raw)
        expected = {str(path): pin for path, pin, _ in self.runtime_file_pins}
        if (
            type(value) is not dict
            or set(value)
            != {
                "interpreter_sha256",
                "flags",
                "files",
                "transitive_native_dependency_closure_verified",
            }
            or value["interpreter_sha256"] != self.interpreter_sha256
            or value["transitive_native_dependency_closure_verified"] is not False
            or value["flags"]
            != {
                "isolated": 1,
                "ignore_environment": 1,
                "no_site": 1,
                "dont_write_bytecode": 1,
            }
            or any(type(flag) is not int for flag in value["flags"].values())
            or type(value["files"]) is not dict
            or not value["files"]
            or any(expected.get(path) != pin for path, pin in value["files"].items())
        ):
            raise ValueError("compiler runtime observation differs from its owned input population")

    def collect(self) -> tuple[CapturedSolcInvocation, ...]:
        """Read only a complete original transcript population; never repair a partial tail."""
        self.require_inputs_unchanged()
        lock_fd = os.open(self.root / "serial.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("compiler transcript still has an active invocation") from exc
            return self._collect_locked()
        finally:
            os.close(lock_fd)

    def _collect_locked(self) -> tuple[CapturedSolcInvocation, ...]:
        self.require_inputs_unchanged()
        expected_helpers = {name for name, _ in self.input_pins}
        expected_root = {"calls", "serial.lock"}
        if self.helper_root == self.root:
            expected_root |= expected_helpers
        elif {p.name for p in self.helper_root.iterdir()} != expected_helpers:
            raise ValueError("compiler capture immutable helper population changed")
        if {p.name for p in self.root.iterdir()} != expected_root:
            raise ValueError("compiler capture root population changed")
        directories = sorted((self.root / "calls").iterdir())
        if not 1 <= len(directories) <= self.limits.max_invocations:
            raise ValueError("compiler capture invocation population is invalid")
        result = []
        total = 0
        observed_sources: set[str] = set()
        original_sources = {source.path: source for source in self.sources}
        directory_pins: dict[Path, tuple[worker.DirectoryIdentity, frozenset[str]]] = {}
        stream_pins: dict[Path, tuple[int, str, worker.FileIdentity]] = {}
        for index, directory in enumerate(directories):
            worker._check_deadline(self.deadline_monotonic)
            if directory.name != f"{index:04d}":
                raise ValueError("compiler capture invocation order changed")
            identity = _directory(directory)
            expected = {
                "request.json",
                "intent.json",
                "stdin.bin",
                "stdout.bin",
                "stderr.bin",
                "process.json",
                "runtime.json",
                "complete.json",
            }
            if {p.name for p in directory.iterdir()} != expected:
                raise ValueError("compiler invocation is partial, failed, or has extra artifacts")
            directory_pins[directory] = (identity, frozenset(expected))
            raw = {}
            for name in sorted(expected):
                maximum = (
                    (524_288 if name == "runtime.json" else 65_536)
                    if name.endswith(".json")
                    else min(
                        getattr(self.limits, "max_" + name.removesuffix(".bin") + "_bytes"),
                        self.limits.max_total_stream_bytes,
                    )
                )
                content, file_identity = worker.file_snapshot(directory / name, maximum)
                raw[name] = content
                stream_pins[directory / name] = (maximum, _sha(content), file_identity)
            intent, complete = (
                worker.decode(raw["intent.json"]),
                worker.decode(raw["complete.json"]),
            )
            if type(intent) is not dict or set(intent) != {"received_argv", "compiler_argv"}:
                raise ValueError("compiler invocation intent is malformed")
            received = intent["received_argv"]
            if type(received) is not list or any(type(x) is not str for x in received):
                raise ValueError("compiler invocation arguments are malformed")
            request_record = worker.decode(raw["request.json"])
            if request_record != {"received_argv": received}:
                raise ValueError("compiler admitted intent differs from its original request")
            actual = worker.compiler_arguments(received, self.workspace)
            if intent["compiler_argv"] != list(actual):
                raise ValueError("compiler invocation arguments differ from the owned policy")
            if type(complete) is not dict or set(complete) != {
                "compiler_exit_code",
                "stdin_sha256",
                "stdout_sha256",
                "stderr_sha256",
                "runtime_sha256",
                "owner_launch_receipt_sha256",
            }:
                raise ValueError("compiler completion is malformed")
            if (
                type(complete["compiler_exit_code"]) is not int
                or complete["compiler_exit_code"] != 0
            ):
                raise ValueError("compiler invocation did not finish with an exact zero exit code")
            process_record = worker.decode(raw["process.json"])
            if (
                type(process_record) is not dict
                or set(process_record) != {"process_started", "compiler_exit_code"}
                or process_record["process_started"] is not True
                or type(process_record["compiler_exit_code"]) is not int
                or process_record["compiler_exit_code"] != complete["compiler_exit_code"]
            ):
                raise ValueError("compiler completion differs from its retained process result")
            if _sha(raw["runtime.json"]) != complete["runtime_sha256"]:
                raise ValueError("compiler runtime observation changed")
            self.require_runtime_observation(raw["runtime.json"])
            expected_receipt = (
                None
                if self.owner_launch_receipt_path is None
                else _sha(worker.file_bytes(self.owner_launch_receipt_path, 524_288))
            )
            if complete["owner_launch_receipt_sha256"] != expected_receipt:
                raise ValueError(
                    "compiler invocation differs from its original owner launch receipt"
                )
            for stream in ("stdin", "stdout", "stderr"):
                content = raw[stream + ".bin"]
                if (
                    len(content) > getattr(self.limits, "max_" + stream + "_bytes")
                    or _sha(content) != complete[stream + "_sha256"]
                ):
                    raise ValueError("compiler raw stream changed or exceeds its ceiling")
                total += len(content)
            if total > self.limits.max_total_stream_bytes:
                raise ValueError("compiler transcript exceeds its cumulative stream ceiling")
            if received == ["--version"]:
                if raw["stdin.bin"]:
                    raise ValueError("compiler version invocation has unexpected input")
            else:
                sources = {
                    s.path: [_sha(s.content), _sha(s.content.replace(b"\r\n", b"\n"))]
                    for s in self.sources
                }
                worker._validate_input(raw["stdin.bin"], sources)
                request = worker.decode(raw["stdin.bin"])
                for path, value in request["sources"].items():
                    source = original_sources[path]
                    CompilerSourceMap(source.content, value["content"].encode())
                    observed_sources.add(path)
                worker.validate_output(raw["stdin.bin"], raw["stdout.bin"])
            digest = _sha(_json({name: _sha(value) for name, value in sorted(raw.items())}))
            result.append(
                CapturedSolcInvocation(
                    index,
                    tuple(received),
                    actual,
                    complete["compiler_exit_code"],
                    raw["stdin.bin"],
                    raw["stdout.bin"],
                    raw["stderr.bin"],
                    digest,
                )
            )
        if observed_sources != {s.path for s in self.sources}:
            raise ValueError(
                "compiler transcript does not cover the complete owned source population"
            )
        if {p.name for p in self.root.iterdir()} != expected_root or sorted(
            (self.root / "calls").iterdir()
        ) != directories:
            raise ValueError("compiler transcript population changed during collection")
        for directory, (identity, members) in directory_pins.items():
            if (
                _directory(directory) != identity
                or frozenset(p.name for p in directory.iterdir()) != members
            ):
                raise ValueError("compiler invocation directory changed during collection")
        for path, (maximum, pin, original_file_identity) in stream_pins.items():
            content, current = worker.file_snapshot(path, maximum)
            if current != original_file_identity or _sha(content) != pin:
                raise ValueError("compiler transcript changed during collection")
        self.require_inputs_unchanged()
        return tuple(result)


def prepare_solc_capture(
    *,
    root: Path,
    workspace: Path,
    compiler: Path,
    compiler_sha256: str,
    sources: tuple[FoundrySourceInput, ...],
    deadline_monotonic: float,
    limits: SolcCaptureLimits | None = None,
    helper_root: Path | None = None,
    owner_launch_receipt_path: Path | None = None,
) -> SolcCaptureSession:
    """Prepare an exact local compiler capture without a provider, fork, or tool install.

    The caller must use the returned launcher in the same prepared namespace and
    deadline, keep the original compiler identity separate, then collect all raw
    invocations. This does not qualify a backend or replace existing admission.
    """
    if os.name != "posix":
        raise ValueError("compiler capture requires the existing POSIX execution boundary")
    workspace_identity = _directory(workspace)
    if limits is not None and type(limits) is not SolcCaptureLimits:
        raise ValueError("compiler capture limits require the exact bounded type")
    bounds = SolcCaptureLimits.model_validate_json(
        (limits if limits is not None else SolcCaptureLimits()).model_dump_json(), strict=True
    )
    if (
        type(deadline_monotonic) not in {float, int}
        or not math.isfinite(deadline_monotonic)
        or not 0 < deadline_monotonic - time.monotonic() <= 3600
    ):
        raise ValueError("compiler capture requires a bounded live owner deadline")
    if not re.fullmatch(r"[0-9a-f]{64}", compiler_sha256):
        raise ValueError("compiler capture requires the exact compiler digest")
    if compiler.resolve(strict=True) != compiler or compiler.is_relative_to(workspace):
        raise ValueError("compiler must be an exact external executable, not audited source")
    if _sha(worker.file_bytes(compiler, 200_000_000)) != compiler_sha256 or not os.access(
        compiler, os.X_OK
    ):
        raise ValueError("compiler differs from its executable pin")
    if type(sources) is not tuple or not 1 <= len(sources) <= 10_000:
        raise ValueError("compiler sources must be a bounded original tuple")
    if any(type(source) is not FoundrySourceInput for source in sources):
        raise ValueError("compiler source input is not exact")
    if [s.path for s in sources] != sorted({s.path for s in sources}):
        raise ValueError("compiler source paths must be unique and canonical")
    for source in sources:
        worker._check_deadline(float(deadline_monotonic))
        if (
            type(source) is not FoundrySourceInput
            or _normalized_source_path(source.path) != source.path
        ):
            raise ValueError("compiler source input is not exact")
        CompilerSourceMap(source.content, source.content)
        if (
            worker.file_bytes(workspace / source.path, 100_000_000) != source.content
            or _sha(source.content) != source.source_sha256
        ):
            raise ValueError("compiler source differs from its original bytes")
    interpreter = Path(sys.executable).resolve(strict=True)
    if any(c.isspace() for c in str(interpreter)) or interpreter.is_relative_to(workspace):
        raise ValueError("compiler capture interpreter is not an exact supported external path")
    interpreter_sha256 = _sha(worker.file_bytes(interpreter, 200_000_000))
    runtime_file_pins = []
    runtime_bytes = 0
    for path in worker.stdlib_file_paths():
        worker._check_deadline(float(deadline_monotonic))
        if path.is_relative_to(workspace):
            raise ValueError("compiler runtime file comes from audited source")
        raw, identity = worker.file_snapshot(path, 16_000_000)
        runtime_bytes += len(raw)
        if runtime_bytes > 64_000_000:
            raise ValueError("compiler runtime files exceed their cumulative byte ceiling")
        runtime_file_pins.append((path, _sha(raw), identity))
    parent = root.parent
    _directory(parent)
    if (
        not root.is_absolute()
        or root.exists()
        or root.is_symlink()
        or root.is_relative_to(workspace)
        or workspace.is_relative_to(root)
    ):
        raise ValueError("compiler capture root must be new and outside the audited source")
    if owner_launch_receipt_path is not None and (
        not owner_launch_receipt_path.is_absolute()
        or owner_launch_receipt_path.parent != root.parent
        or owner_launch_receipt_path == root
        or owner_launch_receipt_path.exists()
        or owner_launch_receipt_path.is_symlink()
    ):
        raise ValueError("compiler owner receipt must be a new sibling of the capture root")
    root.mkdir(mode=0o700)
    (root / "calls").mkdir(mode=0o700)
    helper_root = root if helper_root is None else helper_root
    if helper_root != root:
        _directory(helper_root.parent)
        if (
            not helper_root.is_absolute()
            or helper_root.exists()
            or helper_root.is_symlink()
            or helper_root.is_relative_to(workspace)
            or workspace.is_relative_to(helper_root)
            or helper_root.is_relative_to(root)
            or root.is_relative_to(helper_root)
        ):
            raise ValueError("compiler immutable helpers must be new and separate from source/data")
        helper_root.mkdir(mode=0o700)
    worker_path = Path(worker.__file__).resolve(strict=True)
    worker_raw = worker.file_bytes(worker_path, 2_000_000)
    plan = {
        "schema_version": "1.0",
        "compiler_path": str(compiler),
        "compiler_sha256": compiler_sha256,
        "interpreter_path": str(interpreter),
        "interpreter_sha256": interpreter_sha256,
        "runtime_files": {str(path): pin for path, pin, _ in runtime_file_pins},
        "owner_launch_receipt_path": (
            None if owner_launch_receipt_path is None else str(owner_launch_receipt_path)
        ),
        "workspace": str(workspace),
        "deadline_monotonic": deadline_monotonic,
        "limits": bounds.model_dump(mode="json"),
        "source_sha256s": {
            s.path: [_sha(s.content), _sha(s.content.replace(b"\r\n", b"\n"))] for s in sources
        },
    }
    plan_raw = _json(plan)
    if len(plan_raw) > 2_000_000:
        raise ValueError("compiler capture plan exceeds its byte ceiling")
    launcher_raw = (
        _worker_bootstrap(interpreter, helper_root, worker_raw)
        + (
            f"sys.exit(namespace['capture_main']({str(root)!r}, {_sha(plan_raw)!r}, sys.argv[1:], "
            f"helper_root={str(helper_root)!r}))\n"
        ).encode()
    )
    inputs = {
        "plan.json": plan_raw,
        "worker.py": worker_raw,
        "solc-capture": launcher_raw,
    }
    for name, content in inputs.items():
        worker.write_bytes(helper_root / name, content)
    worker.write_bytes(root / "serial.lock", b"")
    (helper_root / "solc-capture").chmod(0o700)
    session = SolcCaptureSession(
        root,
        helper_root,
        helper_root / "solc-capture",
        compiler,
        compiler_sha256,
        interpreter,
        interpreter_sha256,
        workspace,
        sources,
        bounds,
        float(deadline_monotonic),
        tuple(sorted((name, _sha(raw)) for name, raw in inputs.items())),
        _directory(root),
        _directory(root / "calls"),
        workspace_identity,
        tuple(
            (path, maximum, worker.file_snapshot(path, maximum)[1])
            for path, maximum in (
                *((helper_root / name, 2_000_000) for name in inputs),
                (root / "serial.lock", 0),
                (compiler, 200_000_000),
                (interpreter, 200_000_000),
                *((workspace / source.path, 100_000_000) for source in sources),
            )
        ),
        tuple(runtime_file_pins),
        owner_launch_receipt_path,
    )
    session.require_inputs_unchanged()
    return session


def _worker_bootstrap(interpreter: Path, helper_root: Path, worker_raw: bytes) -> bytes:
    return (
        f"#!{interpreter} -IBS\n"
        "import hashlib, os, pathlib, stat, sys\n"
        f"root = pathlib.Path({str(helper_root)!r})\n"
        "driver = root / 'worker.py'\n"
        "if root.resolve(strict=True) != root: raise ValueError('capture root alias')\n"
        "fd = os.open(driver, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)\n"
        "with os.fdopen(fd, 'rb') as stream:\n"
        "    before = os.fstat(stream.fileno())\n"
        "    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise ValueError('capture worker type')\n"
        "    raw = stream.read(2000001)\n"
        "    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')\n"
        "    identities = {tuple(getattr(s, k) for k in fields) for s in (before, os.fstat(stream.fileno()), driver.lstat())}\n"
        "    if len(identities) != 1: raise ValueError('capture worker changed')\n"
        f"if len(raw) > 2000000 or hashlib.sha256(raw).hexdigest() != {_sha(worker_raw)!r}: raise ValueError('capture worker pin')\n"
        "namespace = {'__name__': 'owned_solc_capture_worker', '__file__': str(driver)}\n"
        "exec(compile(raw, str(driver), 'exec'), namespace)\n"
    ).encode()


@dataclass(frozen=True, slots=True)
class OwnedSolcCoverageLaunch:
    """Original owner's exact host-namespace launch; no backend or runtime authority."""

    session: SolcCaptureSession
    command: tuple[str, ...]
    receipt_path: Path
    plan_sha256: str
    forge_sha256: str
    input_files: tuple[tuple[Path, str, worker.FileIdentity], ...]

    def require_inputs_unchanged(self) -> None:
        self.session.require_inputs_unchanged()
        for path, pin, identity in self.input_files:
            worker._check_deadline(self.session.deadline_monotonic)
            raw, current = worker.file_snapshot(path, 200_000_000)
            if current != identity or _sha(raw) != pin:
                raise ValueError("owned coverage launch input changed or was replaced")

    def collect(self) -> tuple[CapturedSolcInvocation, ...]:
        """Require the original launch receipt and every original compiler invocation."""
        self.require_inputs_unchanged()
        raw, identity = worker.file_snapshot(self.receipt_path, 524_288)
        value = worker.decode(raw)
        if (
            type(value) is not dict
            or set(value) != {"launch_plan_sha256", "runtime"}
            or (value["launch_plan_sha256"] != self.plan_sha256)
        ):
            raise ValueError("coverage launch receipt differs from the original plan")
        self.session.require_runtime_observation(_json(value["runtime"]))
        records = self.session.collect()
        if worker.file_snapshot(self.receipt_path, 524_288) != (raw, identity):
            raise ValueError("coverage launch receipt changed during collection")
        self.require_inputs_unchanged()
        return records


def prepare_owned_coverage_launch(
    *,
    session: SolcCaptureSession,
    trusted_root: Path,
    forge: Path,
    forge_sha256: str,
    command: tuple[str, ...],
    receipt_path: Path,
) -> OwnedSolcCoverageLaunch:
    """Stage selected Forge once and exec it through pinned Python in the existing sandbox.

    The caller must keep trusted_root under the backend's existing read-only
    trusted-inputs tree, and all capture data under the original artifact ceiling.
    No namespace remapping, extra read root, network entitlement or tool install.
    """
    session.require_inputs_unchanged()
    _directory(trusted_root)
    if (
        trusted_root.name != "trusted-inputs"
        or not session.helper_root.is_relative_to(trusted_root)
        or session.root.is_relative_to(trusted_root)
        or not receipt_path.is_relative_to(session.root.parent)
        or receipt_path.is_relative_to(session.root)
        or receipt_path != session.owner_launch_receipt_path
        or not forge.is_absolute()
        or forge.resolve(strict=True) != forge
        or forge.is_relative_to(session.workspace)
        or not re.fullmatch(r"[0-9a-f]{64}", forge_sha256)
        or not os.access(forge, os.X_OK)
    ):
        raise ValueError("coverage owner requires exact separate trusted tool/helper/data paths")
    if (
        type(command) is not tuple
        or not 5 <= len(command) <= 128
        or any(type(argument) is not str or "\x00" in argument for argument in command)
        or len(_json(command)) > 65_536
        or command[:5] != (str(forge), "coverage", "--report", "debug", "--exclude-tests")
        or command.count("--use") != 1
        or command[command.index("--use") + 1] != str(session.launcher)
    ):
        raise ValueError("coverage owner command does not select its exact compiler capture")
    forge_raw, forge_identity = worker.file_snapshot(forge, 200_000_000)
    if _sha(forge_raw) != forge_sha256:
        raise ValueError("coverage owner Forge differs from its selected pin")
    staged = trusted_root / "coverage-forge"
    if not staged.exists():
        worker.write_bytes(staged, forge_raw)
        staged.chmod(0o500)
    if worker.file_bytes(staged, 200_000_000) != forge_raw or not os.access(staged, os.X_OK):
        raise ValueError("staged coverage Forge differs from its selected pin")
    owner_root = session.helper_root.parent
    worker_raw = worker.file_bytes(session.helper_root / "worker.py", 2_000_000)
    capture_plan = worker.decode(worker.file_bytes(session.helper_root / "plan.json", 2_000_000))
    actual_command = (str(staged), *command[1:])
    plan = {
        **capture_plan,
        "command": actual_command,
        "forge_sha256": forge_sha256,
        "receipt_path": str(receipt_path),
        "capture_launcher": str(session.launcher),
        "capture_launcher_sha256": _sha(worker.file_bytes(session.launcher, 2_000_000)),
    }
    plan_raw = _json(plan)
    if len(plan_raw) > 2_000_000:
        raise ValueError("coverage launch plan exceeds its byte ceiling")
    plan_path, launcher = owner_root / "launch.json", owner_root / "launch.py"
    worker.write_bytes(plan_path, plan_raw)
    worker.write_bytes(
        launcher,
        _worker_bootstrap(session.interpreter, session.helper_root, worker_raw)
        + (
            f"sys.exit(namespace['coverage_launch_main']({str(plan_path)!r}, {_sha(plan_raw)!r}))\n"
        ).encode(),
    )
    launch = OwnedSolcCoverageLaunch(
        session,
        (str(session.interpreter), "-IBS", str(launcher)),
        receipt_path,
        _sha(plan_raw),
        forge_sha256,
        (
            (forge, forge_sha256, forge_identity),
            *(
                (path, _sha(raw), identity)
                for path in (staged, plan_path, launcher)
                for raw, identity in (worker.file_snapshot(path, 200_000_000),)
            ),
        ),
    )
    launch.require_inputs_unchanged()
    return launch


@dataclass(frozen=True, slots=True)
class OwnedSolcDebuggerResult:
    """Original separate-process bytes; never a coverage or runtime-authority receipt."""

    launch_plan_sha256: str
    launch_receipt_sha256: str
    process_exit_code: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    dump: bytes = field(repr=False)
    compiler_transcripts: tuple[CapturedSolcInvocation, ...] = field(repr=False)
    observation: FoundryDebuggerObservation


@dataclass(frozen=True, slots=True)
class OwnedSolcDebuggerLaunch:
    """One fixed debugger invocation, distinct from the original coverage invocation."""

    session: SolcCaptureSession
    descriptor: RepositorySuiteTestDescriptor
    command: tuple[str, ...]
    receipt_path: Path
    stdout_path: Path
    stderr_path: Path
    dump_path: Path
    plan_sha256: str
    forge_sha256: str
    limits: FoundryDebuggerLimits
    input_files: tuple[tuple[Path, str, worker.FileIdentity], ...]

    def require_inputs_unchanged(self) -> None:
        self.session.require_inputs_unchanged()
        for path, pin, identity in self.input_files:
            worker._check_deadline(self.session.deadline_monotonic)
            raw, current = worker.file_snapshot(path, 200_000_000)
            if current != identity or _sha(raw) != pin:
                raise ValueError("owned debugger launch input changed or was replaced")

    def collect(self, *, process_exit_code: int) -> OwnedSolcDebuggerResult:
        """Collect after the owner has waited for its exact process and enforced live limits.

        The supplied terminal status is an owner observation, not an attestation.
        Retain every compiler call and recheck original files after bounded parsing.
        """
        from mmaudit.scanners.foundry_debugger import parse_forge_debugger_observation

        if type(process_exit_code) is not int or process_exit_code not in {0, 1}:
            raise ValueError("debugger process is missing a supported terminal exit status")
        self.require_inputs_unchanged()
        receipt = worker.file_snapshot(self.receipt_path, 524_288)
        value = worker.decode(receipt[0])
        if (
            type(value) is not dict
            or set(value)
            != {
                "launch_kind",
                "launch_plan_sha256",
                "descriptor_sha256",
                "runtime",
                "output_file_identities",
            }
            or value["launch_kind"] != "SEPARATE_FOUNDRY_DEBUGGER"
            or value["launch_plan_sha256"] != self.plan_sha256
            or value["descriptor_sha256"] != self.descriptor.descriptor_sha256
        ):
            raise ValueError("debugger launch receipt differs from the original selection/plan")
        self.session.require_runtime_observation(_json(value["runtime"]))
        paths = (self.stdout_path, self.stderr_path, self.dump_path)
        snapshots = tuple(worker.file_snapshot(p, self.limits.max_artifact_bytes) for p in paths)
        expected_objects = {
            name: (snapshot[1][0], snapshot[1][1][:4])
            for name, snapshot in zip(
                ("stdout_path", "stderr_path", "dump_path"), snapshots, strict=True
            )
        }
        if _json(value["output_file_identities"]) != _json(expected_objects):
            raise ValueError("debugger outputs differ from the original writer file objects")
        stdout, stderr, dump = (snapshot[0] for snapshot in snapshots)
        if len(stdout) + len(stderr) + len(dump) > self.limits.max_total_bytes:
            raise ValueError("debugger original outputs exceed their aggregate byte ceiling")
        records = self.session.collect()
        if (
            sum(len(c.stdin) + len(c.stdout) + len(c.stderr) for c in records)
            + sum(len(raw) for raw in (stdout, stderr, dump))
            > self.limits.max_total_bytes
        ):
            raise ValueError("debugger outputs and compiler streams exceed their aggregate ceiling")
        observation = parse_forge_debugger_observation(
            stdout,
            dump,
            compiler_transcripts=records,
            source_inputs=self.session.sources,
            descriptor=self.descriptor,
            process_exit_code=process_exit_code,
            limits=self.limits,
        )
        for path, snapshot in zip(paths, snapshots, strict=True):
            worker._check_deadline(self.session.deadline_monotonic)
            if worker.file_snapshot(path, self.limits.max_artifact_bytes) != snapshot:
                raise ValueError("debugger output changed during collection")
        if worker.file_snapshot(self.receipt_path, 524_288) != receipt:
            raise ValueError("debugger launch receipt changed during collection")
        if self.session.collect() != records:
            raise ValueError("debugger compiler population changed during collection")
        self.require_inputs_unchanged()
        return OwnedSolcDebuggerResult(
            self.plan_sha256,
            _sha(receipt[0]),
            process_exit_code,
            stdout,
            stderr,
            dump,
            records,
            observation,
        )


def prepare_owned_debugger_launch(
    *,
    session: SolcCaptureSession,
    trusted_root: Path,
    forge: Path,
    forge_sha256: str,
    descriptor: RepositorySuiteTestDescriptor,
    fuzz_seed: str,
    fuzz_runs: int,
    limits: FoundryDebuggerLimits | None = None,
    fork_url: str | None = None,
    fork_block_number: int | None = None,
) -> OwnedSolcDebuggerLaunch:
    """Build a separate exact debugger command in the existing read-only helper layout.

    The caller owns isolation, source/inventory admission, process termination and
    live artifact limits. No provider, sandbox expansion or coverage substitution.
    """
    from mmaudit.scanners.foundry_debugger import FoundryDebuggerLimits

    session.require_inputs_unchanged()
    _directory(trusted_root)
    if type(descriptor) is not RepositorySuiteTestDescriptor:
        raise ValueError("debugger owner requires an exact inventory descriptor")
    descriptor = RepositorySuiteTestDescriptor.model_validate(descriptor.model_dump(mode="json"))
    if (
        descriptor.framework is not RepositorySuiteFramework.FOUNDRY
        or descriptor.declaration_signature is None
        or descriptor.inventory_sha256 is None
    ):
        raise ValueError("debugger selection lacks its original inventory declaration")
    selected = PurePosixPath(descriptor.path)
    if descriptor.project_root != ".":
        selected = selected.relative_to(descriptor.project_root)
    if any(c in selected.as_posix() for c in "*?[]{}!") or not any(
        s.path == selected.as_posix() and s.source_sha256 == descriptor.source_sha256
        for s in session.sources
    ):
        raise ValueError("debugger selected source is not exact in its original compiler inputs")
    if limits is not None and type(limits) is not FoundryDebuggerLimits:
        raise ValueError("debugger limits require the exact bounded type")
    bounds = FoundryDebuggerLimits.model_validate_json(
        (FoundryDebuggerLimits() if limits is None else limits).model_dump_json(), strict=True
    )
    if (
        type(fuzz_seed) is not str
        or not re.fullmatch(r"0x[0-9a-f]{64}", fuzz_seed)
        or type(fuzz_runs) is not int
        or not 1 <= fuzz_runs <= 1_000_000
    ):
        raise ValueError("debugger fuzz selection requires exact bounded runs and seed")
    fork_arguments: tuple[str, ...] = ()
    if fork_url is not None or fork_block_number is not None:
        if (
            type(fork_url) is not str
            or type(fork_block_number) is not int
            or not 0 <= fork_block_number <= 2**64 - 1
            or not 1 <= local_fork_rpc_port(fork_url) <= 65_535
        ):
            raise ValueError("debugger fork selection requires an exact loopback/block pair")
        fork_arguments = ("--fork-url", fork_url, "--fork-block-number", str(fork_block_number))
    execution = session.root.parent
    receipt_path = execution / "launch-receipt.json"
    paths = (execution / "stdout.txt", execution / "stderr.txt", execution / "steps.json")
    if (
        trusted_root.name != "trusted-inputs"
        or not session.helper_root.is_relative_to(trusted_root)
        or execution.is_relative_to(trusted_root)
        or execution.is_relative_to(session.workspace)
        or session.owner_launch_receipt_path != receipt_path
        or not forge.is_absolute()
        or forge.resolve(strict=True) != forge
        or forge.is_relative_to(session.workspace)
        or not re.fullmatch(r"[0-9a-f]{64}", forge_sha256)
        or not os.access(forge, os.X_OK)
        or any(p.exists() or p.is_symlink() for p in (receipt_path, *paths))
    ):
        raise ValueError("debugger owner requires exact fresh separate tool/helper/output paths")
    forge_raw, forge_identity = worker.file_snapshot(forge, 200_000_000)
    if _sha(forge_raw) != forge_sha256:
        raise ValueError("debugger owner Forge differs from its selected pin")
    staged = trusted_root / "debugger-forge"
    if not staged.exists():
        worker.write_bytes(staged, forge_raw)
        staged.chmod(0o500)
    if worker.file_bytes(staged, 200_000_000) != forge_raw or not os.access(staged, os.X_OK):
        raise ValueError("staged debugger Forge differs from its selected pin")
    command = (
        str(staged),
        "test",
        "--root",
        str(session.workspace),
        "--match-path",
        selected.as_posix(),
        "--match-contract",
        f"^{re.escape(descriptor.suite_name)}$",
        "--match-test",
        f"^{re.escape(descriptor.declaration_signature)}$",
        "--debug",
        "--dump",
        str(paths[2]),
        "--json",
        "--use",
        str(session.launcher),
        "--offline",
        "--no-auto-detect",
        "--force",
        "--no-storage-caching",
        "--threads",
        "1",
        "--fuzz-seed",
        fuzz_seed,
        "--fuzz-runs",
        str(fuzz_runs),
        "--gas-price",
        str(DETERMINISTIC_FORK_GAS_PRICE_WEI),
        "--cache-path",
        str(execution / "cache"),
        "--out",
        str(execution / "out"),
        "--ast",
        *fork_arguments,
    )
    if len(_json(command)) > 65_536:
        raise ValueError("debugger command exceeds its byte ceiling")
    worker_raw = worker.file_bytes(session.helper_root / "worker.py", 2_000_000)
    capture_plan = worker.decode(worker.file_bytes(session.helper_root / "plan.json", 2_000_000))
    plan_raw = _json(
        {
            **capture_plan,
            "command": command,
            "launch_kind": "SEPARATE_FOUNDRY_DEBUGGER",
            "descriptor_sha256": descriptor.descriptor_sha256,
            "forge_sha256": forge_sha256,
            "receipt_path": str(receipt_path),
            "stdout_path": str(paths[0]),
            "stderr_path": str(paths[1]),
            "dump_path": str(paths[2]),
            "capture_launcher": str(session.launcher),
            "capture_launcher_sha256": _sha(worker.file_bytes(session.launcher, 2_000_000)),
        }
    )
    if len(plan_raw) > 2_000_000:
        raise ValueError("debugger launch plan exceeds its byte ceiling")
    owner = session.helper_root.parent
    plan_path, launcher = owner / "debugger-launch.json", owner / "debugger-launch.py"
    worker.write_bytes(plan_path, plan_raw)
    worker.write_bytes(
        launcher,
        _worker_bootstrap(session.interpreter, session.helper_root, worker_raw)
        + (
            f"sys.exit(namespace['debugger_launch_main']({str(plan_path)!r}, {_sha(plan_raw)!r}))\n"
        ).encode(),
    )
    launch = OwnedSolcDebuggerLaunch(
        session,
        descriptor,
        (str(session.interpreter), "-IBS", str(launcher)),
        receipt_path,
        *paths,
        _sha(plan_raw),
        forge_sha256,
        bounds,
        (
            (forge, forge_sha256, forge_identity),
            *(
                (p, _sha(raw), identity)
                for p in (staged, plan_path, launcher)
                for raw, identity in (worker.file_snapshot(p, 200_000_000),)
            ),
        ),
    )
    launch.require_inputs_unchanged()
    return launch
