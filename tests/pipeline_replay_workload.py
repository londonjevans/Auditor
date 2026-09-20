"""Versioned, nonauthorizing workload declarations for future local replay measurements."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import sys
from importlib.metadata import distributions
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tests.pipeline_replay_scaling_support import load_pipeline_replay_cases
from tests.scheduler_scaling_support import ROOT
from tests.unresolved_recovery_tree_support import TreeScenario

MAX_FILES = 4096
MAX_ENTRIES = 16384
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DECLARATION_BYTES = 2 * 1024 * 1024
MAX_PACKAGES = 256
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FIXED_INPUTS = (
    "pyproject.toml",
    "config/models.selection-plan.json",
    "tests/fixtures/pipeline_replay_scaling/cases.json",
    "tests/fixtures/unresolved_recovery_tree/cases.json",
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ReplayInput(_FrozenModel):
    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    byte_count: int = Field(ge=0, le=MAX_FILE_BYTES)

    @field_validator("path")
    @classmethod
    def relative_input_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or str(path) != value
            or ".." in path.parts
            or "\\" in value
            or not value.isascii()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(part.startswith(".env") for part in path.parts)
        ):
            raise ValueError("replay input path must be a plain relative non-secret path")
        return value


ReplayInputs = Annotated[tuple[ReplayInput, ...], Field(min_length=1, max_length=MAX_FILES)]


class ReplaySchedule(_FrozenModel):
    fresh_pipeline_samples: int = Field(default=1, ge=1, le=1)
    unprofiled_resume_samples: int = Field(default=3, ge=3, le=3)
    separate_profile_samples: int = Field(default=1, ge=1, le=1)
    serial_execution: bool = True
    verification_outside_timing: bool = True

    @model_validator(mode="after")
    def retain_original_schedule(self) -> Self:
        if not self.serial_execution or not self.verification_outside_timing:
            raise ValueError("replay measurements require serial, separately verified operations")
        return self


class ReplayEnvironment(_FrozenModel):
    python: str = Field(min_length=1, max_length=64)
    implementation: str = Field(min_length=1, max_length=64)
    system: str = Field(min_length=1, max_length=64)
    machine: str = Field(min_length=1, max_length=64)
    package_versions: tuple[tuple[str, str], ...] = Field(min_length=1, max_length=MAX_PACKAGES)

    @model_validator(mode="after")
    def exact_package_names(self) -> Self:
        names = tuple(name for name, _ in self.package_versions)
        if names != tuple(sorted(set(names))):
            raise ValueError("replay dependency version inventory is duplicated or unordered")
        if any(not value or len(value) > 128 for pair in self.package_versions for value in pair):
            raise ValueError("replay dependency version exceeds its bound")
        return self


class ReplayWorkload(_FrozenModel):
    schema_version: Literal["2.0"] = "2.0"
    scope: Literal["SYNTHETIC_ORIGINAL_PIPELINE_WORKLOAD_NOT_QUALIFICATION"] = (
        "SYNTHETIC_ORIGINAL_PIPELINE_WORKLOAD_NOT_QUALIFICATION"
    )
    cases: tuple[TreeScenario, TreeScenario]
    schedule: ReplaySchedule = Field(default_factory=ReplaySchedule)
    environment: ReplayEnvironment
    inputs: ReplayInputs

    @model_validator(mode="after")
    def exact_cases_and_inventory(self) -> Self:
        if self.cases != load_pipeline_replay_cases():
            raise ValueError("replay workload must retain both complete original cases")
        _require_sorted_inputs(self.inputs)
        return self


class ReplayDeclaration(_FrozenModel):
    schema_version: Literal["2.0"] = "2.0"
    scope: Literal["PREDECLARED_LOCAL_REPLAY_INPUTS_NOT_EXECUTION_EVIDENCE"] = (
        "PREDECLARED_LOCAL_REPLAY_INPUTS_NOT_EXECUTION_EVIDENCE"
    )
    workload: ReplayWorkload
    implementation_inputs: ReplayInputs

    @model_validator(mode="after")
    def disjoint_input_inventories(self) -> Self:
        _require_sorted_inputs(self.implementation_inputs)
        if (
            sum(item.byte_count for item in (*self.workload.inputs, *self.implementation_inputs))
            > MAX_TOTAL_BYTES
        ):
            raise ValueError("combined replay input bytes exceed their bound")
        if {item.path for item in self.workload.inputs} & {
            item.path for item in self.implementation_inputs
        }:
            raise ValueError("replay implementation and workload inventories overlap")
        return self

    @property
    def workload_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.workload)).hexdigest()

    @property
    def implementation_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(
                [item.model_dump(mode="json") for item in self.implementation_inputs],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self)).hexdigest()


def _canonical(value: BaseModel) -> bytes:
    return json.dumps(
        value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _require_sorted_inputs(inputs: tuple[ReplayInput, ...]) -> None:
    paths = tuple(item.path for item in inputs)
    if paths != tuple(sorted(set(paths))) or sum(i.byte_count for i in inputs) > MAX_TOTAL_BYTES:
        raise ValueError("replay input inventory is duplicated, unordered or oversized")


def _read_regular(path: Path, maximum: int) -> bytes:
    if any(part.startswith(".env") for part in path.parts):
        raise ValueError("replay declarations must not read secret environment files")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("replay input must be a bounded regular file")
        raw = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    if (
        len(raw) > maximum
        or len(raw) != before.st_size
        or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ValueError("replay input changed during bounded read")
    return raw


def _input_paths(root: Path, directory: str, *, python_only: bool) -> tuple[Path, ...]:
    pending = [root / directory]
    files: list[Path] = []
    seen = 0
    while pending:
        current = pending.pop()
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("replay input directories must not be links or special files")
        with os.scandir(current) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_ENTRIES:
                    raise ValueError("replay input traversal exceeds its bound")
                if entry.is_symlink():
                    raise ValueError("replay input tree must not contain links")
                if entry.is_dir(follow_symlinks=False):
                    if entry.name != "__pycache__":
                        pending.append(Path(entry.path))
                elif not python_only or entry.name.endswith(".py"):
                    files.append(Path(entry.path))
                    if len(files) > MAX_FILES:
                        raise ValueError("replay input file count exceeds its bound")
    return tuple(files)


def _snapshot(root: Path, paths: tuple[Path, ...]) -> tuple[ReplayInput, ...]:
    if not 1 <= len(set(paths)) <= MAX_FILES:
        raise ValueError("replay input file count exceeds its bound")
    result = []
    total = 0
    for path in sorted(set(paths)):
        relative = path.relative_to(root).as_posix()
        # Validate the name before reading, including a hostile .env fixture entry.
        ReplayInput(path=relative, sha256="0" * 64, byte_count=0)
        for parent in path.relative_to(root).parents:
            if not stat.S_ISDIR((root / parent).lstat().st_mode):
                raise ValueError("replay input parent must be an original directory")
        raw = _read_regular(path, MAX_FILE_BYTES)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("replay input bytes exceed their bound")
        result.append(
            ReplayInput(path=relative, sha256=hashlib.sha256(raw).hexdigest(), byte_count=len(raw))
        )
    return tuple(result)


def _package_versions() -> tuple[tuple[str, str], ...]:
    packages: list[tuple[str, str]] = []
    for package in distributions():
        if len(packages) >= MAX_PACKAGES:
            raise ValueError("replay dependency inventory exceeds its bound")
        name = package.metadata["Name"]
        if not name:
            raise ValueError("replay dependency name is missing")
        packages.append((re.sub(r"[-_.]+", "-", name).lower(), package.version))
    return tuple(sorted(packages))


def build_replay_declaration(root: Path = ROOT) -> ReplayDeclaration:
    """Snapshot declared inputs, not output sizes, timestamps, owner IDs or authority."""

    if not __debug__ or sys.flags.optimize:
        raise ValueError("replay measurements require enabled original assertions")
    if not root.is_absolute() or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("replay source root must be an absolute original directory")
    workload_paths = (
        *_input_paths(root, "tests", python_only=True),
        *_input_paths(root, "scripts", python_only=True),
        *_input_paths(root, "tests/fixtures/vulnerable_app", python_only=False),
        *(root / name for name in _FIXED_INPUTS),
    )
    cases = load_pipeline_replay_cases()
    if len(cases) != 2:
        raise ValueError("replay declaration requires the exact two-case workload")
    return ReplayDeclaration(
        workload=ReplayWorkload(
            cases=(cases[0], cases[1]),
            environment=ReplayEnvironment(
                python=platform.python_version(),
                implementation=platform.python_implementation(),
                system=platform.system(),
                machine=platform.machine(),
                package_versions=_package_versions(),
            ),
            inputs=_snapshot(root, workload_paths),
        ),
        implementation_inputs=_snapshot(root, _input_paths(root, "src", python_only=False)),
    )


def write_replay_declaration(path: Path, declaration: ReplayDeclaration) -> str:
    """Create a declaration once; never overwrite a prior selection or measurement."""

    raw = _canonical(declaration)
    if len(raw) > MAX_DECLARATION_BYTES:
        raise ValueError("replay declaration exceeds its byte bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def load_replay_declaration(path: Path, expected_sha256: str) -> ReplayDeclaration:
    """Read an exact caller-pinned v2 declaration; legacy observations cannot become one."""

    if _SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("replay declaration requires an exact SHA256")
    raw = _read_regular(path, MAX_DECLARATION_BYTES)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("replay declaration bytes differ from the caller pin")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("replay declaration contains duplicate fields")
            value[key] = item
        return value

    def no_constant(_value: str) -> None:
        raise ValueError("replay declaration contains nonfinite values")

    json.loads(raw, object_pairs_hook=unique, parse_constant=no_constant)
    declaration = ReplayDeclaration.model_validate_json(raw, strict=True)
    if raw != _canonical(declaration):
        raise ValueError("replay declaration must use its complete canonical representation")
    return declaration


def require_current_replay_inputs(declaration: ReplayDeclaration, root: Path = ROOT) -> None:
    """Refuse changed input bytes or inventories before the next measured operation."""

    if declaration != build_replay_declaration(root):
        raise ValueError("replay workload, implementation or environment changed after declaration")


def require_same_replay_workload(
    before: ReplayDeclaration, after: ReplayDeclaration
) -> tuple[str, ...]:
    """Match only predeclared workloads; return source differences, never execution credit."""

    if before.workload != after.workload:
        raise ValueError("replay declarations do not describe the same workload")
    left = {item.path: item for item in before.implementation_inputs}
    right = {item.path: item for item in after.implementation_inputs}
    return tuple(
        name for name in sorted(left.keys() | right.keys()) if left.get(name) != right.get(name)
    )
