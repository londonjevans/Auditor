"""Deterministic repeated-state repository-suite execution.

This module keeps matrix evidence separate from the qualifying scanner portfolio.
Only endpoint-free bridge snapshots and typed runtime observations may enter the
serialized result.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit

from mmaudit.config import (
    RepositoryCleanForkMatrixStateConfig,
    RepositoryForkMatrixStateConfig,
    RepositoryPinnedForkMatrixStateConfig,
    ReproductionConfig,
    SmartContractsConfig,
)
from mmaudit.models.schemas import (
    REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT,
    REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    ExecutionEvidenceKind,
    ForkRpcMethodCount,
    ForkRpcReadOnlyEgressEvidence,
    RepositoryCleanStateAttestationEvidence,
    RepositoryCodeExecutionState,
    RepositoryDifferentialClassification,
    RepositoryDifferentialRunStatus,
    RepositoryExecutionStateKind,
    RepositoryExecutionStateObservationStatus,
    RepositoryForkEgressStatus,
    RepositorySuiteDifferentialMatrix,
    RepositorySuiteDifferentialRun,
    RepositorySuiteExecutionStateEvidence,
    RepositorySuiteStateAttempt,
    RepositorySuiteStateWorkspaceCleanupEvidence,
    RepositorySuiteTestComparison,
    RepositorySuiteTestStateConsensus,
    RepositorySuiteWorkspaceLifecycleEvidence,
    RepositorySuiteWorkspaceLifecycleStatus,
    ScannerRun,
    ScannerStatus,
    SolidityProjectMetadata,
)
from mmaudit.scanners.base import ScannerIsolationBackend
from mmaudit.scanners.fork_rpc import (
    ForkRpcBindingError,
    ForkRpcUnavailableError,
    PinnedForkObservation,
    local_fork_rpc_port,
    observe_pinned_fork_rpc,
)
from mmaudit.scanners.foundry import FoundryForkScanner
from mmaudit.scanners.read_only_rpc import (
    ReadOnlyRpcBridge,
    ReadOnlyRpcBridgeSnapshot,
    ReadOnlyRpcTestScopeSnapshot,
)

_OBSERVATION_TIMEOUT_SECONDS = 5.0
_BRIDGE_SHUTDOWN_RESERVE_SECONDS = 1.0
_SCHEDULING_SLACK_SECONDS = 0.1
_ATTEMPT_CLEANUP_RESERVE_SECONDS = (
    _OBSERVATION_TIMEOUT_SECONDS
    + _BRIDGE_SHUTDOWN_RESERVE_SECONDS
    + REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
    + _SCHEDULING_SLACK_SECONDS
)
_URI_PATTERN = re.compile(r"(?i)\b(?:file|https?|wss?)://[^\s\"'<>]+")


def _directory_open_flags() -> int:
    """Return required descriptor-custody flags or fail before any execution."""

    directory = getattr(os, "O_DIRECTORY", None)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory, int) or directory == 0:
        raise _MatrixEvidenceError("Descriptor-relative directory custody is unavailable.")
    if not isinstance(no_follow, int) or no_follow == 0:
        raise _MatrixEvidenceError("No-follow directory custody is unavailable.")
    return os.O_RDONLY | directory | no_follow | int(getattr(os, "O_CLOEXEC", 0))


class _MatrixEvidenceError(Exception):
    """Expected trust-boundary failure converted to typed failed evidence."""


@dataclass
class _MonotonicClock:
    source: Callable[[], float]
    last: float | None = None

    def read(self) -> float:
        raw = self.source()
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise _MatrixEvidenceError("The monotonic clock returned a non-numeric value.")
        value = float(raw)
        if not math.isfinite(value):
            raise _MatrixEvidenceError("The monotonic clock returned a non-finite value.")
        if self.last is not None and value < self.last:
            raise _MatrixEvidenceError("The monotonic clock regressed during matrix execution.")
        self.last = value
        return value


def _bounded_monotonic() -> float:
    value = time.monotonic()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _MatrixEvidenceError("The workspace cleanup clock returned non-numeric data.")
    observed = float(value)
    if not math.isfinite(observed):
        raise _MatrixEvidenceError("The workspace cleanup clock returned non-finite data.")
    return observed


@dataclass
class _DirectoryRemovalBudget:
    """One fixed removal bound shared by a single owned directory tree."""

    started_at: float
    deadline: float
    entry_limit: int = REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT
    removed_entry_count: int = 0
    maximum_removed_depth: int = 0
    last_observed_at: float | None = None

    @classmethod
    def start(cls) -> _DirectoryRemovalBudget:
        started_at = _bounded_monotonic()
        return cls(
            started_at=started_at,
            deadline=started_at + REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
            last_observed_at=started_at,
        )

    def checkpoint(self) -> float:
        observed = _bounded_monotonic()
        if self.last_observed_at is not None and observed < self.last_observed_at:
            raise _MatrixEvidenceError("The workspace cleanup clock regressed.")
        self.last_observed_at = observed
        if observed > self.deadline:
            raise _MatrixEvidenceError("The workspace cleanup exceeded its time ceiling.")
        return observed

    def consume_entry(self, *, depth: int) -> None:
        if depth < 0 or depth > REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT:
            raise _MatrixEvidenceError("The workspace cleanup exceeded its depth ceiling.")
        self.removed_entry_count += 1
        if self.removed_entry_count > self.entry_limit:
            raise _MatrixEvidenceError("The workspace cleanup exceeded its entry ceiling.")
        self.maximum_removed_depth = max(self.maximum_removed_depth, depth)
        self.checkpoint()


@dataclass(frozen=True)
class _DirectoryDisposalObservation:
    """Path-free runtime facts for one removed, exclusively owned directory."""

    attempt_root_device: int
    attempt_root_inode: int
    removal_entry_limit: int
    removed_entry_count: int
    removal_depth_limit: int
    maximum_removed_depth: int
    removal_timeout_seconds: float
    removal_duration_seconds: float
    aggregate_removed_entry_count: int
    aggregate_removal_duration_seconds: float
    attempt_descriptor_closed: bool
    workspace_path_absent: bool
    attempt_path_absent: bool


@dataclass(frozen=True)
class _StateDisposalObservation:
    """One shared-budget observation over every directory owned by a state."""

    ordered_disposals: tuple[_DirectoryDisposalObservation, ...]
    owned_directory_count: int
    removal_entry_limit: int
    removed_entry_count: int
    removal_depth_limit: int
    maximum_removed_depth: int
    removal_timeout_seconds: float
    removal_duration_seconds: float
    all_owned_descriptors_closed: bool
    all_owned_paths_absent: bool


@dataclass
class _DirectoryCustody:
    """Open-descriptor custody for one private execution directory."""

    path: Path
    descriptor: int
    device: int
    inode: int
    name: str | None = None
    parent: _DirectoryCustody | None = field(default=None, repr=False)
    created_exclusively: bool = False
    closed: bool = False
    disposal_observation: _DirectoryDisposalObservation | None = None

    def assert_stable(self) -> None:
        if self.closed:
            raise _MatrixEvidenceError("A private workspace descriptor was already closed.")
        try:
            path_stat = self.path.lstat()
            descriptor_stat = os.fstat(self.descriptor)
            resolved = self.path.resolve(strict=True)
        except OSError as exc:
            raise _MatrixEvidenceError("A private workspace identity became unavailable.") from exc
        if (
            stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISDIR(path_stat.st_mode)
            or not stat.S_ISDIR(descriptor_stat.st_mode)
            or resolved != self.path
            or (path_stat.st_dev, path_stat.st_ino) != (self.device, self.inode)
            or (descriptor_stat.st_dev, descriptor_stat.st_ino) != (self.device, self.inode)
            or descriptor_stat.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor_stat.st_mode) & 0o077
        ):
            raise _MatrixEvidenceError("A private workspace failed ownership or identity checks.")

    def create_child(self, name: str) -> _DirectoryCustody:
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or (os.altsep is not None and os.altsep in name)
        ):
            raise _MatrixEvidenceError("A private workspace child name was invalid.")
        self.assert_stable()
        child_descriptor = -1
        created_metadata: os.stat_result | None = None
        try:
            os.mkdir(name, mode=0o700, dir_fd=self.descriptor)
            created_metadata = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            child_descriptor = os.open(name, _directory_open_flags(), dir_fd=self.descriptor)
            descriptor_stat = os.fstat(child_descriptor)
            if not _same_entry_identity(created_metadata, descriptor_stat):
                raise _MatrixEvidenceError("A private workspace child changed while it was opened.")
            child = _DirectoryCustody(
                path=self.path / name,
                descriptor=child_descriptor,
                device=descriptor_stat.st_dev,
                inode=descriptor_stat.st_ino,
                name=name,
                parent=self,
                created_exclusively=True,
            )
            child.assert_stable()
            return child
        except BaseException as exc:
            if child_descriptor >= 0:
                with suppress(OSError):
                    os.close(child_descriptor)
            if created_metadata is not None:
                with suppress(OSError):
                    current = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
                    if _same_entry_identity(current, created_metadata):
                        os.rmdir(name, dir_fd=self.descriptor)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(exc, _MatrixEvidenceError):
                raise
            raise _MatrixEvidenceError("A private workspace child could not be created.") from exc

    def remove_owned_tree(
        self,
        *,
        budget: _DirectoryRemovalBudget | None = None,
    ) -> _DirectoryDisposalObservation:
        """Remove exactly this direct child without following any nested link."""

        if (
            self.parent is None
            or self.name is None
            or not self.created_exclusively
            or self.disposal_observation is not None
        ):
            raise _MatrixEvidenceError("A workspace without exclusive child custody was removed.")
        removal_budget = budget or _DirectoryRemovalBudget.start()
        started_at = removal_budget.checkpoint()
        removed_before = removal_budget.removed_entry_count
        removal_error: BaseException | None = None
        closed_cleanly = False
        maximum_removed_depth = 0
        try:
            self.parent.assert_stable()
            self.assert_stable()
            maximum_removed_depth = _remove_custodied_contents(
                self.descriptor,
                root_device=self.device,
                depth=0,
                budget=removal_budget,
            )
            self.parent.assert_stable()
            self.assert_stable()
            removal_budget.consume_entry(depth=0)
            os.rmdir(self.name, dir_fd=self.parent.descriptor)
            removal_budget.checkpoint()
            try:
                os.stat(
                    self.name,
                    dir_fd=self.parent.descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise _MatrixEvidenceError("A removed workspace name remained present.")
        except BaseException as exc:
            removal_error = exc
        finally:
            closed_cleanly = self.close()
        if removal_error is not None:
            if isinstance(removal_error, (KeyboardInterrupt, SystemExit)):
                raise removal_error
            raise _MatrixEvidenceError(
                "A descriptor-anchored workspace could not be removed."
            ) from removal_error
        if not closed_cleanly:
            raise _MatrixEvidenceError("A removed workspace descriptor did not close cleanly.")
        finished_at = removal_budget.checkpoint()
        duration = finished_at - started_at
        observation = _DirectoryDisposalObservation(
            attempt_root_device=self.device,
            attempt_root_inode=self.inode,
            removal_entry_limit=removal_budget.entry_limit,
            removed_entry_count=(removal_budget.removed_entry_count - removed_before),
            removal_depth_limit=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT,
            maximum_removed_depth=maximum_removed_depth,
            removal_timeout_seconds=REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
            removal_duration_seconds=duration,
            aggregate_removed_entry_count=removal_budget.removed_entry_count,
            aggregate_removal_duration_seconds=(finished_at - removal_budget.started_at),
            attempt_descriptor_closed=True,
            workspace_path_absent=True,
            attempt_path_absent=True,
        )
        self.disposal_observation = observation
        return observation

    def remove_owned_empty(self) -> _DirectoryDisposalObservation:
        """Remove an owned direct child only when no untracked entry remains."""

        if self.closed:
            raise _MatrixEvidenceError("A private workspace descriptor was already closed.")
        try:
            with os.scandir(self.descriptor) as entries:
                if next(entries, None) is not None:
                    raise _MatrixEvidenceError(
                        "An owned matrix workspace retained an untracked child."
                    )
        except OSError as exc:
            raise _MatrixEvidenceError(
                "An owned matrix workspace could not be enumerated."
            ) from exc
        return self.remove_owned_tree()

    def close(self) -> bool:
        if self.closed:
            return True
        self.closed = True
        try:
            os.close(self.descriptor)
        except OSError:
            return False
        return True


def _same_entry_identity(
    left: os.stat_result,
    right: os.stat_result,
) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
    )


def _remove_custodied_contents(
    directory_descriptor: int,
    *,
    root_device: int,
    depth: int,
    budget: _DirectoryRemovalBudget,
) -> int:
    """Bounded descriptor-relative deletion that never follows a symlink."""

    if depth > REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT:
        raise _MatrixEvidenceError("The workspace cleanup exceeded its depth ceiling.")
    budget.checkpoint()
    try:
        with os.scandir(directory_descriptor) as iterator:
            names: list[str] = []
            for entry in iterator:
                if budget.removed_entry_count + len(names) + 1 > budget.entry_limit:
                    raise _MatrixEvidenceError("The workspace cleanup exceeded its entry ceiling.")
                budget.checkpoint()
                names.append(entry.name)
            names.sort()
    except OSError as exc:
        raise _MatrixEvidenceError("A workspace directory could not be enumerated.") from exc
    maximum_removed_depth = depth
    for name in names:
        budget.consume_entry(depth=depth + 1)
        maximum_removed_depth = max(maximum_removed_depth, depth + 1)
        try:
            before = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise _MatrixEvidenceError("A workspace entry identity became unavailable.") from exc
        if before.st_dev != root_device:
            raise _MatrixEvidenceError("A workspace entry crossed its owned filesystem boundary.")
        if stat.S_ISDIR(before.st_mode):
            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=directory_descriptor,
                )
                opened = os.fstat(child_descriptor)
                if not _same_entry_identity(before, opened):
                    raise _MatrixEvidenceError(
                        "A workspace directory changed while cleanup opened it."
                    )
                child_maximum_depth = _remove_custodied_contents(
                    child_descriptor,
                    root_device=root_device,
                    depth=depth + 1,
                    budget=budget,
                )
                maximum_removed_depth = max(maximum_removed_depth, child_maximum_depth)
                opened_after = os.fstat(child_descriptor)
                named_after = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if not _same_entry_identity(before, opened_after) or not _same_entry_identity(
                    before, named_after
                ):
                    raise _MatrixEvidenceError(
                        "A workspace directory changed before cleanup removed it."
                    )
                os.rmdir(name, dir_fd=directory_descriptor)
                budget.checkpoint()
            except OSError as exc:
                raise _MatrixEvidenceError(
                    "A workspace directory could not be removed safely."
                ) from exc
            finally:
                if child_descriptor >= 0:
                    with suppress(OSError):
                        os.close(child_descriptor)
            continue
        try:
            current = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if not _same_entry_identity(before, current):
                raise _MatrixEvidenceError("A workspace leaf changed before cleanup removed it.")
            os.unlink(name, dir_fd=directory_descriptor)
            budget.checkpoint()
        except OSError as exc:
            raise _MatrixEvidenceError("A workspace leaf could not be removed safely.") from exc
    return maximum_removed_depth


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _validate_existing_canonical_directory(path: Path) -> Path:
    absolute = _absolute_lexical(path)
    try:
        path_stat = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise _MatrixEvidenceError("A required custody directory was unavailable.") from exc
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or not stat.S_ISDIR(path_stat.st_mode)
        or resolved != absolute
    ):
        raise _MatrixEvidenceError("A custody directory was not canonical.")
    return absolute


def _open_private_root(
    private_root: Path,
    *,
    repository_root: Path,
    repository_exclusion_root: Path,
) -> _DirectoryCustody:
    root = _validate_existing_canonical_directory(repository_root)
    private = _absolute_lexical(private_root)
    exclusion = _absolute_lexical(repository_exclusion_root)
    if private == root or _path_is_within(root, private):
        raise _MatrixEvidenceError("The private workspace overlaps the repository root.")
    if _path_is_within(private, root):
        if (
            exclusion == root
            or not _path_is_within(exclusion, root)
            or not _path_is_within(private, exclusion)
        ):
            raise _MatrixEvidenceError(
                "The private workspace was not contained by the validated exclusion root."
            )
        if exclusion.exists() or exclusion.is_symlink():
            canonical_exclusion = _validate_existing_canonical_directory(exclusion)
            if canonical_exclusion != exclusion:
                raise _MatrixEvidenceError("The repository exclusion root was not canonical.")
        elif private != exclusion:
            raise _MatrixEvidenceError("The repository exclusion root was unavailable.")

    parent = _validate_existing_canonical_directory(private.parent)
    try:
        parent_descriptor = os.open(parent, _directory_open_flags())
    except OSError as exc:
        raise _MatrixEvidenceError("The private workspace parent could not be opened.") from exc
    try:
        parent_stat = os.fstat(parent_descriptor)
        if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o022:
            raise _MatrixEvidenceError("The private workspace parent was not safely owned.")
        if private.exists() or private.is_symlink():
            path_stat = private.lstat()
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
                raise _MatrixEvidenceError("The private workspace was not a direct directory.")
        else:
            os.mkdir(private.name, mode=0o700, dir_fd=parent_descriptor)
        descriptor = os.open(
            private.name,
            _directory_open_flags(),
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise _MatrixEvidenceError("The private workspace could not be opened safely.") from exc
    finally:
        os.close(parent_descriptor)
    descriptor_stat = os.fstat(descriptor)
    custody = _DirectoryCustody(
        path=private,
        descriptor=descriptor,
        device=descriptor_stat.st_dev,
        inode=descriptor_stat.st_ino,
    )
    try:
        custody.assert_stable()
    except BaseException:
        custody.close()
        raise
    return custody


class ForkMatrixScanner(Protocol):
    """Injected repository-suite scanner used by one matrix attempt."""

    def run(
        self,
        root: Path,
        private_dir: Path,
        timeout_seconds: float,
        *,
        backend: ScannerIsolationBackend | None = None,
        expected_version: str | None = None,
        expected_sha256: str | None = None,
    ) -> ScannerRun: ...


class ForkMatrixBridge(Protocol):
    """Small lifecycle surface required from a read-only RPC bridge."""

    @property
    def endpoint(self) -> str: ...

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def snapshot(self) -> ReadOnlyRpcBridgeSnapshot: ...

    def begin_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> None: ...

    def end_selected_test_scope(
        self,
        *,
        attempt_binding_sha256: str,
        selection_sha256: str,
        descriptor_sha256: str,
        sequence_index: int,
    ) -> ReadOnlyRpcTestScopeSnapshot: ...


class CleanStateLease(Protocol):
    """Trusted internally launched clean-chain lease."""

    @property
    def endpoint(self) -> str: ...

    def stop(self, deadline: float) -> None:
        """Stop the clean chain inside the caller's absolute deadline."""

    def attestation(self) -> RepositoryCleanStateAttestationEvidence:
        """Return endpoint-free evidence only after a clean stop."""


class CleanStateProvider(Protocol):
    """Injected clean-chain launcher; target repositories cannot provide it."""

    def start(
        self,
        config: RepositoryCleanForkMatrixStateConfig,
        repository_root: Path,
        private_root: Path,
        absolute_deadline: float,
    ) -> CleanStateLease: ...


class ForkStateObserver(Protocol):
    def __call__(
        self,
        endpoint: str,
        *,
        expected_chain_id: int | None,
        pinned_block_number: int | None,
        timeout_seconds: float,
    ) -> PinnedForkObservation: ...


class ForkBridgeFactory(Protocol):
    def __call__(
        self,
        origin_endpoint: str,
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
        timeout_seconds: float,
    ) -> ForkMatrixBridge: ...


class ForkScannerFactory(Protocol):
    def __call__(
        self,
        config: SmartContractsConfig,
        *,
        reproduction: ReproductionConfig,
        projects: Sequence[SolidityProjectMetadata],
        allow_fork_probing: bool,
        expected_repository_sha256: str,
        repository_exclusion_root: Path,
        fork_rpc_url_override: str,
        fork_rpc_scope_recorder: ForkMatrixBridge,
        attempt_binding_sha256: str,
    ) -> ForkMatrixScanner: ...


def _default_bridge_factory(
    origin_endpoint: str,
    *,
    expected_chain_id: int,
    pinned_block_number: int,
    pinned_block_hash: str,
    timeout_seconds: float,
) -> ForkMatrixBridge:
    return ReadOnlyRpcBridge(
        origin_endpoint,
        expected_chain_id=expected_chain_id,
        pinned_block_number=pinned_block_number,
        pinned_block_hash=pinned_block_hash,
        timeout_seconds=timeout_seconds,
        shutdown_timeout_seconds=min(
            _BRIDGE_SHUTDOWN_RESERVE_SECONDS,
            timeout_seconds,
        ),
    )


def _default_scanner_factory(
    config: SmartContractsConfig,
    *,
    reproduction: ReproductionConfig,
    projects: Sequence[SolidityProjectMetadata],
    allow_fork_probing: bool,
    expected_repository_sha256: str,
    repository_exclusion_root: Path,
    fork_rpc_url_override: str,
    fork_rpc_scope_recorder: ForkMatrixBridge,
    attempt_binding_sha256: str,
) -> ForkMatrixScanner:
    return FoundryForkScanner(
        config,
        reproduction=reproduction,
        projects=projects,
        allow_fork_probing=allow_fork_probing,
        expected_repository_sha256=expected_repository_sha256,
        repository_exclusion_root=repository_exclusion_root,
        fork_rpc_url_override=fork_rpc_url_override,
        fork_rpc_scope_recorder=fork_rpc_scope_recorder,
        attempt_binding_sha256=attempt_binding_sha256,
    )


@dataclass(frozen=True)
class ForkMatrixDependencies:
    """Trusted dependencies injected so unit tests never bind sockets or execute tools."""

    observer: ForkStateObserver = observe_pinned_fork_rpc
    bridge_factory: ForkBridgeFactory = _default_bridge_factory
    scanner_factory: ForkScannerFactory = _default_scanner_factory
    clean_state_provider: CleanStateProvider | None = None
    environment: Mapping[str, str] | None = None
    monotonic: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    nonce: Callable[[], str] = field(default=lambda: secrets.token_hex(32))


@dataclass
class _RawAttempt:
    index: int
    workspace_identity_sha256: str
    workspace_freshness_attestation_sha256: str
    attempt_root_device: int
    attempt_root_inode: int
    scanner_run: ScannerRun
    snapshot: ReadOnlyRpcBridgeSnapshot | None = None
    workspace_disposal: _DirectoryDisposalObservation | None = None


@dataclass
class _RawState:
    config: RepositoryForkMatrixStateConfig
    attempts: list[_RawAttempt]
    observations: list[PinnedForkObservation]
    observation_status: RepositoryExecutionStateObservationStatus
    observation_detail: str | None
    clean_attestation: RepositoryCleanStateAttestationEvidence | None = None
    workspace_cleanup: _StateDisposalObservation | None = None


@dataclass
class _StateLifecycle:
    clean_lease: CleanStateLease | None = None
    clean_stop_attempted: bool = False
    directories: list[_DirectoryCustody] = field(default_factory=list)
    disposal_observations: dict[
        tuple[int, int],
        _DirectoryDisposalObservation,
    ] = field(default_factory=dict)
    aggregate_disposal: _StateDisposalObservation | None = None


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


def _unavailable_run(
    detail: str,
    *,
    now: Callable[[], datetime],
    status: ScannerStatus = ScannerStatus.UNAVAILABLE,
) -> ScannerRun:
    observed_at = now()
    return ScannerRun(
        scanner="foundry_fork",
        status=status,
        execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
        started_at=observed_at,
        finished_at=observed_at,
        duration_seconds=0,
        error=detail,
    )


def _reseal_run(
    run: ScannerRun,
    *,
    egress: ForkRpcReadOnlyEgressEvidence | None,
) -> ScannerRun:
    """Attach endpoint-free egress, discard private paths, and rebind the observation."""

    payload = run.model_dump(mode="python")
    payload["raw_output_path"] = None
    payload["fork_rpc_egress"] = egress
    payload["execution_observation_sha256"] = None
    provisional = ScannerRun.model_validate(payload)
    payload["execution_observation_sha256"] = provisional.expected_execution_observation_sha256()
    return ScannerRun.model_validate(payload)


def _decoded_forms(value: str) -> tuple[str, ...]:
    forms = [value]
    for _ in range(16):
        decoded = unquote(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return tuple(forms)


def _uri_is_loopback(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return True
    if hostname is None:
        return False
    normalized = hostname.casefold().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    if normalized == "::1" or normalized.startswith("127."):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _retains_prohibited_private_reference(
    value: object,
    *,
    prohibited_paths: tuple[Path, ...],
    prohibited_endpoints: tuple[str, ...],
) -> bool:
    if isinstance(value, str):
        forms = _decoded_forms(value)
        if len(forms) == 17 and unquote(forms[-1]) != forms[-1]:
            return True
        prohibited_path_forms = tuple(str(path).casefold() for path in prohibited_paths)
        for form in forms:
            casefolded = form.casefold()
            if any(path in casefolded for path in prohibited_path_forms):
                return True
            if any(endpoint.casefold() in casefolded for endpoint in prohibited_endpoints):
                return True
            if any(_uri_is_loopback(match.group(0)) for match in _URI_PATTERN.finditer(form)):
                return True
        return False
    if isinstance(value, Mapping):
        return any(
            _retains_prohibited_private_reference(
                key,
                prohibited_paths=prohibited_paths,
                prohibited_endpoints=prohibited_endpoints,
            )
            or _retains_prohibited_private_reference(
                item,
                prohibited_paths=prohibited_paths,
                prohibited_endpoints=prohibited_endpoints,
            )
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return any(
            _retains_prohibited_private_reference(
                item,
                prohibited_paths=prohibited_paths,
                prohibited_endpoints=prohibited_endpoints,
            )
            for item in value
        )
    return False


def _remove_ephemeral_run_data(
    run: ScannerRun,
    *,
    origin_endpoint: str,
    bridge_endpoint: str,
    private_root: Path,
    repository_exclusion_root: Path,
    attempt_dir: Path,
    matrix_root: Path,
) -> ScannerRun:
    """Reject evidence that retains an endpoint or private workspace identity."""

    sanitized = _reseal_run(run, egress=None)
    prohibited_paths = tuple(
        dict.fromkeys(
            (
                _absolute_lexical(private_root),
                _absolute_lexical(repository_exclusion_root),
                _absolute_lexical(matrix_root),
                _absolute_lexical(attempt_dir),
            )
        )
    )
    if _retains_prohibited_private_reference(
        sanitized.model_dump(mode="python"),
        prohibited_paths=prohibited_paths,
        prohibited_endpoints=(origin_endpoint, bridge_endpoint),
    ):
        return _unavailable_run(
            "The matrix attempt retained prohibited ephemeral execution data.",
            now=lambda: sanitized.finished_at,
            status=ScannerStatus.FAILED,
        )
    return sanitized


def _baseline_limitation(
    run: ScannerRun,
    *,
    repository_sha256: str,
    smart_contracts: SmartContractsConfig,
    backend: ScannerIsolationBackend,
) -> str | None:
    selection = run.repository_suite_selection
    policy = run.repository_suite_execution_policy
    if (
        run.scanner != "foundry_fork"
        or run.status is not ScannerStatus.SUCCESS
        or run.execution_evidence is not ExecutionEvidenceKind.REAL
        or run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
        or run.isolation_backend is None
        or run.isolation_attestation_sha256 is None
        or not run.machine_output_validated
        or not run.version
        or run.executable_sha256 is None
        or run.execution_observation_sha256 is None
        or not run.execution_observation_sha256_is_valid()
        or selection is None
        or policy is None
        or not selection.tests
    ):
        return "The qualifying baseline Foundry execution evidence was incomplete."
    if (
        selection.repository_sha256 != repository_sha256
        or selection.configuration_sha256 != smart_contracts.repository_suite.stable_hash()
        or policy.selection_sha256 != selection.selection_sha256
        or policy.selection_configuration_sha256 != selection.configuration_sha256
        or policy.fuzz_seed != smart_contracts.repository_suite.fuzz_seed
        or policy.fuzz_runs != smart_contracts.foundry_fuzz_runs
        or policy.invariant_runs != smart_contracts.foundry_invariant_runs
        or policy.per_test_timeout_seconds
        != smart_contracts.repository_suite.per_test_timeout_seconds
        or policy.total_timeout_seconds != smart_contracts.repository_suite.total_timeout_seconds
        or policy.max_output_bytes_per_test
        != smart_contracts.repository_suite.max_output_bytes_per_test
        or policy.max_total_output_bytes != smart_contracts.repository_suite.max_total_output_bytes
        or policy.tool_version != run.version
        or policy.tool_sha256 != run.executable_sha256
        or policy.compiler_version is None
        or policy.compiler_sha256 is None
        or (
            smart_contracts.solc_version is not None
            and policy.compiler_version != smart_contracts.solc_version
        )
        or (
            smart_contracts.solc_sha256 is not None
            and policy.compiler_sha256 != smart_contracts.solc_sha256
        )
        or policy.isolation_backend != run.isolation_backend
        or policy.isolation_backend != backend.name
        or policy.isolation_attestation_sha256 != run.isolation_attestation_sha256
    ):
        return "The qualifying baseline Foundry identity differed from the matrix configuration."
    descriptor_hashes = {descriptor.descriptor_sha256 for descriptor in selection.tests}
    executions_by_descriptor = {
        execution.descriptor_sha256: execution for execution in run.repository_test_executions
    }
    if set(executions_by_descriptor) != descriptor_hashes or any(
        execution.execution_evidence is not ExecutionEvidenceKind.REAL
        or not execution.machine_output_validated
        for execution in executions_by_descriptor.values()
    ):
        return "The qualifying baseline did not bind every selected test to real machine output."
    return None


class RepositoryForkMatrixRunner:
    """Execute a configured clean-versus-pinned matrix under one absolute deadline."""

    def __init__(
        self,
        smart_contracts: SmartContractsConfig,
        reproduction: ReproductionConfig,
        *,
        dependencies: ForkMatrixDependencies | None = None,
    ) -> None:
        self.smart_contracts = smart_contracts
        self.reproduction = reproduction
        self.dependencies = dependencies or ForkMatrixDependencies()

    def run(
        self,
        root: Path,
        private_root: Path,
        *,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: ScannerIsolationBackend,
        baseline_run: ScannerRun,
        absolute_deadline: float,
    ) -> RepositorySuiteDifferentialRun | None:
        suite = self.smart_contracts.repository_suite
        configured_states = tuple(suite.fork_matrix_states)
        if not configured_states:
            return None
        configuration_sha256 = suite.stable_hash()
        requested_state_ids = tuple(state.state_id for state in configured_states)
        limitations: list[str] = []

        def failed(detail: str) -> RepositorySuiteDifferentialRun:
            failure_limitations = tuple(dict.fromkeys((*limitations, detail)))
            return RepositorySuiteDifferentialRun.sealed(
                status=RepositoryDifferentialRunStatus.FAILED,
                configuration_sha256=configuration_sha256,
                requested_state_ids=requested_state_ids,
                required_repetitions=suite.fork_matrix_repetitions,
                matrix=None,
                limitations=failure_limitations,
            )

        baseline_error = _baseline_limitation(
            baseline_run,
            repository_sha256=repository_sha256,
            smart_contracts=self.smart_contracts,
            backend=backend,
        )
        if baseline_error is not None:
            return failed(baseline_error)
        try:
            _directory_open_flags()
        except _MatrixEvidenceError as exc:
            return failed(str(exc))
        if self.dependencies.clean_state_provider is None:
            return failed("The trusted internal clean-state launcher was unavailable.")
        if (
            isinstance(absolute_deadline, bool)
            or not isinstance(absolute_deadline, (int, float))
            or not math.isfinite(float(absolute_deadline))
        ):
            return failed("The differential matrix deadline was not a finite numeric value.")
        deadline = float(absolute_deadline)
        clock = _MonotonicClock(self.dependencies.monotonic)
        try:
            if clock.read() >= deadline:
                return failed("The differential matrix deadline expired before execution.")
        except Exception:
            return failed("The differential matrix clock failed validation before execution.")

        private_custody: _DirectoryCustody | None = None
        matrix_custody: _DirectoryCustody | None = None
        raw_states: list[_RawState] = []
        states: tuple[RepositorySuiteExecutionStateEvidence, ...] = ()
        state_execution_failed = False
        custody_cleanup_failed = False
        try:
            private_custody = _open_private_root(
                private_root,
                repository_root=root,
                repository_exclusion_root=repository_exclusion_root,
            )
            matrix_nonce = self.dependencies.nonce()
            if (
                not matrix_nonce
                or len(matrix_nonce) > 256
                or any(ord(character) < 33 or ord(character) > 126 for character in matrix_nonce)
            ):
                raise _MatrixEvidenceError(
                    "The fresh-workspace nonce source returned invalid data."
                )
            matrix_nonce_sha256 = hashlib.sha256(matrix_nonce.encode("utf-8")).hexdigest()
            matrix_custody = private_custody.create_child(
                f"repository-fork-matrix-{matrix_nonce_sha256[:16]}"
            )
            for state_config in configured_states:
                raw_states.append(
                    self._execute_state(
                        state_config,
                        root=root,
                        private_root=private_custody.path,
                        matrix_custody=matrix_custody,
                        matrix_nonce_sha256=matrix_nonce_sha256,
                        projects=projects,
                        repository_sha256=repository_sha256,
                        repository_exclusion_root=repository_exclusion_root,
                        backend=backend,
                        absolute_deadline=deadline,
                        clock=clock,
                        expected_forge_version=baseline_run.version,
                        expected_forge_sha256=baseline_run.executable_sha256,
                        limitations=limitations,
                    )
                )
            private_custody.assert_stable()
            matrix_custody.assert_stable()
            states = tuple(
                self._seal_state(raw_state)
                for raw_state in sorted(raw_states, key=lambda item: item.config.state_id)
            )
        except Exception:
            state_execution_failed = True
        finally:
            if matrix_custody is not None:
                try:
                    matrix_custody.remove_owned_empty()
                except BaseException:
                    custody_cleanup_failed = True
                    if not matrix_custody.closed:
                        matrix_custody.close()
            if private_custody is not None and not private_custody.close():
                custody_cleanup_failed = True

        if state_execution_failed:
            return failed("The differential state evidence failed closed.")
        if custody_cleanup_failed:
            return failed("The differential workspace custody did not close cleanly.")
        if not raw_states:
            return failed("The differential matrix deadline expired before execution.")
        snapshots = [
            attempt.snapshot
            for raw_state in raw_states
            for attempt in raw_state.attempts
            if attempt.snapshot is not None
        ]
        if not snapshots:
            return failed("No stopped read-only RPC bridge produced matrix evidence.")
        policy_hashes = tuple(sorted({snapshot.policy_sha256 for snapshot in snapshots}))
        fork_rpc_policy_sha256 = policy_hashes[0]
        if len(policy_hashes) != 1:
            limitations.append("Read-only RPC bridge policies differed across matrix attempts.")

        selection = baseline_run.repository_suite_selection
        policy = baseline_run.repository_suite_execution_policy
        assert selection is not None
        assert policy is not None
        states_by_id = {state.state_id: state for state in states}
        attempts: list[RepositorySuiteStateAttempt] = []
        for raw_state in sorted(raw_states, key=lambda item: item.config.state_id):
            state = states_by_id[raw_state.config.state_id]
            for raw_attempt in sorted(raw_state.attempts, key=lambda item: item.index):
                egress: ForkRpcReadOnlyEgressEvidence | None = None
                if (
                    raw_attempt.snapshot is not None
                    and raw_attempt.scanner_run.repository_suite_execution_policy is not None
                ):
                    try:
                        egress = fork_rpc_egress_from_snapshot(raw_attempt.snapshot, state)
                    except (TypeError, ValueError):
                        limitations.append(
                            f"State {state.state_id} had bridge evidence that did not bind "
                            "its final state identity."
                        )
                run = _reseal_run(raw_attempt.scanner_run, egress=egress)
                disposal = raw_attempt.workspace_disposal
                if disposal is None:
                    return failed(
                        "A differential attempt lacked verified workspace disposal evidence."
                    )
                workspace_copy = run.repository_suite_workspace_copy
                lifecycle_status = (
                    RepositorySuiteWorkspaceLifecycleStatus.VALIDATED
                    if (
                        run.status is ScannerStatus.SUCCESS
                        and workspace_copy is not None
                        and run.execution_observation_sha256 is not None
                    )
                    else RepositorySuiteWorkspaceLifecycleStatus.DISPOSED_UNCREDITED
                )
                try:
                    lifecycle = RepositorySuiteWorkspaceLifecycleEvidence.sealed(
                        status=lifecycle_status,
                        attempt_binding_sha256=raw_attempt.workspace_identity_sha256,
                        selection_sha256=selection.selection_sha256,
                        repository_sha256=repository_sha256,
                        workspace_copy_evidence_sha256=(
                            workspace_copy.copy_evidence_sha256
                            if workspace_copy is not None
                            else None
                        ),
                        scanner_execution_observation_sha256=(run.execution_observation_sha256),
                        freshness_attestation_sha256=(
                            raw_attempt.workspace_freshness_attestation_sha256
                        ),
                        disposal_policy_sha256=(REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256),
                        attempt_root_device=disposal.attempt_root_device,
                        attempt_root_inode=disposal.attempt_root_inode,
                        attempt_root_created_exclusively=True,
                        attempt_root_direct_child=True,
                        removal_entry_limit=disposal.removal_entry_limit,
                        removed_entry_count=disposal.removed_entry_count,
                        removal_depth_limit=disposal.removal_depth_limit,
                        maximum_removed_depth=disposal.maximum_removed_depth,
                        removal_timeout_seconds=disposal.removal_timeout_seconds,
                        removal_duration_seconds=disposal.removal_duration_seconds,
                        attempt_descriptor_closed=disposal.attempt_descriptor_closed,
                        workspace_path_absent=disposal.workspace_path_absent,
                        attempt_path_absent=disposal.attempt_path_absent,
                        private_path_retained=False,
                        rpc_endpoint_retained=False,
                    )
                    attempt = RepositorySuiteStateAttempt.sealed(
                        state_id=state.state_id,
                        state_sha256=state.state_sha256,
                        attempt_index=raw_attempt.index,
                        workspace_kind="fresh_disposable_copy",
                        workspace_identity_sha256=raw_attempt.workspace_identity_sha256,
                        workspace_freshness_attestation_sha256=(
                            raw_attempt.workspace_freshness_attestation_sha256
                        ),
                        workspace_disposal_policy_sha256=(
                            REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256
                        ),
                        workspace_lifecycle=lifecycle,
                        fork_rpc_egress_sha256=(
                            egress.evidence_sha256 if egress is not None else None
                        ),
                        scanner_run=run,
                    )
                except (TypeError, ValueError):
                    return failed("A differential attempt workspace lifecycle failed validation.")
                attempts.append(attempt)

        descriptor_sha256s = tuple(
            sorted(descriptor.descriptor_sha256 for descriptor in selection.tests)
        )
        execution_configuration_sha256 = (
            RepositorySuiteDifferentialMatrix.execution_configuration_sha256_for_policy(policy)
        )
        attempts_tuple = tuple(
            sorted(attempts, key=lambda item: (item.state_id, item.attempt_index))
        )
        state_workspace_cleanups: list[RepositorySuiteStateWorkspaceCleanupEvidence] = []
        for raw_state in sorted(raw_states, key=lambda item: item.config.state_id):
            state = states_by_id[raw_state.config.state_id]
            aggregate = raw_state.workspace_cleanup
            if aggregate is None:
                return failed("A differential state lacked aggregate workspace disposal.")
            state_attempts = tuple(
                attempt for attempt in attempts_tuple if attempt.state_id == state.state_id
            )
            lifecycles_by_root = {
                (
                    attempt.workspace_lifecycle.attempt_root_device,
                    attempt.workspace_lifecycle.attempt_root_inode,
                ): attempt.workspace_lifecycle
                for attempt in state_attempts
            }
            cleanup_sequence: list[str] = []
            cumulative_entries: list[int] = []
            cumulative_durations: list[float] = []
            for disposal in aggregate.ordered_disposals:
                matched_lifecycle = lifecycles_by_root.get(
                    (disposal.attempt_root_device, disposal.attempt_root_inode)
                )
                if matched_lifecycle is None:
                    continue
                cleanup_sequence.append(matched_lifecycle.lifecycle_evidence_sha256)
                cumulative_entries.append(disposal.aggregate_removed_entry_count)
                cumulative_durations.append(disposal.aggregate_removal_duration_seconds)
            try:
                state_workspace_cleanups.append(
                    RepositorySuiteStateWorkspaceCleanupEvidence.sealed(
                        state_id=state.state_id,
                        state_sha256=state.state_sha256,
                        disposal_policy_sha256=(REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256),
                        attempt_cleanup_sequence_lifecycle_sha256s=tuple(cleanup_sequence),
                        attempt_cumulative_removed_entry_counts=tuple(cumulative_entries),
                        attempt_cumulative_removal_duration_seconds=tuple(cumulative_durations),
                        owned_directory_count=aggregate.owned_directory_count,
                        auxiliary_directory_count=(
                            aggregate.owned_directory_count - len(state_attempts)
                        ),
                        removal_entry_limit=aggregate.removal_entry_limit,
                        removed_entry_count=aggregate.removed_entry_count,
                        removal_depth_limit=aggregate.removal_depth_limit,
                        maximum_removed_depth=aggregate.maximum_removed_depth,
                        removal_timeout_seconds=aggregate.removal_timeout_seconds,
                        removal_duration_seconds=aggregate.removal_duration_seconds,
                        all_owned_descriptors_closed=(aggregate.all_owned_descriptors_closed),
                        all_owned_paths_absent=aggregate.all_owned_paths_absent,
                        private_path_retained=False,
                        rpc_endpoint_retained=False,
                    )
                )
            except (TypeError, ValueError):
                return failed(
                    "A differential state aggregate workspace lifecycle failed validation."
                )
        state_workspace_cleanup_tuple = tuple(state_workspace_cleanups)
        matrix_shell = RepositorySuiteDifferentialMatrix.model_construct(
            repository_sha256=repository_sha256,
            selection_sha256=selection.selection_sha256,
            selection_configuration_sha256=selection.configuration_sha256,
            descriptor_sha256s=descriptor_sha256s,
            required_repetitions=suite.fork_matrix_repetitions,
            fuzz_seed=suite.fuzz_seed,
            execution_configuration_sha256=execution_configuration_sha256,
            fork_rpc_policy_sha256=fork_rpc_policy_sha256,
            states=states,
            attempts=attempts_tuple,
            state_workspace_cleanups=state_workspace_cleanup_tuple,
            state_consensuses=(),
            comparisons=(),
            safety_claim=False,
            matrix_sha256="0" * 64,
        )
        consensuses: list[RepositorySuiteTestStateConsensus] = []
        for state in states:
            state_attempts = tuple(
                attempt for attempt in attempts_tuple if attempt.state_id == state.state_id
            )
            for descriptor_sha256 in descriptor_sha256s:
                (
                    consensus_status,
                    observed_status,
                    machine_result_sha256,
                    reasons,
                ) = matrix_shell._expected_consensus(
                    state,
                    state_attempts,
                    descriptor_sha256,
                )
                consensuses.append(
                    RepositorySuiteTestStateConsensus.sealed(
                        state_id=state.state_id,
                        state_sha256=state.state_sha256,
                        descriptor_sha256=descriptor_sha256,
                        status=consensus_status,
                        attempt_sha256s=tuple(
                            sorted(attempt.attempt_sha256 for attempt in state_attempts)
                        ),
                        observed_status=observed_status,
                        machine_result_sha256=machine_result_sha256,
                        inconclusive_reasons=reasons,
                    )
                )
        consensus_tuple = tuple(
            sorted(
                consensuses,
                key=lambda item: (item.state_id, item.descriptor_sha256),
            )
        )
        consensus_by_key = {
            (consensus.state_id, consensus.descriptor_sha256): consensus
            for consensus in consensus_tuple
        }
        clean = next(
            state for state in states if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL
        )
        comparisons: list[RepositorySuiteTestComparison] = []
        for pinned in (
            state for state in states if state.kind is RepositoryExecutionStateKind.PINNED_FORK
        ):
            for descriptor_sha256 in descriptor_sha256s:
                clean_consensus = consensus_by_key[(clean.state_id, descriptor_sha256)]
                pinned_consensus = consensus_by_key[(pinned.state_id, descriptor_sha256)]
                classification, direction = RepositorySuiteDifferentialMatrix._expected_comparison(
                    clean_consensus,
                    pinned_consensus,
                )
                comparisons.append(
                    RepositorySuiteTestComparison.sealed(
                        clean_state_id=clean.state_id,
                        clean_state_sha256=clean.state_sha256,
                        pinned_state_id=pinned.state_id,
                        pinned_state_sha256=pinned.state_sha256,
                        descriptor_sha256=descriptor_sha256,
                        clean_consensus_sha256=clean_consensus.consensus_sha256,
                        pinned_consensus_sha256=pinned_consensus.consensus_sha256,
                        classification=classification,
                        direction=direction,
                    )
                )
        comparisons_tuple = tuple(
            sorted(
                comparisons,
                key=lambda item: (item.pinned_state_id, item.descriptor_sha256),
            )
        )
        try:
            matrix = RepositorySuiteDifferentialMatrix.sealed(
                repository_sha256=repository_sha256,
                selection_sha256=selection.selection_sha256,
                selection_configuration_sha256=selection.configuration_sha256,
                descriptor_sha256s=descriptor_sha256s,
                required_repetitions=suite.fork_matrix_repetitions,
                fuzz_seed=suite.fuzz_seed,
                execution_configuration_sha256=execution_configuration_sha256,
                fork_rpc_policy_sha256=fork_rpc_policy_sha256,
                states=states,
                attempts=attempts_tuple,
                state_workspace_cleanups=state_workspace_cleanup_tuple,
                state_consensuses=consensus_tuple,
                comparisons=comparisons_tuple,
                safety_claim=False,
            )
        except ValueError:
            return failed("The differential matrix evidence failed typed validation.")

        has_inconclusive = any(
            comparison.classification is RepositoryDifferentialClassification.INCONCLUSIVE
            for comparison in matrix.comparisons
        )
        if has_inconclusive:
            limitations.append("At least one clean-versus-pinned comparison was inconclusive.")
        unique_limitations = tuple(dict.fromkeys(limitations))
        if unique_limitations and not has_inconclusive:
            return failed("A material matrix limitation prevented evidence completion.")
        status = (
            RepositoryDifferentialRunStatus.INCONCLUSIVE
            if has_inconclusive
            else RepositoryDifferentialRunStatus.COMPLETE
        )
        return RepositorySuiteDifferentialRun.sealed(
            status=status,
            configuration_sha256=configuration_sha256,
            requested_state_ids=requested_state_ids,
            required_repetitions=suite.fork_matrix_repetitions,
            matrix=matrix,
            limitations=unique_limitations,
        )

    def _execute_state(
        self,
        state_config: RepositoryForkMatrixStateConfig,
        *,
        root: Path,
        private_root: Path,
        matrix_custody: _DirectoryCustody,
        matrix_nonce_sha256: str,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: ScannerIsolationBackend,
        absolute_deadline: float,
        clock: _MonotonicClock,
        expected_forge_version: str | None,
        expected_forge_sha256: str | None,
        limitations: list[str],
    ) -> _RawState:
        lifecycle = _StateLifecycle()
        try:
            result = self._execute_state_inner(
                state_config,
                root=root,
                private_root=private_root,
                matrix_custody=matrix_custody,
                matrix_nonce_sha256=matrix_nonce_sha256,
                projects=projects,
                repository_sha256=repository_sha256,
                repository_exclusion_root=repository_exclusion_root,
                backend=backend,
                absolute_deadline=absolute_deadline,
                clock=clock,
                expected_forge_version=expected_forge_version,
                expected_forge_sha256=expected_forge_sha256,
                limitations=limitations,
                lifecycle=lifecycle,
            )
        except BaseException as original_error:
            cleanup_error = self._cleanup_state_lifecycle(
                lifecycle,
                absolute_deadline=absolute_deadline,
            )
            if isinstance(original_error, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(cleanup_error, (KeyboardInterrupt, SystemExit)):
                raise cleanup_error from original_error
            if cleanup_error is not None:
                raise _MatrixEvidenceError(
                    "The differential state lifecycle did not close cleanly."
                ) from cleanup_error
            raise
        cleanup_error = self._cleanup_state_lifecycle(
            lifecycle,
            absolute_deadline=absolute_deadline,
        )
        if isinstance(cleanup_error, (KeyboardInterrupt, SystemExit)):
            raise cleanup_error
        if cleanup_error is not None:
            raise _MatrixEvidenceError(
                "The differential state lifecycle did not close cleanly."
            ) from cleanup_error
        for attempt in result.attempts:
            attempt.workspace_disposal = lifecycle.disposal_observations.get(
                (attempt.attempt_root_device, attempt.attempt_root_inode)
            )
            if attempt.workspace_disposal is None:
                raise _MatrixEvidenceError(
                    "A differential attempt lacked verified workspace disposal."
                )
        result.workspace_cleanup = lifecycle.aggregate_disposal
        if result.workspace_cleanup is None:
            raise _MatrixEvidenceError(
                "A differential state lacked shared-budget workspace disposal evidence."
            )
        return result

    @staticmethod
    def _cleanup_state_lifecycle(
        lifecycle: _StateLifecycle,
        *,
        absolute_deadline: float,
    ) -> BaseException | None:
        cleanup_error: BaseException | None = None
        owned_directory_count = len(lifecycle.directories)
        ordered_disposals: list[_DirectoryDisposalObservation] = []
        if lifecycle.clean_lease is not None and not lifecycle.clean_stop_attempted:
            lifecycle.clean_stop_attempted = True
            try:
                lifecycle.clean_lease.stop(absolute_deadline)
            except BaseException as exc:
                cleanup_error = exc
        removal_budget: _DirectoryRemovalBudget | None = None
        if lifecycle.directories:
            try:
                removal_budget = _DirectoryRemovalBudget.start()
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        for custody in reversed(lifecycle.directories):
            if removal_budget is None:
                if not custody.closed:
                    custody.close()
                continue
            try:
                observation = custody.remove_owned_tree(budget=removal_budget)
                lifecycle.disposal_observations[(custody.device, custody.inode)] = observation
                ordered_disposals.append(observation)
            except BaseException as exc:
                if cleanup_error is None:
                    cleanup_error = exc
                if not custody.closed:
                    custody.close()
        if (
            cleanup_error is None
            and removal_budget is not None
            and len(ordered_disposals) == owned_directory_count
        ):
            try:
                finished_at = removal_budget.checkpoint()
                lifecycle.aggregate_disposal = _StateDisposalObservation(
                    ordered_disposals=tuple(ordered_disposals),
                    owned_directory_count=owned_directory_count,
                    removal_entry_limit=removal_budget.entry_limit,
                    removed_entry_count=removal_budget.removed_entry_count,
                    removal_depth_limit=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT,
                    maximum_removed_depth=removal_budget.maximum_removed_depth,
                    removal_timeout_seconds=(REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS),
                    removal_duration_seconds=(finished_at - removal_budget.started_at),
                    all_owned_descriptors_closed=all(
                        observation.attempt_descriptor_closed for observation in ordered_disposals
                    ),
                    all_owned_paths_absent=all(
                        observation.attempt_path_absent and observation.workspace_path_absent
                        for observation in ordered_disposals
                    ),
                )
            except BaseException as exc:
                cleanup_error = exc
        lifecycle.directories.clear()
        return cleanup_error

    def _execute_state_inner(
        self,
        state_config: RepositoryForkMatrixStateConfig,
        *,
        root: Path,
        private_root: Path,
        matrix_custody: _DirectoryCustody,
        matrix_nonce_sha256: str,
        projects: Sequence[SolidityProjectMetadata],
        repository_sha256: str,
        repository_exclusion_root: Path,
        backend: ScannerIsolationBackend,
        absolute_deadline: float,
        clock: _MonotonicClock,
        expected_forge_version: str | None,
        expected_forge_sha256: str | None,
        limitations: list[str],
        lifecycle: _StateLifecycle,
    ) -> _RawState:
        matrix_root = matrix_custody.path
        repetitions = self.smart_contracts.repository_suite.fork_matrix_repetitions
        attempts: list[_RawAttempt] = []
        observations: list[PinnedForkObservation] = []
        completed_observation_pairs = 0
        observation_status = RepositoryExecutionStateObservationStatus.OBSERVED
        observation_detail: str | None = None
        clean_lease: CleanStateLease | None = None
        endpoint: str | None = None

        if isinstance(state_config, RepositoryCleanForkMatrixStateConfig):
            provider = self.dependencies.clean_state_provider
            assert provider is not None
            try:
                if clock.read() + state_config.shutdown_timeout_seconds >= absolute_deadline:
                    raise TimeoutError
                clean_custody = matrix_custody.create_child(f"{state_config.state_id}-clean-origin")
                lifecycle.directories.append(clean_custody)
                clean_lease = provider.start(
                    state_config,
                    root,
                    clean_custody.path,
                    absolute_deadline,
                )
                lifecycle.clean_lease = clean_lease
                clock.read()
                matrix_custody.assert_stable()
                clean_custody.assert_stable()
                endpoint = clean_lease.endpoint
                local_fork_rpc_port(endpoint)
            except (ForkRpcBindingError, OSError, RuntimeError, TimeoutError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The trusted clean-state launcher failed closed."
        else:
            environment = self.dependencies.environment
            if environment is None:
                environment = os.environ
            endpoint = environment.get(state_config.rpc_url_env)
            if not endpoint:
                observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                observation_detail = "The configured local pinned state was unavailable."
            else:
                try:
                    local_fork_rpc_port(endpoint)
                except ForkRpcBindingError:
                    endpoint = None
                    observation_status = RepositoryExecutionStateObservationStatus.FAILED
                    observation_detail = "The configured pinned state endpoint was invalid."

        state_execution_deadline = (
            absolute_deadline - state_config.shutdown_timeout_seconds
            if isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
            else absolute_deadline
        )
        for index in range(1, repetitions + 1):
            attempt_custody, identity_sha256, freshness_sha256 = self._fresh_attempt_dir(
                matrix_custody,
                matrix_nonce_sha256=matrix_nonce_sha256,
                state_id=state_config.state_id,
                attempt_index=index,
                repository_sha256=repository_sha256,
            )
            lifecycle.directories.append(attempt_custody)
            attempt_dir = attempt_custody.path
            if endpoint is None or clock.read() >= state_execution_deadline:
                detail = (
                    observation_detail
                    or "The differential matrix deadline expired before this attempt."
                )
                if endpoint is not None:
                    limitations.append(
                        f"State {state_config.state_id} exceeded the matrix deadline."
                    )
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        attempt_root_device=attempt_custody.device,
                        attempt_root_inode=attempt_custody.inode,
                        scanner_run=_unavailable_run(
                            detail,
                            now=self.dependencies.now,
                            status=(
                                ScannerStatus.TIMED_OUT
                                if endpoint is not None
                                else ScannerStatus.UNAVAILABLE
                            ),
                        ),
                    )
                )
                continue

            expected_chain_id = state_config.expected_chain_id
            pinned_block_number = (
                0
                if isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
                else state_config.pinned_block_number
            )
            remaining = state_execution_deadline - clock.read()
            try:
                pre = self.dependencies.observer(
                    endpoint,
                    expected_chain_id=expected_chain_id,
                    pinned_block_number=pinned_block_number,
                    timeout_seconds=min(_OBSERVATION_TIMEOUT_SECONDS, remaining),
                )
                observations.append(pre)
            except ForkRpcUnavailableError:
                observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                observation_detail = "The configured local state was unavailable."
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        attempt_root_device=attempt_custody.device,
                        attempt_root_inode=attempt_custody.inode,
                        scanner_run=_unavailable_run(
                            observation_detail,
                            now=self.dependencies.now,
                        ),
                    )
                )
                continue
            except (ForkRpcBindingError, RuntimeError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The configured local state identity was invalid."
                attempts.append(
                    _RawAttempt(
                        index=index,
                        workspace_identity_sha256=identity_sha256,
                        workspace_freshness_attestation_sha256=freshness_sha256,
                        attempt_root_device=attempt_custody.device,
                        attempt_root_inode=attempt_custody.inode,
                        scanner_run=_unavailable_run(
                            observation_detail,
                            now=self.dependencies.now,
                            status=ScannerStatus.FAILED,
                        ),
                    )
                )
                continue

            bridge: ForkMatrixBridge | None = None
            snapshot: ReadOnlyRpcBridgeSnapshot | None = None
            run = _unavailable_run(
                "The read-only RPC bridge was unavailable.",
                now=self.dependencies.now,
            )
            try:
                remaining = state_execution_deadline - clock.read()
                if remaining <= _ATTEMPT_CLEANUP_RESERVE_SECONDS:
                    raise TimeoutError
                bridge = self.dependencies.bridge_factory(
                    endpoint,
                    expected_chain_id=pre.chain_id,
                    pinned_block_number=pre.block_number,
                    pinned_block_hash=pre.block_hash,
                    timeout_seconds=min(_OBSERVATION_TIMEOUT_SECONDS, remaining),
                )
                bridge.start()
                bridge_endpoint = bridge.endpoint
                matrix_custody.assert_stable()
                attempt_custody.assert_stable()
                state_smart_contracts = self.smart_contracts.model_copy(
                    update={
                        "fork_rpc_url_env": (
                            state_config.rpc_url_env
                            if isinstance(
                                state_config,
                                RepositoryPinnedForkMatrixStateConfig,
                            )
                            else self.smart_contracts.fork_rpc_url_env
                        )
                    }
                )
                state_reproduction = self.reproduction.model_copy(
                    update={
                        "expected_chain_id": pre.chain_id,
                        "pinned_block_number": pre.block_number,
                    }
                )
                scanner = self.dependencies.scanner_factory(
                    state_smart_contracts,
                    reproduction=state_reproduction,
                    projects=projects,
                    allow_fork_probing=True,
                    expected_repository_sha256=repository_sha256,
                    repository_exclusion_root=repository_exclusion_root,
                    fork_rpc_url_override=bridge_endpoint,
                    fork_rpc_scope_recorder=bridge,
                    attempt_binding_sha256=identity_sha256,
                )
                remaining = state_execution_deadline - clock.read()
                if remaining <= _ATTEMPT_CLEANUP_RESERVE_SECONDS:
                    raise TimeoutError
                run = scanner.run(
                    root,
                    attempt_dir,
                    remaining - _ATTEMPT_CLEANUP_RESERVE_SECONDS,
                    backend=backend,
                    expected_version=expected_forge_version,
                    expected_sha256=expected_forge_sha256,
                )
                if (
                    run.version != expected_forge_version
                    or run.executable_sha256 != expected_forge_sha256
                ):
                    limitations.append(
                        f"State {state_config.state_id} returned a child Forge identity "
                        "outside the qualifying baseline trust pin."
                    )
                    raise ValueError("child Forge identity differed from its trust pin")
                matrix_custody.assert_stable()
                attempt_custody.assert_stable()
                run = _remove_ephemeral_run_data(
                    run,
                    origin_endpoint=endpoint,
                    bridge_endpoint=bridge_endpoint,
                    private_root=private_root,
                    repository_exclusion_root=repository_exclusion_root,
                    attempt_dir=attempt_dir,
                    matrix_root=matrix_root,
                )
            except TimeoutError:
                run = _unavailable_run(
                    "The differential matrix deadline expired during this attempt.",
                    now=self.dependencies.now,
                    status=ScannerStatus.TIMED_OUT,
                )
                limitations.append(f"State {state_config.state_id} exceeded the matrix deadline.")
            except (OSError, RuntimeError, ValueError):
                run = _unavailable_run(
                    "The differential repository-suite attempt failed closed.",
                    now=self.dependencies.now,
                    status=ScannerStatus.FAILED,
                )
            finally:
                if bridge is not None:
                    try:
                        bridge.stop()
                        snapshot = bridge.snapshot()
                    except (OSError, RuntimeError, ValueError):
                        snapshot = None
                        limitations.append(
                            f"State {state_config.state_id} had an unverified RPC bridge stop."
                        )

            if clock.read() >= state_execution_deadline:
                run = _unavailable_run(
                    "The differential matrix absolute deadline was exceeded.",
                    now=self.dependencies.now,
                    status=ScannerStatus.TIMED_OUT,
                )
                limitations.append(f"State {state_config.state_id} exceeded the matrix deadline.")
            else:
                try:
                    post = self.dependencies.observer(
                        endpoint,
                        expected_chain_id=expected_chain_id,
                        pinned_block_number=pinned_block_number,
                        timeout_seconds=min(
                            _OBSERVATION_TIMEOUT_SECONDS,
                            state_execution_deadline - clock.read(),
                        ),
                    )
                    observations.append(post)
                    completed_observation_pairs += 1
                    if post != pre:
                        observation_status = RepositoryExecutionStateObservationStatus.FAILED
                        observation_detail = (
                            "The configured local state identity changed during execution."
                        )
                except ForkRpcUnavailableError:
                    observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
                    observation_detail = (
                        "The configured local state became unavailable after execution."
                    )
                except (ForkRpcBindingError, RuntimeError, ValueError):
                    observation_status = RepositoryExecutionStateObservationStatus.FAILED
                    observation_detail = (
                        "The configured local state identity could not be revalidated."
                    )
            attempts.append(
                _RawAttempt(
                    index=index,
                    workspace_identity_sha256=identity_sha256,
                    workspace_freshness_attestation_sha256=freshness_sha256,
                    attempt_root_device=attempt_custody.device,
                    attempt_root_inode=attempt_custody.inode,
                    scanner_run=run,
                    snapshot=snapshot,
                )
            )

        for custody in lifecycle.directories:
            custody.assert_stable()
        matrix_custody.assert_stable()
        clean_attestation: RepositoryCleanStateAttestationEvidence | None = None
        if clean_lease is not None:
            lifecycle.clean_stop_attempted = True
            try:
                clean_lease.stop(absolute_deadline)
                clean_attestation = clean_lease.attestation()
            except (OSError, RuntimeError, ValueError):
                observation_status = RepositoryExecutionStateObservationStatus.FAILED
                observation_detail = "The trusted clean state did not stop with attested evidence."
        if (
            not observations
            and observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
        ):
            observation_status = RepositoryExecutionStateObservationStatus.UNAVAILABLE
            observation_detail = "The configured local state produced no identity observation."
        elif observations and len(set(observations)) != 1:
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = "The configured local state identity changed during execution."
        elif (
            observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
            and completed_observation_pairs != repetitions
        ):
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = (
                "The configured local state lacked complete pre/post attempt observations."
            )
        if (
            isinstance(state_config, RepositoryCleanForkMatrixStateConfig)
            and clean_attestation is None
        ):
            observation_status = RepositoryExecutionStateObservationStatus.FAILED
            observation_detail = "The trusted clean state lacked final process attestation."
        return _RawState(
            config=state_config,
            attempts=attempts,
            observations=observations,
            observation_status=observation_status,
            observation_detail=observation_detail,
            clean_attestation=clean_attestation,
        )

    def _fresh_attempt_dir(
        self,
        matrix_custody: _DirectoryCustody,
        *,
        matrix_nonce_sha256: str,
        state_id: str,
        attempt_index: int,
        repository_sha256: str,
    ) -> tuple[_DirectoryCustody, str, str]:
        attempt_custody = matrix_custody.create_child(f"{state_id}-attempt-{attempt_index}")
        identity_sha256 = _canonical_sha256(
            {
                "matrix_nonce_sha256": matrix_nonce_sha256,
                "repository_sha256": repository_sha256,
                "state_id": state_id,
                "attempt_index": attempt_index,
            }
        )
        freshness_sha256 = _canonical_sha256(
            {
                "workspace_identity_sha256": identity_sha256,
                "created_with_exist_ok_false": True,
                "device": attempt_custody.device,
                "inode": attempt_custody.inode,
            }
        )
        return attempt_custody, identity_sha256, freshness_sha256

    @staticmethod
    def _seal_state(raw: _RawState) -> RepositorySuiteExecutionStateEvidence:
        config = raw.config
        observed = (
            raw.observation_status is RepositoryExecutionStateObservationStatus.OBSERVED
            and raw.observations
            and len(set(raw.observations)) == 1
        )
        observation = raw.observations[0] if observed else None
        if isinstance(config, RepositoryCleanForkMatrixStateConfig):
            attestation = raw.clean_attestation
            if attestation is None:
                observed = False
                observation = None
                state_source_sha256 = config.anvil_sha256
                attestation = None
            else:
                state_source_sha256 = attestation.expected_state_source_sha256()
            return RepositorySuiteExecutionStateEvidence.sealed(
                state_id=config.state_id,
                kind=RepositoryExecutionStateKind.CLEAN_LOCAL,
                rpc_url_env=None,
                state_source_sha256=state_source_sha256,
                expected_chain_id=config.expected_chain_id,
                pinned_block_number=0,
                observation_status=(
                    RepositoryExecutionStateObservationStatus.OBSERVED
                    if observed
                    else raw.observation_status
                ),
                observed_chain_id=observation.chain_id if observation is not None else None,
                observed_block_number=(
                    observation.block_number if observation is not None else None
                ),
                observed_block_hash=observation.block_hash if observation is not None else None,
                clean_state_attestation=attestation if observed else None,
                observation_detail=(
                    None
                    if observed
                    else raw.observation_detail or "The trusted clean state was not observed."
                ),
            )
        return RepositorySuiteExecutionStateEvidence.sealed(
            state_id=config.state_id,
            kind=RepositoryExecutionStateKind.PINNED_FORK,
            rpc_url_env=config.rpc_url_env,
            state_source_sha256=config.state_source_sha256,
            expected_chain_id=config.expected_chain_id,
            pinned_block_number=config.pinned_block_number,
            observation_status=(
                RepositoryExecutionStateObservationStatus.OBSERVED
                if observed
                else raw.observation_status
            ),
            observed_chain_id=observation.chain_id if observation is not None else None,
            observed_block_number=observation.block_number if observation is not None else None,
            observed_block_hash=observation.block_hash if observation is not None else None,
            observation_detail=(
                None if observed else raw.observation_detail or "The pinned state was not observed."
            ),
        )


def run_repository_fork_matrix(
    smart_contracts: SmartContractsConfig,
    reproduction: ReproductionConfig,
    root: Path,
    private_root: Path,
    *,
    projects: Sequence[SolidityProjectMetadata],
    repository_sha256: str,
    repository_exclusion_root: Path,
    backend: ScannerIsolationBackend,
    baseline_run: ScannerRun,
    absolute_deadline: float,
    dependencies: ForkMatrixDependencies | None = None,
) -> RepositorySuiteDifferentialRun | None:
    """Functional wrapper used by orchestration without adding child runs to its portfolio."""

    return RepositoryForkMatrixRunner(
        smart_contracts,
        reproduction,
        dependencies=dependencies,
    ).run(
        root,
        private_root,
        projects=projects,
        repository_sha256=repository_sha256,
        repository_exclusion_root=repository_exclusion_root,
        backend=backend,
        baseline_run=baseline_run,
        absolute_deadline=absolute_deadline,
    )


def fork_rpc_egress_from_snapshot(
    snapshot: ReadOnlyRpcBridgeSnapshot,
    state: RepositorySuiteExecutionStateEvidence,
) -> ForkRpcReadOnlyEgressEvidence:
    """Bind one stopped bridge snapshot to its already observed execution state."""

    if (
        state.observation_status is not RepositoryExecutionStateObservationStatus.OBSERVED
        or state.observed_chain_id != snapshot.expected_chain_id
        or state.observed_block_number != snapshot.pinned_block_number
        or state.observed_block_hash != snapshot.pinned_block_hash
    ):
        raise ValueError("read-only bridge snapshot differs from its observed state identity")
    return ForkRpcReadOnlyEgressEvidence.sealed(
        status=RepositoryForkEgressStatus(snapshot.status),
        state_id=state.state_id,
        state_source_sha256=state.state_source_sha256,
        expected_chain_id=snapshot.expected_chain_id,
        pinned_block_number=snapshot.pinned_block_number,
        pinned_block_hash=snapshot.pinned_block_hash,
        policy_sha256=snapshot.policy_sha256,
        method_log_sha256=snapshot.method_log_sha256,
        selected_test_scope_snapshot_sha256s=(snapshot.selected_test_scope_snapshot_sha256s),
        preflight_origin_observation_sha256=(snapshot.preflight_origin_observation_sha256),
        postflight_origin_observation_sha256=(snapshot.postflight_origin_observation_sha256),
        origin_state_stable=snapshot.origin_state_stable,
        http_request_count=snapshot.http_request_count,
        permitted_rpc_call_count=snapshot.permitted_rpc_call_count,
        origin_attempted_rpc_call_count=snapshot.origin_attempted_rpc_call_count,
        origin_validated_rpc_call_count=snapshot.origin_validated_rpc_call_count,
        synthetic_rpc_call_count=snapshot.synthetic_rpc_call_count,
        denied_request_count=snapshot.denied_request_count,
        malformed_request_count=snapshot.malformed_request_count,
        limit_exceeded_request_count=snapshot.limit_exceeded_request_count,
        upstream_error_request_count=snapshot.upstream_error_request_count,
        allowed_method_counts=tuple(
            ForkRpcMethodCount(method=method, count=count)
            for method, count in snapshot.allowed_method_counts
        ),
        stopped_cleanly=snapshot.stopped_cleanly,
        bridge_snapshot_sha256=snapshot.snapshot_sha256,
    )
