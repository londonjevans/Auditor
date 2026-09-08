"""Prepare exact declared offline reads for managed leases, never fork or audit authority."""

from __future__ import annotations

import math
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, SupportsIndex

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mmaudit.config import (
    AuditConfig,
    RepositoryPinnedForkMatrixStateConfig,
    canonical_audit_config_json,
    parse_canonical_audit_config,
)
from mmaudit.models.schemas import LanguageCapabilityProfile
from mmaudit.orchestration.manifest import ManifestFileBinding
from mmaudit.release_io import read_file_evidence
from mmaudit.scanners.fork_rpc import PinnedForkObservation
from mmaudit.scanners.offline_fork_rpc import _MAX_ARCHIVE_BYTES, load_offline_fork_rpc_archive
from mmaudit.scanners.offline_fork_service import (
    _MAX_LIFETIME_SECONDS,
    _SHUTDOWN_SECONDS,
    OfflineForkRpcLease,
    OfflineForkRpcLeaseError,
)

_MAX_TOTAL_ARCHIVE_BYTES = 64 * 1024 * 1024
_REPRODUCTION_STARTUP_SECONDS = 15.0
# Preserve the existing five-second process waits, including stop/reap on failure.
_REPRODUCTION_PROCESS_CLEANUP_SECONDS = 15.0
_PREPARED_ARCHIVES = object()


class ManagedForkArchiveError(ValueError):
    """Declared offline inputs or the owned read lifecycle cannot be verified."""


class ManagedForkArchiveSource(BaseModel):
    """One explicit hash-addressed local store; never a URL, script or ambient discovery input."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    archive_root: Path
    primary_archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reproduction_archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    invariant_archive_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "primary_archive_sha256", "reproduction_archive_sha256", "invariant_archive_sha256"
    )
    @classmethod
    def primary_digest_is_nonzero(cls, value: str | None) -> str | None:
        if value == "0" * 64:
            raise ValueError("managed archive digest must be nonzero")
        return value

    @field_validator("archive_root")
    @classmethod
    def archive_root_is_absolute(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("managed fork archive root must be absolute and direct")
        return value


@dataclass(frozen=True, slots=True)
class _ArchiveSelection:
    state_json: str
    binding_json: str
    observation: PinnedForkObservation


def _pinned_states(config: AuditConfig) -> tuple[RepositoryPinnedForkMatrixStateConfig, ...]:
    if type(config) is not AuditConfig or config.effective() != config:
        raise ManagedForkArchiveError("managed fork archives require exact effective config")
    detached = parse_canonical_audit_config(canonical_audit_config_json(config))
    states = tuple(
        state
        for state in detached.smart_contracts.repository_suite.fork_matrix_states
        if type(state) is RepositoryPinnedForkMatrixStateConfig
    )
    if len(states) > 7:
        raise ManagedForkArchiveError("managed fork archives require declared pinned matrix states")
    return states


def _primary_state(config: AuditConfig, digest: str) -> RepositoryPinnedForkMatrixStateConfig:
    if (
        config.language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or not config.scanners.foundry_fork.enabled
        or not config.smart_contracts.enabled
        or not config.smart_contracts.allow_fork_probing
        or config.reproduction.expected_chain_id is None
        or config.reproduction.pinned_block_number is None
    ):
        raise ManagedForkArchiveError(
            "managed primary archive requires acknowledged pinned Foundry"
        )
    # A private binding record for the primary role, never a new configured matrix state.
    return RepositoryPinnedForkMatrixStateConfig(
        state_id="managed-primary",
        kind="pinned_fork",
        rpc_url_env=config.smart_contracts.fork_rpc_url_env,
        expected_chain_id=config.reproduction.expected_chain_id,
        pinned_block_number=config.reproduction.pinned_block_number,
        state_source_sha256=digest,
    )


def _primary_timeout(config: AuditConfig) -> float:
    """Preserve the existing Foundry consumer's three-way timeout policy exactly."""

    return min(
        config.execution.scanner_timeout_seconds,
        config.smart_contracts.max_fork_probe_seconds,
        config.smart_contracts.repository_suite.total_timeout_seconds,
    )


def _primary_lease_lifetime(config: AuditConfig) -> float:
    required = math.fsum((_primary_timeout(config), _SHUTDOWN_SECONDS, 1.0))
    if not 0.05 <= required <= _MAX_LIFETIME_SECONDS:
        raise ManagedForkArchiveError("primary scanner budget exceeds the fixed lease lifetime")
    return required


def _reproduction_state(config: AuditConfig, digest: str) -> RepositoryPinnedForkMatrixStateConfig:
    if (
        config.language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or not config.reproduction.enabled
        or not config.smart_contracts.enabled
        or not config.smart_contracts.allow_fork_probing
        or config.reproduction.expected_chain_id is None
        or config.reproduction.pinned_block_number is None
    ):
        raise ManagedForkArchiveError(
            "managed reproduction archive requires acknowledged pinned reproduction"
        )
    return RepositoryPinnedForkMatrixStateConfig(
        state_id="managed-reproduction",
        kind="pinned_fork",
        rpc_url_env=config.smart_contracts.fork_rpc_url_env,
        expected_chain_id=config.reproduction.expected_chain_id,
        pinned_block_number=config.reproduction.pinned_block_number,
        state_source_sha256=digest,
    )


def _invariant_state(config: AuditConfig, digest: str) -> RepositoryPinnedForkMatrixStateConfig:
    if (
        config.language_profile is not LanguageCapabilityProfile.SOLIDITY_EVM
        or not config.invariants.enabled
        or not config.invariants.execute_generated
        or not config.smart_contracts.enabled
        or not config.smart_contracts.allow_fork_probing
        or config.reproduction.expected_chain_id is None
        or config.reproduction.pinned_block_number is None
    ):
        raise ManagedForkArchiveError(
            "managed invariant archive requires acknowledged pinned generated invariants"
        )
    return RepositoryPinnedForkMatrixStateConfig(
        state_id="managed-invariant",
        kind="pinned_fork",
        rpc_url_env=config.smart_contracts.fork_rpc_url_env,
        expected_chain_id=config.reproduction.expected_chain_id,
        pinned_block_number=config.reproduction.pinned_block_number,
        state_source_sha256=digest,
    )


def _reproduction_execution_reserve(config: AuditConfig) -> float:
    return math.fsum(
        (
            config.reproduction.timeout_seconds,
            _REPRODUCTION_PROCESS_CLEANUP_SECONDS,
            _SHUTDOWN_SECONDS,
        )
    )


def _reproduction_lease_lifetime(config: AuditConfig) -> float:
    required = math.fsum((_reproduction_execution_reserve(config), _REPRODUCTION_STARTUP_SECONDS))
    if not 0.05 <= required <= _MAX_LIFETIME_SECONDS:
        raise ManagedForkArchiveError(
            "reproduction attempt budget exceeds the fixed lease lifetime"
        )
    return required


def _lease_lifetime(config: AuditConfig) -> float:
    from mmaudit.scanners.fork_matrix import (
        _MATRIX_ORCHESTRATION_SLACK_SECONDS,
        _PER_ATTEMPT_MATRIX_OVERHEAD_SECONDS,
        repository_fork_matrix_timeout_budget_seconds,
    )

    suite = config.smart_contracts.repository_suite
    repository_fork_matrix_timeout_budget_seconds(suite)
    required = math.fsum(
        (
            suite.fork_matrix_repetitions
            * (suite.total_timeout_seconds + _PER_ATTEMPT_MATRIX_OVERHEAD_SECONDS),
            _SHUTDOWN_SECONDS,
            _MATRIX_ORCHESTRATION_SLACK_SECONDS,
        )
    )
    if not 0.05 <= required <= _MAX_LIFETIME_SECONDS:
        raise ManagedForkArchiveError("declared state budget exceeds the fixed lease lifetime")
    return required


def _verify_archive_roots(archive_root: Path, *protected_roots: Path) -> None:
    try:
        if (
            not archive_root.is_absolute()
            or ".." in archive_root.parts
            or archive_root.resolve(strict=True) != archive_root
        ):
            raise ValueError("archive root differs")
        for root in protected_roots:
            if (
                not isinstance(root, Path)
                or not root.is_absolute()
                or ".." in root.parts
                or root.resolve(strict=False) != root
                or root.is_relative_to(archive_root)
                or archive_root.is_relative_to(root)
            ):
                raise ValueError("archive root overlap or alias")
    except (OSError, RuntimeError, ValueError):
        raise ManagedForkArchiveError("managed archive roots are invalid or overlap") from None


class ManagedForkArchives:
    """Detached selection with boundary-local source rechecks and fresh, owned per-state leases.

    File digests identify supplied data, not complete state or provenance. Primary Foundry,
    reproduction, invariant and matrix reads are separate roles. Preparation starts no listener.
    """

    def __init__(
        self,
        *,
        config_json: str,
        archive_root: Path,
        selections: tuple[_ArchiveSelection, ...],
        primary_selection: _ArchiveSelection | None = None,
        primary_archive_sha256: str | None = None,
        reproduction_selection: _ArchiveSelection | None = None,
        reproduction_archive_sha256: str | None = None,
        invariant_selection: _ArchiveSelection | None = None,
        invariant_archive_sha256: str | None = None,
        _admission: object | None = None,
    ) -> None:
        if _admission is not _PREPARED_ARCHIVES:
            raise ManagedForkArchiveError("managed archives require exact preparation")
        self._config_json = config_json
        self._archive_root = archive_root
        self._selections = selections
        self._primary_selection = primary_selection
        self._primary_archive_sha256 = primary_archive_sha256
        self._reproduction_selection = reproduction_selection
        self._reproduction_archive_sha256 = reproduction_archive_sha256
        self._invariant_selection = invariant_selection
        self._invariant_archive_sha256 = invariant_archive_sha256

    def __copy__(self) -> ManagedForkArchives:
        raise TypeError("managed archive handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> ManagedForkArchives:
        raise TypeError("managed archive handles cannot be copied")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("managed archive handles cannot be serialized")

    @property
    def config(self) -> AuditConfig:
        return parse_canonical_audit_config(self._config_json)

    @property
    def state_ids(self) -> tuple[str, ...]:
        return tuple(state.state_id for state in _pinned_states(self.config))

    @property
    def source_bindings(self) -> tuple[ManifestFileBinding, ...]:
        selections = (
            self._selections
            + ((self._primary_selection,) if self._primary_selection is not None else ())
            + ((self._reproduction_selection,) if self._reproduction_selection is not None else ())
            + ((self._invariant_selection,) if self._invariant_selection is not None else ())
        )
        return tuple(
            ManifestFileBinding.model_validate_json(item.binding_json) for item in selections
        )

    @property
    def primary_source_binding(self) -> ManifestFileBinding | None:
        if self._primary_selection is None:
            return None
        return ManifestFileBinding.model_validate_json(self._primary_selection.binding_json)

    @property
    def primary_timeout_seconds(self) -> float:
        if self._primary_selection is None:
            raise ManagedForkArchiveError("managed primary archive is unavailable")
        return _primary_timeout(self.config)

    @property
    def reproduction_source_binding(self) -> ManifestFileBinding | None:
        if self._reproduction_selection is None:
            return None
        return ManifestFileBinding.model_validate_json(self._reproduction_selection.binding_json)

    @property
    def reproduction_attempt_lifetime_seconds(self) -> float:
        if self._reproduction_selection is None:
            raise ManagedForkArchiveError("managed reproduction archive is unavailable")
        return _reproduction_lease_lifetime(self.config)

    def verify_reproduction_execution_budget(self, absolute_deadline: float) -> None:
        """Require the full original child timeout plus cleanup; never shorten it to fit."""

        config = self.config
        now = time.monotonic()
        if (
            self._reproduction_selection is None
            or type(absolute_deadline) not in {int, float}
            or not now + _reproduction_execution_reserve(config)
            <= absolute_deadline
            <= now + _reproduction_lease_lifetime(config)
        ):
            raise ManagedForkArchiveError("managed reproduction attempt budget is unavailable")

    @property
    def invariant_source_binding(self) -> ManifestFileBinding | None:
        if self._invariant_selection is None:
            return None
        return ManifestFileBinding.model_validate_json(self._invariant_selection.binding_json)

    @property
    def invariant_attempt_lifetime_seconds(self) -> float:
        if self._invariant_selection is None:
            raise ManagedForkArchiveError("managed invariant archive is unavailable")
        return _reproduction_lease_lifetime(self.config)

    def verify_invariant_execution_budget(self, absolute_deadline: float) -> None:
        """Require the full original child timeout plus cleanup; never shorten it to fit."""

        config = self.config
        now = time.monotonic()
        if (
            self._invariant_selection is None
            or type(absolute_deadline) not in {int, float}
            or not now + _reproduction_execution_reserve(config)
            <= absolute_deadline
            <= now + _reproduction_lease_lifetime(config)
        ):
            raise ManagedForkArchiveError("managed invariant attempt budget is unavailable")

    @property
    def runtime_authority(self) -> Literal[False]:
        return False

    @property
    def complete_state(self) -> Literal[False]:
        return False

    def verify_roots(self, *protected_roots: Path) -> None:
        _verify_archive_roots(self._archive_root, *protected_roots)

    def verify(self, config: AuditConfig) -> None:
        """Reverify full config, canonical state joins and exact file bytes without opening RPC."""

        try:
            if (
                type(config) is not AuditConfig
                or canonical_audit_config_json(config) != self._config_json
            ):
                raise ValueError("archive config differs")
            states = _pinned_states(config)
            if states:
                _lease_lifetime(config)
            self.verify_roots()
            if len(states) != len(self._selections):
                raise ValueError("archive state set differs")
            selections = self._selections
            if (self._primary_selection is None) != (self._primary_archive_sha256 is None):
                raise ValueError("primary archive selection is incomplete")
            if self._primary_selection is not None:
                assert self._primary_archive_sha256 is not None
                primary = _primary_state(config, self._primary_archive_sha256)
                _primary_lease_lifetime(config)
                states += (primary,)
                selections += (self._primary_selection,)
            if (self._reproduction_selection is None) != (
                self._reproduction_archive_sha256 is None
            ):
                raise ValueError("reproduction archive selection is incomplete")
            if self._reproduction_selection is not None:
                assert self._reproduction_archive_sha256 is not None
                states += (_reproduction_state(config, self._reproduction_archive_sha256),)
                selections += (self._reproduction_selection,)
                _reproduction_lease_lifetime(config)
            if (self._invariant_selection is None) != (self._invariant_archive_sha256 is None):
                raise ValueError("invariant archive selection is incomplete")
            if self._invariant_selection is not None:
                assert self._invariant_archive_sha256 is not None
                states += (_invariant_state(config, self._invariant_archive_sha256),)
                selections += (self._invariant_selection,)
                _reproduction_lease_lifetime(config)
            if not states:
                raise ValueError("no archive state is declared")
            remaining = _MAX_TOTAL_ARCHIVE_BYTES
            for state, item in zip(states, selections, strict=True):
                binding = ManifestFileBinding.model_validate_json(item.binding_json)
                if (
                    item.state_json != state.model_dump_json()
                    or binding.path != state.state_source_sha256 + ".json"
                    or binding.sha256 != state.state_source_sha256
                    or item.observation.chain_id != state.expected_chain_id
                    or item.observation.block_number != state.pinned_block_number
                    or not 1 <= binding.size <= remaining
                ):
                    raise ValueError("archive state or binding differs")
                current = read_file_evidence(
                    evidence_root=self._archive_root,
                    relative_path=binding.path,
                    max_bytes=min(_MAX_ARCHIVE_BYTES, remaining),
                )
                if current.binding != binding:
                    raise ValueError("archive bytes differ")
                remaining -= binding.size
        except (OSError, RuntimeError, ValueError, TypeError):
            raise ManagedForkArchiveError("managed fork archive verification failed") from None

    def start(
        self,
        state: RepositoryPinnedForkMatrixStateConfig,
        *,
        repository: Path,
        output: Path,
        absolute_deadline: float,
    ) -> OfflineForkRpcLease:
        """Start one exact declared state with its whole budget, never a shortened child timeout."""

        lease: OfflineForkRpcLease | None = None
        try:
            from mmaudit.scanners.fork_matrix import _MAX_FORK_MATRIX_TIMEOUT_BUDGET_SECONDS

            config = self.config
            lifetime = _lease_lifetime(config)
            now = time.monotonic()
            if (
                type(state) is not RepositoryPinnedForkMatrixStateConfig
                or type(absolute_deadline) not in {int, float}
                or not now + lifetime
                <= absolute_deadline
                <= now + _MAX_FORK_MATRIX_TIMEOUT_BUDGET_SECONDS
                or state.model_dump_json() not in {item.state_json for item in self._selections}
            ):
                raise ValueError("archive state or deadline differs")
            self.verify_roots(repository, output)
            self.verify(config)
            replay = load_offline_fork_rpc_archive(
                self._archive_root,
                state.state_source_sha256 + ".json",
                expected_sha256=state.state_source_sha256,
                expected_chain_id=state.expected_chain_id,
                pinned_block_number=state.pinned_block_number,
            )
            expected = next(
                item for item in self._selections if item.state_json == state.model_dump_json()
            )
            if (
                replay.source_binding
                != ManifestFileBinding.model_validate_json(expected.binding_json)
                or replay.observation != expected.observation
            ):
                raise ValueError("archive state changed")
            if time.monotonic() + lifetime > absolute_deadline:
                raise ValueError("archive startup budget unavailable")
            lease = OfflineForkRpcLease(replay, lifetime_seconds=lifetime)
            lease.start()
            if time.monotonic() + lifetime > absolute_deadline:
                raise ValueError("archive startup exceeded the full state budget")
            return lease
        except BaseException as exc:
            if lease is not None:
                with suppress(OfflineForkRpcLeaseError):
                    lease.stop(deadline=absolute_deadline)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ManagedForkArchiveError("managed fork archive lease could not start") from None

    def start_primary(
        self,
        *,
        repository: Path,
        output: Path,
        absolute_deadline: float,
    ) -> OfflineForkRpcLease:
        """Own primary reads within the scanner's existing deadline; never shorten its policy.

        The service lifetime covers the full original child policy plus cleanup. Archive startup
        consumes the existing scanner deadline, just like its other admission checks; expiry refuses.
        """

        lease: OfflineForkRpcLease | None = None
        try:
            config = self.config
            if self._primary_selection is None or self._primary_archive_sha256 is None:
                raise ValueError("primary archive is unavailable")
            lifetime = _primary_lease_lifetime(config)
            now = time.monotonic()
            if type(absolute_deadline) not in {
                int,
                float,
            } or not now < absolute_deadline <= now + _primary_timeout(config):
                raise ValueError("primary scanner deadline differs")
            self.verify_roots(repository, output)
            self.verify(config)
            state = _primary_state(config, self._primary_archive_sha256)
            replay = load_offline_fork_rpc_archive(
                self._archive_root,
                state.state_source_sha256 + ".json",
                expected_sha256=state.state_source_sha256,
                expected_chain_id=state.expected_chain_id,
                pinned_block_number=state.pinned_block_number,
            )
            if (
                replay.source_binding != self.primary_source_binding
                or replay.observation != self._primary_selection.observation
                or time.monotonic() >= absolute_deadline
            ):
                raise ValueError("primary archive or startup deadline changed")
            lease = OfflineForkRpcLease(replay, lifetime_seconds=lifetime)
            lease.start()
            if time.monotonic() >= absolute_deadline:
                raise ValueError("primary startup exceeded the scanner deadline")
            return lease
        except BaseException as exc:
            if lease is not None:
                with suppress(OfflineForkRpcLeaseError):
                    lease.stop(deadline=absolute_deadline + _SHUTDOWN_SECONDS)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ManagedForkArchiveError("managed primary archive lease could not start") from None

    def start_reproduction_attempt(
        self,
        *,
        repository: Path,
        output: Path,
        absolute_deadline: float,
    ) -> OfflineForkRpcLease:
        """Start fresh per-attempt reads while reserving the original child timeout and cleanup."""

        lease: OfflineForkRpcLease | None = None
        try:
            config = self.config
            self.verify_reproduction_execution_budget(absolute_deadline)
            self.verify_roots(repository, output)
            self.verify(config)
            if self._reproduction_selection is None or self._reproduction_archive_sha256 is None:
                raise ValueError("reproduction archive is unavailable")
            state = _reproduction_state(config, self._reproduction_archive_sha256)
            replay = load_offline_fork_rpc_archive(
                self._archive_root,
                state.state_source_sha256 + ".json",
                expected_sha256=state.state_source_sha256,
                expected_chain_id=state.expected_chain_id,
                pinned_block_number=state.pinned_block_number,
            )
            if (
                replay.source_binding != self.reproduction_source_binding
                or replay.observation != self._reproduction_selection.observation
            ):
                raise ValueError("reproduction archive changed")
            self.verify_reproduction_execution_budget(absolute_deadline)
            lease = OfflineForkRpcLease(
                replay, lifetime_seconds=_reproduction_lease_lifetime(config)
            )
            lease.start()
            self.verify_reproduction_execution_budget(absolute_deadline)
            return lease
        except BaseException as exc:
            if lease is not None:
                with suppress(OfflineForkRpcLeaseError):
                    lease.stop(deadline=absolute_deadline)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ManagedForkArchiveError(
                "managed reproduction archive lease could not start"
            ) from None

    def start_invariant_attempt(
        self,
        *,
        repository: Path,
        output: Path,
        absolute_deadline: float,
    ) -> OfflineForkRpcLease:
        """Start fresh per-attempt reads while reserving the original child timeout and cleanup."""

        lease: OfflineForkRpcLease | None = None
        try:
            config = self.config
            self.verify_invariant_execution_budget(absolute_deadline)
            self.verify_roots(repository, output)
            self.verify(config)
            if self._invariant_selection is None or self._invariant_archive_sha256 is None:
                raise ValueError("invariant archive is unavailable")
            state = _invariant_state(config, self._invariant_archive_sha256)
            replay = load_offline_fork_rpc_archive(
                self._archive_root,
                state.state_source_sha256 + ".json",
                expected_sha256=state.state_source_sha256,
                expected_chain_id=state.expected_chain_id,
                pinned_block_number=state.pinned_block_number,
            )
            if (
                replay.source_binding != self.invariant_source_binding
                or replay.observation != self._invariant_selection.observation
            ):
                raise ValueError("invariant archive changed")
            self.verify_invariant_execution_budget(absolute_deadline)
            lease = OfflineForkRpcLease(
                replay, lifetime_seconds=_reproduction_lease_lifetime(config)
            )
            lease.start()
            self.verify_invariant_execution_budget(absolute_deadline)
            return lease
        except BaseException as exc:
            if lease is not None:
                with suppress(OfflineForkRpcLeaseError):
                    lease.stop(deadline=absolute_deadline)
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ManagedForkArchiveError(
                "managed invariant archive lease could not start"
            ) from None


def prepare_managed_fork_archives(
    config: AuditConfig,
    *,
    source: ManagedForkArchiveSource,
    repository: Path,
    output: Path,
) -> ManagedForkArchives:
    """Select only declared hash-named stable files; no directory discovery, writes or service."""

    try:
        if type(source) is not ManagedForkArchiveSource:
            raise ValueError("archive source type differs")
        source = ManagedForkArchiveSource.model_validate(source.model_dump(), strict=True)
        states = _pinned_states(config)
        if states:
            _lease_lifetime(config)
        matrix_state_count = len(states)
        if source.primary_archive_sha256 is not None:
            states += (_primary_state(config, source.primary_archive_sha256),)
            _primary_lease_lifetime(config)
        if source.reproduction_archive_sha256 is not None:
            states += (_reproduction_state(config, source.reproduction_archive_sha256),)
            _reproduction_lease_lifetime(config)
        if source.invariant_archive_sha256 is not None:
            states += (_invariant_state(config, source.invariant_archive_sha256),)
            # Invariant campaigns use the same configured per-child timeout and process waits.
            _reproduction_lease_lifetime(config)
        if not states:
            raise ManagedForkArchiveError(
                "managed archives require a primary, reproduction, invariant or matrix declaration"
            )
        _verify_archive_roots(source.archive_root, repository, output)
        remaining = _MAX_TOTAL_ARCHIVE_BYTES
        selections = []
        for state in states:
            relative_path = state.state_source_sha256 + ".json"
            bounded = read_file_evidence(
                evidence_root=source.archive_root,
                relative_path=relative_path,
                max_bytes=min(_MAX_ARCHIVE_BYTES, remaining),
            )
            if bounded.binding.sha256 != state.state_source_sha256:
                raise ValueError("archive source digest differs")
            replay = load_offline_fork_rpc_archive(
                source.archive_root,
                relative_path,
                expected_sha256=state.state_source_sha256,
                expected_chain_id=state.expected_chain_id,
                pinned_block_number=state.pinned_block_number,
            )
            if replay.source_binding != bounded.binding:
                raise ValueError("archive source changed")
            remaining -= bounded.binding.size
            selections.append(
                _ArchiveSelection(
                    state_json=state.model_dump_json(),
                    binding_json=bounded.binding.model_dump_json(),
                    observation=replay.observation,
                )
            )
        result = ManagedForkArchives(
            config_json=canonical_audit_config_json(config),
            archive_root=source.archive_root,
            selections=tuple(selections[:matrix_state_count]),
            primary_selection=(
                selections[matrix_state_count]
                if source.primary_archive_sha256 is not None
                else None
            ),
            primary_archive_sha256=source.primary_archive_sha256,
            reproduction_selection=(
                selections[matrix_state_count + int(source.primary_archive_sha256 is not None)]
                if source.reproduction_archive_sha256 is not None
                else None
            ),
            reproduction_archive_sha256=source.reproduction_archive_sha256,
            invariant_selection=(
                selections[-1] if source.invariant_archive_sha256 is not None else None
            ),
            invariant_archive_sha256=source.invariant_archive_sha256,
            _admission=_PREPARED_ARCHIVES,
        )
        result.verify(config)
        return result
    except ManagedForkArchiveError:
        raise
    except (OSError, RuntimeError, ValueError, TypeError):
        raise ManagedForkArchiveError("managed fork archive preparation failed") from None
