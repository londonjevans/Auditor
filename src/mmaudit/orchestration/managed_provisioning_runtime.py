"""Descriptor-bound local runtime for nonauthorizing managed provisioning evidence."""

from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mmaudit.config import AuditConfig, canonical_audit_config_json, parse_canonical_audit_config
from mmaudit.isolation.dependency_snapshot import (
    DependencySnapshotBuildLimits,
    DependencySnapshotVerificationError,
    build_managed_dependency_snapshot,
    verify_managed_dependency_snapshot,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostLedgerError,
    PortfolioHoldStatus,
    cost_ledger_snapshot_sha256,
)
from mmaudit.orchestration.managed_fork_archives import (
    ManagedForkArchives,
    ManagedForkArchiveSource,
    prepare_managed_fork_archives,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolMaterialization,
    ManagedHostToolSource,
    materialize_managed_host_tools,
    preflight_managed_host_tool_source,
)
from mmaudit.orchestration.managed_provisioning import (
    MAX_MANAGED_PROVISIONING_RECEIPT_BYTES,
    CostLedgerProvisioningObservation,
    DependencySnapshotProvisioningObservation,
    ManagedProvisioningAction,
    ManagedProvisioningObservations,
    ManagedProvisioningObservationStatus,
    ManagedProvisioningReceipt,
    ManagedProvisioningRefusalCode,
    ManagedProvisioningRequirement,
    build_managed_provisioning_receipt,
    derive_managed_provisioning_plan,
    parse_managed_provisioning_receipt,
    reduce_managed_provisioning_observations,
    render_managed_provisioning_receipt,
    verify_managed_provisioning_receipt,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainBundle,
    derive_managed_toolchain_config,
    preflight_managed_toolchain_config,
)
from mmaudit.scanners.base import retain_scanner_workspace_source_custody

_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK: Final = getattr(os, "O_NONBLOCK", 0)
_READ_CHUNK_BYTES: Final = 64 * 1024
_MAX_TEMPORARY_RECEIPT_ATTEMPTS: Final = 1024
_OUTPUT_LOCKS_GUARD = threading.Lock()
_OUTPUT_LOCKS: dict[tuple[int, int], threading.RLock] = {}


class ManagedProvisioningRuntimeError(ValueError):
    """Raised when exact local provisioning evidence cannot be recorded safely."""


class ManagedDependencySource(BaseModel):
    """Explicit local material selection, never an endpoint or execution request."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    archive_root: Path
    advisory_path: Path
    advisory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("archive_root", "advisory_path")
    @classmethod
    def source_paths_are_absolute(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("managed dependency source requires absolute direct local paths")
        return value


@dataclass(frozen=True, slots=True)
class ManagedProvisioningRun:
    """Receipt plus a detached, reproducible config; neither authorizes execution."""

    receipt: ManagedProvisioningReceipt
    _config_json: str = field(repr=False)
    host_tools: ManagedHostToolMaterialization | None = field(default=None, repr=False)
    offline_forks: ManagedForkArchives | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        verify_managed_provisioning_receipt(self.receipt)
        if self.config.stable_hash() != self.receipt.plan.effective_config_sha256:
            raise ManagedProvisioningRuntimeError("managed setup config differs from its receipt")
        if self.offline_forks is not None:
            if type(self.offline_forks) is not ManagedForkArchives:
                raise ManagedProvisioningRuntimeError("managed archive material has the wrong type")
            self.offline_forks.verify(self.config)
        if self.host_tools is not None:
            if type(self.host_tools) is not ManagedHostToolMaterialization:
                raise ManagedProvisioningRuntimeError("managed host material has the wrong type")
            self.host_tools.verify()
            manifest = self.host_tools.manifest
            if (
                manifest.source_bundle_sha256 != self.receipt.plan.source_bundle_sha256
                or manifest.effective_config_sha256 != self.receipt.plan.effective_config_sha256
                or manifest.required_roles != self.receipt.plan.required_roles
                or self.host_tools.config != self.config
            ):
                raise ManagedProvisioningRuntimeError("managed host material differs from receipt")

    @property
    def config(self) -> AuditConfig:
        """Return a fresh copy so downstream edits cannot alter the retained selection."""

        return parse_canonical_audit_config(self._config_json)


@dataclass(frozen=True, slots=True)
class _PreparedReceipt:
    """Fully written private receipt awaiting atomic no-replace publication."""

    temporary_name: str
    final_name: str
    identity: tuple[int, int]
    content: bytes
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _ReceiptPublication:
    """Exact final path identity that may be rolled back after custody failure."""

    name: str
    identity: tuple[int, int]
    created: bool


@dataclass(slots=True)
class _PrivateOutputCustody:
    """Retain one exact owned mode-0700 output directory through receipt publication."""

    path: Path
    descriptor: int
    identity: tuple[int, int, int, int]
    thread_lock: threading.RLock
    closed: bool = False

    @classmethod
    def acquire(cls, path: Path) -> _PrivateOutputCustody:
        absolute = _canonical_unlinked_directory(path, label="managed provisioning output")
        before = absolute.lstat()
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning output must be an owned private directory"
            )
        if _NOFOLLOW == 0 or _DIRECTORY == 0 or _NONBLOCK == 0:
            raise ManagedProvisioningRuntimeError(
                "descriptor-safe managed provisioning output is unavailable"
            )
        try:
            descriptor = os.open(absolute, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning output could not be opened safely"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            after = absolute.lstat()
            identity = _private_directory_identity(before)
            if (
                _private_directory_identity(opened) != identity
                or _private_directory_identity(after) != identity
            ):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning output changed while being opened"
                )
        except BaseException:
            os.close(descriptor)
            raise
        return cls(
            path=absolute,
            descriptor=descriptor,
            identity=identity,
            thread_lock=_output_thread_lock((identity[0], identity[1])),
        )

    def prepare(
        self,
        receipt: ManagedProvisioningReceipt,
    ) -> _PreparedReceipt:
        """Write and fsync one private temp file without exposing a final pathname."""

        if self.closed:
            raise ManagedProvisioningRuntimeError("managed provisioning output custody is closed")
        content = render_managed_provisioning_receipt(receipt).encode("utf-8")
        if not content or len(content) > MAX_MANAGED_PROVISIONING_RECEIPT_BYTES:
            raise ManagedProvisioningRuntimeError("managed provisioning receipt exceeds its bound")
        final_name = f"managed-provisioning-receipt-{receipt.receipt_sha256}.json"
        self._require_retained_identity()
        descriptor = -1
        temporary_name = ""
        for attempt in range(_MAX_TEMPORARY_RECEIPT_ATTEMPTS):
            candidate = f".{final_name}.{attempt}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                    0o600,
                    dir_fd=self.descriptor,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt could not be prepared safely"
                ) from exc
            temporary_name = candidate
            break
        if descriptor < 0:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt temporary namespace is exhausted"
            )

        created_identity: tuple[int, int] | None = None
        try:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            created_identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or opened.st_size != 0
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt is not a fresh private file"
                )
            _write_all(descriptor, content)
            os.fsync(descriptor)
            finished = os.fstat(descriptor)
            named = os.stat(
                temporary_name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            expected_file = (*created_identity, os.geteuid(), 1, len(content), 0o600)
            if (
                _private_file_identity(finished) != expected_file
                or _private_file_identity(named) != expected_file
            ):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt changed while being written"
                )
            self._require_retained_identity()
            return _PreparedReceipt(
                temporary_name=temporary_name,
                final_name=final_name,
                identity=created_identity,
                content=content,
                receipt_sha256=receipt.receipt_sha256,
            )
        except BaseException:
            if created_identity is not None:
                _unlink_exact_created_file(
                    self.descriptor,
                    temporary_name,
                    created_identity,
                )
            raise
        finally:
            os.close(descriptor)

    @contextmanager
    def publish_or_verify(
        self,
        prepared: _PreparedReceipt,
        receipt: ManagedProvisioningReceipt,
    ) -> Iterator[_ReceiptPublication]:
        """Lease an exact publication through source finalization and commit or rollback."""

        if self.closed:
            raise ManagedProvisioningRuntimeError("managed provisioning output custody is closed")
        if (
            prepared.receipt_sha256 != receipt.receipt_sha256
            or prepared.content != render_managed_provisioning_receipt(receipt).encode("utf-8")
        ):
            raise ManagedProvisioningRuntimeError(
                "managed provisioning prepared receipt differs from its envelope"
            )
        with self.thread_lock:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_EX)
            except OSError as exc:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning output lock is unavailable"
                ) from exc
            publication: _ReceiptPublication | None = None
            try:
                try:
                    publication = self._publish_or_verify_locked(prepared, receipt)
                    yield publication
                    self._require_publication_locked(publication, prepared, receipt)
                except BaseException as exc:
                    if publication is not None and publication.created:
                        try:
                            self._rollback_created_locked(publication)
                        except BaseException as rollback_exc:
                            raise rollback_exc from exc
                    raise
            finally:
                # Closing the retained directory descriptor also drops the flock. Suppressing an
                # unlock failure prevents a successful publication from escaping without its
                # rollback handle; close() remains mandatory in the outer runtime finally block.
                with suppress(OSError):
                    fcntl.flock(self.descriptor, fcntl.LOCK_UN)

    def _publish_or_verify_locked(
        self,
        prepared: _PreparedReceipt,
        receipt: ManagedProvisioningReceipt,
    ) -> _ReceiptPublication:
        """Publish or verify while the output-directory lease is held."""

        self._require_retained_identity()
        self._require_prepared(prepared)
        linked_identity: tuple[int, int] | None = None
        try:
            try:
                os.link(
                    prepared.temporary_name,
                    prepared.final_name,
                    src_dir_fd=self.descriptor,
                    dst_dir_fd=self.descriptor,
                    follow_symlinks=False,
                )
                linked_identity = prepared.identity
                linked = os.stat(
                    prepared.final_name,
                    dir_fd=self.descriptor,
                    follow_symlinks=False,
                )
                linked_identity = (linked.st_dev, linked.st_ino)
            except FileExistsError:
                self._discard_prepared(prepared)
                os.fsync(self.descriptor)
                observed = self._read_existing(prepared.final_name)
                parsed = parse_managed_provisioning_receipt(observed)
                if observed != prepared.content or parsed != receipt:
                    raise ManagedProvisioningRuntimeError(
                        "managed provisioning receipt differs from exact envelope"
                    ) from None
                final = os.stat(
                    prepared.final_name,
                    dir_fd=self.descriptor,
                    follow_symlinks=False,
                )
                self._require_retained_identity()
                return _ReceiptPublication(
                    name=prepared.final_name,
                    identity=(final.st_dev, final.st_ino),
                    created=False,
                )
            except OSError as exc:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt could not be published safely"
                ) from exc

            temporary = os.stat(
                prepared.temporary_name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            final = os.stat(
                prepared.final_name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            expected_linked = (
                *prepared.identity,
                os.geteuid(),
                2,
                len(prepared.content),
                0o600,
            )
            if (
                _private_file_identity(temporary) != expected_linked
                or _private_file_identity(final) != expected_linked
            ):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt changed during publication"
                )
            os.unlink(prepared.temporary_name, dir_fd=self.descriptor)
            os.fsync(self.descriptor)
            completed = os.stat(
                prepared.final_name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            expected_final = (
                *prepared.identity,
                os.geteuid(),
                1,
                len(prepared.content),
                0o600,
            )
            if _private_file_identity(completed) != expected_final:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt final identity is inconsistent"
                )
            observed = self._read_existing(prepared.final_name)
            parsed = parse_managed_provisioning_receipt(observed)
            if observed != prepared.content or parsed != receipt:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning published receipt is inconsistent"
                )
            self._require_retained_identity()
            return _ReceiptPublication(
                name=prepared.final_name,
                identity=prepared.identity,
                created=True,
            )
        except BaseException as exc:
            cleanup_error: BaseException | None = None
            if linked_identity is not None:
                try:
                    self._rollback_failed_publication_locked(
                        prepared.final_name,
                        linked_identity,
                    )
                except BaseException as final_cleanup_exc:
                    cleanup_error = final_cleanup_exc
            _unlink_exact_created_file(
                self.descriptor,
                prepared.temporary_name,
                prepared.identity,
            )
            with suppress(OSError):
                os.fsync(self.descriptor)
            if cleanup_error is not None:
                raise cleanup_error from exc
            raise

    def _rollback_failed_publication_locked(
        self,
        name: str,
        identity: tuple[int, int],
    ) -> None:
        """Identity-check the final name before rollback under the cooperative lease."""

        try:
            observed = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning failed receipt could not be inspected for rollback"
            ) from exc
        if (observed.st_dev, observed.st_ino) != identity:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning failed receipt changed before rollback"
            )
        try:
            os.unlink(name, dir_fd=self.descriptor)
            os.fsync(self.descriptor)
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning failed receipt could not be rolled back"
            ) from exc

    def _require_publication_locked(
        self,
        publication: _ReceiptPublication,
        prepared: _PreparedReceipt,
        receipt: ManagedProvisioningReceipt,
    ) -> None:
        """Revalidate the exact final receipt after source custody has finalized."""

        self._require_retained_identity()
        observed = self._read_existing(publication.name)
        parsed = parse_managed_provisioning_receipt(observed)
        try:
            final = os.stat(
                publication.name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt became unavailable during finalization"
            ) from exc
        if (final.st_dev, final.st_ino) != publication.identity:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt identity changed during finalization"
            )
        if observed != prepared.content or parsed != receipt:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt changed during finalization"
            )
        self._require_retained_identity()

    def _rollback_created_locked(self, publication: _ReceiptPublication) -> None:
        """Identity-check a created final name before cooperative rollback."""

        try:
            observed = os.stat(
                publication.name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
            if (observed.st_dev, observed.st_ino) != publication.identity:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt changed before rollback"
                )
            os.unlink(publication.name, dir_fd=self.descriptor)
            os.fsync(self.descriptor)
        except FileNotFoundError:
            return
        except ManagedProvisioningRuntimeError:
            raise
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt could not be rolled back safely"
            ) from exc

    def discard_prepared(self, prepared: _PreparedReceipt) -> None:
        """Best-effort cleanup for an unpublished exact temporary inode."""

        _unlink_exact_created_file(
            self.descriptor,
            prepared.temporary_name,
            prepared.identity,
        )

    def _require_prepared(self, prepared: _PreparedReceipt) -> None:
        try:
            observed = os.stat(
                prepared.temporary_name,
                dir_fd=self.descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning prepared receipt is unavailable"
            ) from exc
        expected = (
            *prepared.identity,
            os.geteuid(),
            1,
            len(prepared.content),
            0o600,
        )
        if _private_file_identity(observed) != expected:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning prepared receipt identity changed"
            )

    def _discard_prepared(self, prepared: _PreparedReceipt) -> None:
        self._require_prepared(prepared)
        try:
            os.unlink(prepared.temporary_name, dir_fd=self.descriptor)
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning prepared receipt could not be removed"
            ) from exc

    def _read_existing(self, name: str) -> bytes:
        try:
            before = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > MAX_MANAGED_PROVISIONING_RECEIPT_BYTES
            ):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt is not a bounded private file"
                )
            descriptor = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _NONBLOCK,
                dir_fd=self.descriptor,
            )
        except ManagedProvisioningRuntimeError:
            raise
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt could not be reopened safely"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if _private_file_identity(opened) != _private_file_identity(before):
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt changed while being reopened"
                )
            content = _read_bounded(descriptor)
            finished = os.fstat(descriptor)
            after = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            identities = {
                _private_file_identity(before),
                _private_file_identity(opened),
                _private_file_identity(finished),
                _private_file_identity(after),
            }
            if len(identities) != 1 or len(content) != before.st_size:
                raise ManagedProvisioningRuntimeError(
                    "managed provisioning receipt changed while being read"
                )
            return content
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning receipt could not be read safely"
            ) from exc
        finally:
            os.close(descriptor)

    def _require_retained_identity(self) -> None:
        if _private_directory_identity(os.fstat(self.descriptor)) != self.identity:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning output descriptor identity changed"
            )
        try:
            named = self.path.lstat()
        except OSError as exc:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning output path became unavailable"
            ) from exc
        if _private_directory_identity(named) != self.identity:
            raise ManagedProvisioningRuntimeError("managed provisioning output path changed")

    def close(self) -> None:
        """Idempotently release output-directory custody."""

        if self.closed:
            return
        self.closed = True
        descriptor = self.descriptor
        self.descriptor = -1
        os.close(descriptor)


def provision_managed_local_receipt(
    *,
    config: AuditConfig,
    bundle: ManagedToolchainBundle,
    repository: Path,
    output_dir: Path,
    verify_only: bool,
) -> ManagedProvisioningReceipt:
    """Compatibility receipt API for an already selected dependency configuration."""

    return provision_managed_local_run(
        config=config,
        bundle=bundle,
        repository=repository,
        output_dir=output_dir,
        verify_only=verify_only,
    ).receipt


def provision_managed_local_run(
    *,
    config: AuditConfig,
    bundle: ManagedToolchainBundle,
    repository: Path,
    output_dir: Path,
    verify_only: bool,
    dependency_source: ManagedDependencySource | None = None,
    host_tool_source: ManagedHostToolSource | None = None,
    offline_fork_source: ManagedForkArchiveSource | None = None,
) -> ManagedProvisioningRun:
    """Prepare selected local dependencies/host files and hand off their exact config.

    Existing dependency pins cannot be overridden by automatic construction. All
    other profile settings retain their normal effective meaning. No input profile
    is written, and missing tools or rejected dependencies remain explicit refusals.
    Direct host-file material cannot satisfy installed-toolchain or execution authority.
    """

    if type(config) is not AuditConfig or type(bundle) is not ManagedToolchainBundle:
        raise ManagedProvisioningRuntimeError(
            "managed provisioning requires exact config and bundle inputs"
        )
    if type(verify_only) is not bool:
        raise ManagedProvisioningRuntimeError("managed provisioning verify-only must be a boolean")
    # AuditConfig is mutable; retain one detached selection through all observations.
    bundle, config, _ = preflight_managed_toolchain_config(bundle, config, allow_unresolved=True)
    config = derive_managed_toolchain_config(bundle, config, allow_unresolved=True)
    if host_tool_source is not None:
        host_tool_source = preflight_managed_host_tool_source(bundle, config, host_tool_source)
    if dependency_source is not None:
        if type(dependency_source) is not ManagedDependencySource:
            raise ManagedProvisioningRuntimeError("managed dependency source has the wrong type")
        dependency_source = ManagedDependencySource.model_validate(
            dependency_source.model_dump(), strict=True
        )
        if (
            config.dependency_preparation.offline_snapshot_path is not None
            or config.dependency_preparation.offline_snapshot_sha256 is not None
        ):
            raise ManagedProvisioningRuntimeError(
                "automatic dependency construction conflicts with explicit snapshot configuration"
            )
    output = _PrivateOutputCustody.acquire(output_dir)
    source_custody = None
    prepared: _PreparedReceipt | None = None
    primary_error: BaseException | None = None
    try:
        repository_root = _canonical_unlinked_directory(
            repository,
            label="managed provisioning repository",
        )
        _require_disjoint_directories(repository_root, output.path)
        _require_ledger_outside_protected_directories(
            config,
            repository=repository_root,
            output=output.path,
        )
        source_custody = retain_scanner_workspace_source_custody(repository_root)
        repository_identity = source_custody.source_inventory_sha256_before
        if dependency_source is not None:
            config = _build_managed_dependency_config(
                config=config,
                source=dependency_source,
                repository=repository_root,
                repository_identity=repository_identity,
                output=output.path,
                verify_only=verify_only,
            )
        offline_forks = (
            prepare_managed_fork_archives(
                config,
                source=offline_fork_source,
                repository=repository_root,
                output=output.path,
            )
            if offline_fork_source is not None
            else None
        )
        host_tools = (
            materialize_managed_host_tools(
                bundle=bundle,
                config=config,
                repository=repository_root,
                output_root=output.path,
                source=host_tool_source,
                verify_only=verify_only,
            )
            if host_tool_source is not None
            else None
        )
        plan = derive_managed_provisioning_plan(
            bundle,
            config,
            repository_identity_sha256=repository_identity,
        )
        observations = ManagedProvisioningObservations.refused_for(
            plan,
            code=ManagedProvisioningRefusalCode.UNSUPPORTED_RUNTIME_SURFACE,
        )
        observations = observations.model_copy(
            update={
                "cost_ledger": _managed_cost_ledger_observation(
                    plan_cost_ledger=plan.cost_ledger,
                    config=config,
                    verify_only=verify_only,
                ),
                "dependency_snapshot": _managed_dependency_snapshot_observation(
                    requirement=plan.dependency_snapshot,
                    repository=repository_root,
                    config=config,
                ),
            }
        )
        state = reduce_managed_provisioning_observations(plan, observations)
        receipt = build_managed_provisioning_receipt(plan, state)
        result = ManagedProvisioningRun(
            receipt=receipt,
            _config_json=canonical_audit_config_json(config),
            host_tools=host_tools,
            offline_forks=offline_forks,
        )
        prepared = output.prepare(receipt)
        _revalidate_dependency_observation(
            observations.dependency_snapshot, plan.dependency_snapshot, repository_root, config
        )
        if host_tools is not None:
            host_tools.verify()
        if offline_forks is not None:
            offline_forks.verify(config)
            offline_forks.verify_roots(repository_root, output.path)
        final_repository_identity = source_custody.finalize()
        source_custody = None
        if final_repository_identity != repository_identity:
            raise ManagedProvisioningRuntimeError(
                "managed provisioning repository changed during setup"
            )
        output._require_retained_identity()
        with output.publish_or_verify(prepared, receipt):
            _revalidate_dependency_observation(
                observations.dependency_snapshot, plan.dependency_snapshot, repository_root, config
            )
            if host_tools is not None:
                host_tools.verify()
            if offline_forks is not None:
                offline_forks.verify(config)
                offline_forks.verify_roots(repository_root, output.path)
            prepared = None
        return result
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if prepared is not None:
            output.discard_prepared(prepared)
        if source_custody is not None:
            try:
                source_custody.close()
            except OSError:
                if primary_error is None:
                    raise
        try:
            output.close()
        except OSError:
            if primary_error is None:
                raise


def _build_managed_dependency_config(
    *,
    config: AuditConfig,
    source: ManagedDependencySource,
    repository: Path,
    repository_identity: str,
    output: Path,
    verify_only: bool,
) -> AuditConfig:
    archives = _canonical_unlinked_directory(source.archive_root, label="dependency archive store")
    _require_disjoint_directories(archives, output)
    advisory = source.advisory_path
    if advisory == output or output in advisory.parents:
        raise ManagedProvisioningRuntimeError(
            "dependency advisory must remain outside receipt output"
        )
    defaults = DependencySnapshotBuildLimits()
    selected = config.dependency_preparation
    limits = DependencySnapshotBuildLimits(
        max_metadata_bytes=min(selected.max_snapshot_bytes, defaults.max_metadata_bytes),
        max_projects=min(selected.max_projects, defaults.max_projects),
        max_packages=min(selected.max_packages, defaults.max_packages),
        max_files=min(selected.max_files, defaults.max_files),
        max_file_bytes=min(selected.max_file_bytes, defaults.max_file_bytes),
        max_total_bytes=min(selected.max_total_bytes, defaults.max_total_bytes),
    )
    built = build_managed_dependency_snapshot(
        repository=repository,
        archive_root=archives,
        advisory_path=advisory,
        advisory_sha256=source.advisory_sha256,
        limits=limits,
        verify_only=verify_only,
    )
    if built.source_inventory_sha256 != repository_identity:
        raise ManagedProvisioningRuntimeError("dependency construction bound a different target")
    payload = config.model_dump(mode="python")
    payload["dependency_preparation"] = built.config.model_dump(mode="python")
    return AuditConfig.model_validate(payload, strict=True)


def _managed_dependency_snapshot_observation(
    *, requirement: ManagedProvisioningRequirement, repository: Path, config: AuditConfig
) -> DependencySnapshotProvisioningObservation:
    if not requirement.required:
        return DependencySnapshotProvisioningObservation.not_required(requirement)
    if config.dependency_preparation.offline_snapshot_path is None:
        return DependencySnapshotProvisioningObservation.refused(
            requirement, code=ManagedProvisioningRefusalCode.MISSING_CONFIGURATION
        )
    try:
        observed = verify_managed_dependency_snapshot(
            repository=repository, config=config.dependency_preparation
        )
        if observed != requirement.expected_identity_sha256:
            return DependencySnapshotProvisioningObservation.refused(
                requirement, code=ManagedProvisioningRefusalCode.IDENTITY_MISMATCH
            )
        return DependencySnapshotProvisioningObservation.verified(
            requirement, observed_identity_sha256=observed
        )
    except DependencySnapshotVerificationError:
        return DependencySnapshotProvisioningObservation.refused(
            requirement, code=ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE
        )


def _revalidate_dependency_observation(
    observation: DependencySnapshotProvisioningObservation,
    requirement: ManagedProvisioningRequirement,
    repository: Path,
    config: AuditConfig,
) -> None:
    if observation.status is ManagedProvisioningObservationStatus.VERIFIED_NONAUTHORIZING and (
        _managed_dependency_snapshot_observation(
            requirement=requirement, repository=repository, config=config
        )
        != observation
    ):
        raise ManagedProvisioningRuntimeError(
            "managed provisioning dependency material changed during setup"
        )


def _managed_cost_ledger_observation(
    *,
    plan_cost_ledger: ManagedProvisioningRequirement,
    config: AuditConfig,
    verify_only: bool,
) -> CostLedgerProvisioningObservation:
    configured_path = config.execution.cost_ledger_path
    if configured_path is None:
        return CostLedgerProvisioningObservation.refused(
            plan_cost_ledger,
            code=ManagedProvisioningRefusalCode.MISSING_CONFIGURATION,
        )
    expected_path_sha256 = plan_cost_ledger.expected_path_sha256
    expected_cap_usd = plan_cost_ledger.expected_cap_usd_exact
    actual_path_sha256 = hashlib.sha256(configured_path.encode("utf-8")).hexdigest()
    actual_cap_usd = _decimal_text(config.execution.budget_usd)
    if (
        expected_path_sha256 is None
        or expected_cap_usd is None
        or actual_path_sha256 != expected_path_sha256
        or actual_cap_usd != expected_cap_usd
    ):
        return CostLedgerProvisioningObservation.refused(
            plan_cost_ledger,
            code=ManagedProvisioningRefusalCode.IDENTITY_MISMATCH,
        )
    try:
        with AtomicCostLedger.provisioning_lease(
            Path(configured_path),
            cap_usd=Decimal(expected_cap_usd),
            create_missing=not verify_only,
        ) as (ledger, created, marker_identity_sha256):
            identity_before, snapshot = ledger.snapshot_with_identity_sha256()
            identity_after, final_snapshot = ledger.snapshot_with_identity_sha256()
            if identity_before != identity_after or snapshot != final_snapshot:
                raise CostLedgerConfigurationError(
                    "cost ledger changed while managed provisioning observed it"
                )
            return CostLedgerProvisioningObservation.verified(
                requirement_id=plan_cost_ledger.requirement_id,
                config_binding_sha256=plan_cost_ledger.config_binding_sha256,
                action=(
                    ManagedProvisioningAction.CREATED
                    if created
                    else ManagedProvisioningAction.VERIFIED_EXISTING
                ),
                ledger_path_sha256=actual_path_sha256,
                provisioning_marker_identity_sha256=marker_identity_sha256,
                ledger_identity_sha256=identity_after,
                ledger_snapshot_sha256=cost_ledger_snapshot_sha256(snapshot),
                cap_usd_exact=actual_cap_usd,
                entry_count=len(snapshot.entries),
                active_reservation_count=sum(
                    entry.status is CostEntryStatus.RESERVED for entry in snapshot.entries
                ),
                portfolio_hold_count=len(snapshot.portfolio_holds),
                active_portfolio_hold_count=sum(
                    hold.status is PortfolioHoldStatus.ACTIVE for hold in snapshot.portfolio_holds
                ),
                held_portfolio_usd_exact=_decimal_text(snapshot.held_portfolio_usd),
            )
    except (CostLedgerError, OSError, ValueError):
        return CostLedgerProvisioningObservation.refused(
            plan_cost_ledger,
            code=ManagedProvisioningRefusalCode.INVALID_LOCAL_STATE,
        )


def _require_ledger_outside_protected_directories(
    config: AuditConfig,
    *,
    repository: Path,
    output: Path,
) -> None:
    configured_path = config.execution.cost_ledger_path
    if configured_path is None:
        return
    ledger = Path(configured_path)
    if not ledger.is_absolute():
        raise ManagedProvisioningRuntimeError(
            "managed provisioning cost ledger must use an absolute path"
        )
    try:
        canonical = ledger.parent.resolve(strict=True) / ledger.name
    except OSError as exc:
        raise ManagedProvisioningRuntimeError(
            "managed provisioning cost-ledger parent is unavailable"
        ) from exc
    if canonical == repository or repository in canonical.parents:
        raise ManagedProvisioningRuntimeError(
            "managed provisioning cost ledger must remain outside the repository"
        )
    if canonical == output or output in canonical.parents:
        raise ManagedProvisioningRuntimeError(
            "managed provisioning cost ledger must remain outside the receipt directory"
        )


def _require_disjoint_directories(repository: Path, output: Path) -> None:
    if repository == output or repository in output.parents or output in repository.parents:
        raise ManagedProvisioningRuntimeError(
            "managed provisioning repository and output must be disjoint"
        )


def _canonical_unlinked_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ManagedProvisioningRuntimeError(f"{label} must be an absolute directory")
    absolute = Path(os.path.normpath(path))
    try:
        for candidate in (absolute, *absolute.parents):
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or candidate.is_junction():
                raise ManagedProvisioningRuntimeError(f"{label} may not traverse links")
        metadata = absolute.lstat()
    except ManagedProvisioningRuntimeError:
        raise
    except OSError as exc:
        raise ManagedProvisioningRuntimeError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ManagedProvisioningRuntimeError(f"{label} must be a directory")
    return absolute


def _private_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def _private_file_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        stat.S_IMODE(metadata.st_mode),
    )


def _read_bounded(descriptor: int) -> bytes:
    content = bytearray()
    while len(content) <= MAX_MANAGED_PROVISIONING_RECEIPT_BYTES:
        chunk = os.read(
            descriptor,
            min(
                _READ_CHUNK_BYTES,
                MAX_MANAGED_PROVISIONING_RECEIPT_BYTES + 1 - len(content),
            ),
        )
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > MAX_MANAGED_PROVISIONING_RECEIPT_BYTES:
        raise ManagedProvisioningRuntimeError("managed provisioning receipt exceeds its bound")
    return bytes(content)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("managed provisioning receipt write made no progress")
        view = view[written:]


def _unlink_exact_created_file(
    directory_descriptor: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    try:
        observed = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) == identity:
            os.unlink(name, dir_fd=directory_descriptor)
    except OSError:
        return


def _output_thread_lock(identity: tuple[int, int]) -> threading.RLock:
    with _OUTPUT_LOCKS_GUARD:
        lock = _OUTPUT_LOCKS.get(identity)
        if lock is None:
            lock = threading.RLock()
            _OUTPUT_LOCKS[identity] = lock
        return lock


def _decimal_text(value: int | float | Decimal) -> str:
    rendered = format(Decimal(str(value)), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered
