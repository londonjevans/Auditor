"""Deterministic fresh-discovery to candidate-registry custody bridge."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path

import mmaudit.models.candidate_revocation as candidate_revocation_module
from mmaudit.models.candidate_revocation import (
    candidate_revocation_callables_are_pristine,
    require_candidate_assignment_eligible,
)
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    LineageReviewStatus,
    OperatorLineageReview,
    seal_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.models.route_constraints import ExactRouteRole
from mmaudit.reporting.json_report import stable_json

_MAX_CANDIDATE_REGISTRY_BYTES = 50_000_000
_PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
type _CandidateRevocationCallRoots = tuple[Callable[[], bool], Callable[..., None]]
_CANDIDATE_REVOCATION_CALL_ROOTS: _CandidateRevocationCallRoots = (
    candidate_revocation_callables_are_pristine,
    require_candidate_assignment_eligible,
)


def validate_candidate_registry_template_selection(
    *,
    template: CandidateRegistry,
    routes: tuple[DiscoveryCandidateRoute, ...],
    _candidate_revocation_call_roots: _CandidateRevocationCallRoots = (
        _CANDIDATE_REVOCATION_CALL_ROOTS
    ),
) -> CandidateRegistry:
    """Validate one exact selected subset without trusting stale discovery fields."""

    function_defaults = validate_candidate_registry_template_selection.__kwdefaults__
    if (
        type(_candidate_revocation_call_roots) is not tuple
        or len(_candidate_revocation_call_roots) != 2
    ):
        raise ValueError("candidate registry revocation boundary changed")
    trusted_revocation_pristine, trusted_assignment_gate = _candidate_revocation_call_roots
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_candidate_revocation_call_roots")
        is not _candidate_revocation_call_roots
        or _CANDIDATE_REVOCATION_CALL_ROOTS is not _candidate_revocation_call_roots
        or candidate_revocation_callables_are_pristine is not trusted_revocation_pristine
        or require_candidate_assignment_eligible is not trusted_assignment_gate
        or candidate_revocation_module.candidate_revocation_callables_are_pristine
        is not trusted_revocation_pristine
        or candidate_revocation_module.require_candidate_assignment_eligible
        is not trusted_assignment_gate
        or not trusted_revocation_pristine()
    ):
        raise ValueError("candidate registry revocation boundary changed")
    canonical_routes = tuple(
        DiscoveryCandidateRoute.model_validate(route.model_dump(mode="python")) for route in routes
    )
    route_keys = tuple(
        (route.exact_model_id, route.approved_provider_endpoint) for route in canonical_routes
    )
    route_ids = tuple(route.exact_model_id for route in canonical_routes)
    if (
        not canonical_routes
        or route_keys != tuple(sorted(set(route_keys)))
        or len(route_ids) != len(set(route_ids))
    ):
        raise ValueError(
            "candidate registry selection routes must be non-empty, unique, and sorted"
        )
    for route in canonical_routes:
        trusted_assignment_gate(
            role=ExactRouteRole.CANDIDATE,
            exact_model_id=route.exact_model_id,
            provider_endpoint=route.approved_provider_endpoint,
        )

    canonical_template = CandidateRegistry.model_validate(template.model_dump(mode="python"))

    template_by_id = {
        candidate.exact_model_id: candidate for candidate in canonical_template.candidates
    }
    selected_ids = {route.exact_model_id for route in canonical_routes}
    missing = sorted(selected_ids.difference(template_by_id))
    if missing:
        raise ValueError("candidate registry template is missing a selected exact model ID")
    for route in canonical_routes:
        template_candidate = template_by_id[route.exact_model_id]
        if template_candidate.approved_provider_endpoint != route.approved_provider_endpoint:
            raise ValueError(
                "candidate discovery route differs from its operator-approved template endpoint"
            )
        for model_id in {
            template_candidate.exact_model_id,
            template_candidate.canonical_model_slug,
        }:
            trusted_assignment_gate(
                role=ExactRouteRole.CANDIDATE,
                exact_model_id=model_id,
                provider_endpoint=route.approved_provider_endpoint,
            )

    selected_reviews: dict[str, OperatorLineageReview] = {}
    for model_id in selected_ids:
        review = template_by_id[model_id].lineage_review
        previous_review = selected_reviews.setdefault(review.review_sha256, review)
        if previous_review != review:
            raise ValueError("candidate registry template has conflicting lineage review policy")
    review_owners: dict[str, str] = {}
    for review_hash, review in selected_reviews.items():
        for model_id in review.reviewed_model_ids:
            previous_owner = review_owners.setdefault(model_id, review_hash)
            if previous_owner != review_hash:
                raise ValueError("selected candidate lineage review policy overlaps")
    if set(review_owners) != selected_ids:
        raise ValueError(
            "selected candidate subset does not preserve complete lineage review policy"
        )
    return canonical_template


def derive_candidate_registry_from_discovery(
    *,
    template: CandidateRegistry,
    run_manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    _candidate_revocation_call_roots: _CandidateRevocationCallRoots = (
        _CANDIDATE_REVOCATION_CALL_ROOTS
    ),
) -> CandidateRegistry:
    """Seal a pending registry from fresh facts plus exact operator policy metadata."""

    function_defaults = derive_candidate_registry_from_discovery.__kwdefaults__
    if (
        type(_candidate_revocation_call_roots) is not tuple
        or len(_candidate_revocation_call_roots) != 2
    ):
        raise ValueError("candidate registry revocation boundary changed")
    trusted_revocation_pristine, trusted_assignment_gate = _candidate_revocation_call_roots
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_candidate_revocation_call_roots")
        is not _candidate_revocation_call_roots
        or _CANDIDATE_REVOCATION_CALL_ROOTS is not _candidate_revocation_call_roots
        or candidate_revocation_callables_are_pristine is not trusted_revocation_pristine
        or require_candidate_assignment_eligible is not trusted_assignment_gate
        or candidate_revocation_module.candidate_revocation_callables_are_pristine
        is not trusted_revocation_pristine
        or candidate_revocation_module.require_candidate_assignment_eligible
        is not trusted_assignment_gate
        or not trusted_revocation_pristine()
    ):
        raise ValueError("candidate registry revocation boundary changed")
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        run_manifest.model_dump(mode="python")
    )
    records = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="python"))
        for item in evidence
    )
    for item in records:
        for model_id in {item.exact_model_id, item.canonical_slug}:
            trusted_assignment_gate(
                role=ExactRouteRole.CANDIDATE,
                exact_model_id=model_id,
                provider_endpoint=item.approved_provider_endpoint,
            )
    record_ids = tuple(item.exact_model_id for item in records)
    route_ids = tuple(route.exact_model_id for route in manifest.run_provenance.candidate_routes)
    if record_ids != route_ids or record_ids != tuple(sorted(set(record_ids))):
        raise ValueError("fresh candidate evidence does not exactly cover unique discovery routes")

    canonical_template = validate_candidate_registry_template_selection(
        template=template,
        routes=manifest.run_provenance.candidate_routes,
    )
    if canonical_template.created_at > manifest.run_provenance.retrieved_at:
        raise ValueError("candidate registry template postdates the fresh discovery run")
    template_by_id = {
        candidate.exact_model_id: candidate for candidate in canonical_template.candidates
    }

    candidates: list[CandidateModel] = []
    for item in records:
        if item.zdr_eligible is not True or not item.endpoint_snapshot.require_zdr:
            raise ValueError("fresh candidate discovery is not bound to exact ZDR eligibility")
        endpoint = item.endpoint_snapshot.endpoint(item.approved_provider_endpoint)
        policy = template_by_id[item.exact_model_id]
        review = OperatorLineageReview.model_validate(
            policy.lineage_review.model_dump(mode="python")
        )
        candidates.append(
            CandidateModel(
                exact_model_id=item.exact_model_id,
                canonical_model_slug=item.canonical_slug,
                root_lineage=(
                    review.root_lineage if review.status is LineageReviewStatus.APPROVED else None
                ),
                lineage_review=review,
                discovery_evidence_sha256=item.discovery_evidence_sha256,
                approved_provider_endpoint=item.approved_provider_endpoint,
                approved_provider_name=item.provider_name,
                endpoint_snapshot_sha256=item.endpoint_snapshot_sha256,
                output_capability_sha256=item.output_capability_sha256,
                model_metadata_snapshot_sha256=item.model_metadata_snapshot_sha256,
                pricing_snapshot_sha256=item.pricing_snapshot_sha256,
                context_size=item.context_size,
                max_prompt_tokens=endpoint.max_prompt_tokens,
                max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
                output_limit=item.output_limit,
                output_limit_source=endpoint.max_completion_tokens_source,
                structured_output_supported=item.structured_output_supported,
                structured_output_mode=item.structured_output_mode,
                reasoning_supported=item.reasoning_supported,
                zdr_eligible=True,
                data_collection_deny_eligible=item.data_collection_deny_eligible,
                data_collection_deny_request_policy_enforced=(
                    item.data_collection_deny_request_policy_enforced
                ),
                data_collection_deny_evidence_source=item.data_collection_deny_evidence_source,
                data_collection_deny_evidence_sha256=item.data_collection_deny_evidence_sha256,
                data_collection_deny_evidence_expires_at=(
                    item.data_collection_deny_evidence_expires_at
                ),
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PENDING,
                benchmark_artifact_sha256=None,
                qualification_expires_at=None,
                approved_roles=policy.approved_roles,
            )
        )

    registry = seal_candidate_registry(
        created_at=manifest.run_provenance.retrieved_at,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=tuple(candidates),
    )
    validate_candidate_registry_discovery(
        registry=registry,
        run_manifest=manifest,
        evidence=records,
    )
    return registry


def preflight_candidate_registry_output(path: Path) -> Path:
    """Validate one fresh JSON destination before any provider or secret access."""

    if not isinstance(path, Path):
        raise ValueError("candidate registry output path must be explicit")
    absolute = Path(os.path.abspath(path))
    if absolute.suffix.casefold() != ".json":
        raise ValueError("candidate registry output must use a .json filename")
    _reject_linked_components(absolute)
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise ValueError("candidate registry output must be a fresh file")
    absolute.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_linked_components(absolute.parent)
    if not absolute.parent.is_dir():
        raise ValueError("candidate registry output parent must be a regular directory")
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{absolute.name}.preflight-",
            suffix=".tmp",
            dir=absolute.parent,
        ):
            pass
    except OSError as exc:
        raise ValueError("candidate registry output parent is not writable") from exc
    return absolute


def write_candidate_registry_json(
    path: Path,
    registry: CandidateRegistry,
) -> CandidateRegistry:
    """Atomically publish one canonical fresh mode-0600 registry JSON file."""

    canonical = CandidateRegistry.model_validate(registry.model_dump(mode="python"))
    serialized = stable_json(canonical).encode("utf-8")
    if not serialized or len(serialized) > _MAX_CANDIDATE_REGISTRY_BYTES:
        raise ValueError("candidate registry output exceeds its byte bound")
    absolute = preflight_candidate_registry_output(path)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{absolute.name}.",
        suffix=".tmp",
        dir=absolute.parent,
    )
    temporary = Path(temporary_name)
    final_linked = False
    published = False
    created_identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        view = memoryview(serialized)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("candidate registry write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(serialized)
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        ):
            raise OSError("candidate registry temporary artifact is not exact and private")
        os.close(descriptor)
        descriptor = -1

        _reject_linked_components(absolute.parent)
        try:
            os.link(temporary, absolute, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("candidate registry output must remain a fresh file") from exc
        final_linked = True
        temporary.unlink()

        final_descriptor = os.open(absolute, os.O_RDONLY | _NOFOLLOW_FLAG)
        try:
            final_metadata = os.fstat(final_descriptor)
            if (
                created_identity != (final_metadata.st_dev, final_metadata.st_ino)
                or not stat.S_ISREG(final_metadata.st_mode)
                or final_metadata.st_nlink != 1
                or final_metadata.st_size != len(serialized)
                or stat.S_IMODE(final_metadata.st_mode) != _PRIVATE_FILE_MODE
            ):
                raise OSError("published candidate registry is not exact and private")
            readback = _read_descriptor(final_descriptor, maximum=len(serialized))
        finally:
            os.close(final_descriptor)
        if readback != serialized:
            raise OSError("published candidate registry bytes changed after publication")
        parsed = CandidateRegistry.model_validate_json(readback, strict=True)
        if parsed != canonical or stable_json(parsed).encode("utf-8") != readback:
            raise ValueError("published candidate registry is not canonical")
        directory_descriptor = os.open(absolute.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        published = True
        return parsed
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        if final_linked and not published:
            _unlink_exact_created_file(absolute, created_identity=created_identity)


def _read_descriptor(descriptor: int, *, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum:
        raise ValueError("candidate registry readback exceeds its byte bound")
    return value


def _reject_linked_components(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("candidate registry path may not traverse filesystem links")


def _unlink_exact_created_file(
    path: Path,
    *,
    created_identity: tuple[int, int] | None,
) -> None:
    if created_identity is None:
        return
    try:
        metadata = os.lstat(path)
    except OSError:
        return
    if (metadata.st_dev, metadata.st_ino) == created_identity and stat.S_ISREG(metadata.st_mode):
        path.unlink(missing_ok=True)
