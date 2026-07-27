"""Deterministic validation of all model-referenced repository locations."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from mmaudit.models.schemas import CandidateFinding, Location, LocationValidation, SourceSink
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_path


def _resolve_location(root: Path, relative: str) -> tuple[Path | None, str | None]:
    try:
        normalized = normalize_relative_path(relative)
    except ValueError:
        return None, "path traversal or absolute path rejected"
    pure = PurePosixPath(normalized)
    if is_sensitive_workspace_path(pure):
        return None, "sensitive repository path rejected"
    repository_root = root.resolve(strict=True)
    candidate = repository_root
    for part in pure.parts:
        candidate /= part
        if candidate.is_symlink() or candidate.is_junction():
            return None, "linked repository path rejected"
    try:
        resolved = candidate.resolve(strict=True)
        resolved_relative = resolved.relative_to(repository_root)
    except (OSError, ValueError):
        return None, "path does not exist inside repository"
    if is_sensitive_workspace_path(resolved_relative):
        return None, "sensitive repository path rejected"
    if not resolved.is_file():
        return None, "path is not a regular file"
    try:
        if resolved.stat().st_nlink > 1:
            return None, "hardlinked files are outside the trusted repository boundary"
    except OSError:
        return None, "path is no longer readable"
    return resolved, None


def validate_location(
    root: Path,
    location: Location,
    *,
    context_hashes: dict[tuple[str, int, int], str] | None = None,
) -> LocationValidation:
    errors: list[str] = []
    resolved, path_error = _resolve_location(root, location.path)
    if path_error is not None or resolved is None:
        return LocationValidation(
            valid=False,
            errors=[path_error or "invalid path"],
            validated_at=datetime.now(UTC),
        )
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return LocationValidation(
            valid=False,
            errors=["file is no longer readable"],
            validated_at=datetime.now(UTC),
        )
    lines = content.splitlines(keepends=True)
    if location.start_line > len(lines) or location.end_line > len(lines):
        errors.append(f"line range exceeds file length ({len(lines)})")
        selected = ""
    else:
        selected = "".join(lines[location.start_line - 1 : location.end_line])
    content_hash = hashlib.sha256(selected.encode()).hexdigest() if selected else None
    expected = location.content_hash
    if context_hashes is not None:
        expected_from_context = context_hashes.get(
            (location.path, location.start_line, location.end_line)
        )
        containing_excerpt = any(
            path == location.path
            and start > 0
            and start <= location.start_line
            and end >= location.end_line
            for path, start, end in context_hashes
        )
        if expected_from_context is None and not containing_excerpt:
            errors.append("location was not present in supplied context")
        elif (
            expected_from_context is not None
            and expected is not None
            and expected != expected_from_context
        ):
            errors.append("model-supplied hash differs from context hash")
        expected = expected_from_context or expected
        snapshot_hash = context_hashes.get((location.path, 0, 0))
        current_file_hash = hashlib.sha256(content.encode()).hexdigest()
        if snapshot_hash is not None and snapshot_hash != current_file_hash:
            errors.append("file changed since repository discovery")
    if expected is not None and content_hash != expected:
        errors.append("location content changed since context construction")
    if location.symbol and location.symbol not in selected:
        errors.append("quoted symbol is absent from the referenced range")
    return LocationValidation(
        valid=not errors,
        content_hash=content_hash,
        errors=errors,
        validated_at=datetime.now(UTC),
    )


def validate_source_sink(
    root: Path,
    endpoint: SourceSink,
    *,
    context_hashes: dict[tuple[str, int, int], str] | None = None,
) -> list[str]:
    location = Location(path=endpoint.path, start_line=endpoint.line, end_line=endpoint.line)
    result = validate_location(root, location, context_hashes=context_hashes)
    return [f"{endpoint.path}:{endpoint.line}: {error}" for error in result.errors]


def validate_candidate(
    root: Path,
    candidate: CandidateFinding,
    *,
    context_hashes: dict[tuple[str, int, int], str],
) -> LocationValidation:
    errors: list[str] = []
    hashes: list[str] = []
    for location in candidate.locations:
        result = validate_location(root, location, context_hashes=context_hashes)
        errors.extend(f"{location.path}:{location.start_line}: {error}" for error in result.errors)
        if result.content_hash:
            hashes.append(result.content_hash)
    if candidate.source is not None:
        errors.extend(
            validate_source_sink(
                root,
                candidate.source,
                context_hashes=context_hashes,
            )
        )
    if candidate.sink is not None:
        errors.extend(
            validate_source_sink(
                root,
                candidate.sink,
                context_hashes=context_hashes,
            )
        )
    aggregate = hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest() if hashes else None
    return LocationValidation(
        valid=not errors,
        content_hash=aggregate,
        errors=errors,
        validated_at=datetime.now(UTC),
    )
