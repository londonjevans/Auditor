from __future__ import annotations

import hashlib
from pathlib import Path

from mmaudit.models.scheduler import SchedulerShardDescriptor, SchedulerSourceDescriptor
from mmaudit.models.schemas import ModelReviewSurfaceKind
from mmaudit.orchestration.model_review_evidence import build_source_file_review_request
from mmaudit.orchestration.pipeline import _blind_shard_surface_requests
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult


def _discovered_file(root: Path, relative_path: str, content: str) -> DiscoveredFile:
    absolute_path = root / relative_path
    absolute_path.parent.mkdir(parents=True, exist_ok=True)
    absolute_path.write_text(content, encoding="utf-8")
    encoded = content.encode("utf-8")
    return DiscoveredFile(
        absolute_path=absolute_path,
        relative_path=relative_path,
        content=content,
        size=len(encoded),
        lines=len(content.splitlines()),
        sha256=hashlib.sha256(encoded).hexdigest(),
        language="Solidity",
        categories=("source",),
    )


def test_blind_shard_keeps_primary_disposition_when_assignment_only_covers_neighbour(
    tmp_path: Path,
) -> None:
    primary = _discovered_file(
        tmp_path,
        "src/Primary.sol",
        "contract Primary { function guarded() external {} }\n",
    )
    neighbour = _discovered_file(
        tmp_path,
        "src/Neighbour.sol",
        "contract Neighbour { uint256 internal value; }\n",
    )
    discovery = DiscoveryResult(
        root=tmp_path,
        files=(primary, neighbour),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    shard = SchedulerShardDescriptor.semantic(
        shard_id="shard-" + "1" * 24,
        semantic_shard_sha256="2" * 64,
        sources=(
            SchedulerSourceDescriptor.build(
                path=primary.relative_path,
                sha256=primary.sha256,
                size=primary.size,
            ),
        ),
    )
    neighbour_assignment = build_source_file_review_request(
        path=neighbour.relative_path,
        size=neighbour.size,
        lines=neighbour.lines,
        sha256=neighbour.sha256,
    )

    selected = _blind_shard_surface_requests(
        shard=shard,
        discovery=discovery,
        assigned=[neighbour_assignment],
    )

    assert neighbour_assignment in selected
    primary_dispositions = [
        request
        for request in selected
        if request.kind is ModelReviewSurfaceKind.SOURCE_FILE
        and request.allowed_locations[0].path == primary.relative_path
    ]
    assert len(primary_dispositions) == 1
    assert primary_dispositions[0].allowed_locations[0].content_hash == primary.sha256


def test_blind_shard_does_not_duplicate_existing_primary_disposition(tmp_path: Path) -> None:
    primary = _discovered_file(
        tmp_path,
        "src/Primary.sol",
        "contract Primary { function guarded() external {} }\n",
    )
    discovery = DiscoveryResult(
        root=tmp_path,
        files=(primary,),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    shard = SchedulerShardDescriptor.semantic(
        shard_id="shard-" + "3" * 24,
        semantic_shard_sha256="4" * 64,
        sources=(
            SchedulerSourceDescriptor.build(
                path=primary.relative_path,
                sha256=primary.sha256,
                size=primary.size,
            ),
        ),
    )
    assigned = build_source_file_review_request(
        path=primary.relative_path,
        size=primary.size,
        lines=primary.lines,
        sha256=primary.sha256,
    )

    selected = _blind_shard_surface_requests(
        shard=shard,
        discovery=discovery,
        assigned=[assigned],
    )

    assert selected == [assigned]
