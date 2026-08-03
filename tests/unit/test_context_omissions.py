from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.orchestration.context as context_module
from mmaudit.models.token_planning import (
    CONTEXT_OMISSION_SAMPLE_CAP,
    ContextOmissionCategory,
    ContextOmissionItem,
    ContextOmissionNoticeLevel,
    ContextOmissionReason,
)
from mmaudit.orchestration.context import ContextBudgetError, ContextBuilder, render_context
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map


def _base_package(vulnerable_repo: Path, config_factory):
    config = config_factory(
        repository={"max_total_context_bytes": 200_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    return ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    ).build("source_audit")


def _notice_payload(rendered: str) -> dict[str, object]:
    start_tag = "<CONTEXT_LIMITATIONS_JSON>\n"
    end_tag = "\n</CONTEXT_LIMITATIONS_JSON>"
    assert start_tag in rendered
    return json.loads(rendered.split(start_tag, 1)[1].split(end_tag, 1)[0])


def _commitment_payload(rendered: str) -> dict[str, object]:
    start_tag = "<CONTEXT_OMISSION_COMMITMENT_JSON>\n"
    end_tag = "\n</CONTEXT_OMISSION_COMMITMENT_JSON>"
    assert start_tag in rendered
    return json.loads(rendered.split(start_tag, 1)[1].split(end_tag, 1)[0])


def test_provider_omission_notice_is_bounded_and_excludes_forensic_digests(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    inventory = tuple(f"{index:064x}" for index in range(1, 201))
    omission = ContextOmissionItem.build_aggregate(
        category=ContextOmissionCategory.SOURCE,
        reason=ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
        omitted_item_sha256s=inventory,
    )
    package = _base_package(vulnerable_repo, config_factory).model_copy(
        update={
            "omission_notice_level": ContextOmissionNoticeLevel.COUNTS_BY_GROUP,
            "omissions": (omission,),
        }
    )

    rendered = render_context(package)
    payload = _notice_payload(rendered)
    notice = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    assert len(notice) <= 4_096
    assert payload["detail_level"] == ContextOmissionNoticeLevel.COUNTS_BY_GROUP.value
    assert payload["omitted_item_count"] == len(inventory)
    assert payload["retained_forensic_sample_count"] == CONTEXT_OMISSION_SAMPLE_CAP
    assert payload["forensic_samples_truncated"] is True
    assert omission.omitted_item_sha256 not in rendered
    assert all(sample not in rendered for sample in omission.sampled_item_sha256s)
    assert "<OMISSIONS_JSON>" not in rendered


def test_omission_notice_degrades_before_source_and_manifest_mode_is_out_of_band(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    omissions = tuple(
        sorted(
            (
                ContextOmissionItem.build(
                    category=category,
                    reason=reason,
                    omitted_item_sha256=character * 64,
                )
                for category, reason, character in (
                    (
                        ContextOmissionCategory.SOURCE,
                        ContextOmissionReason.SOURCE_BUDGET_EXCLUDED,
                        "a",
                    ),
                    (
                        ContextOmissionCategory.GRAPH,
                        ContextOmissionReason.METADATA_BUDGET_EXCLUDED,
                        "b",
                    ),
                )
            ),
            key=lambda item: (item.category.value, item.reason.value),
        )
    )
    base = _base_package(vulnerable_repo, config_factory)
    counts = base.model_copy(
        update={
            "omission_notice_level": ContextOmissionNoticeLevel.COUNTS_BY_GROUP,
            "omissions": omissions,
        }
    )
    totals = counts.model_copy(
        update={"omission_notice_level": ContextOmissionNoticeLevel.TOTALS_ONLY}
    )
    manifest_only = counts.model_copy(
        update={"omission_notice_level": ContextOmissionNoticeLevel.MANIFEST_ONLY}
    )

    counts_rendered = render_context(counts)
    totals_rendered = render_context(totals)
    manifest_rendered = render_context(manifest_only)
    empty_commitment = _commitment_payload(render_context(base))
    omitted_commitment = _commitment_payload(manifest_rendered)

    assert counts.excerpts == totals.excerpts == manifest_only.excerpts
    assert len(manifest_rendered.encode("utf-8")) < len(totals_rendered.encode("utf-8"))
    assert len(totals_rendered.encode("utf-8")) < len(counts_rendered.encode("utf-8"))
    assert _notice_payload(totals_rendered)["detail_level"] == (
        ContextOmissionNoticeLevel.TOTALS_ONLY.value
    )
    assert "<CONTEXT_LIMITATIONS_JSON>" not in manifest_rendered
    assert empty_commitment["inventory_sha256"] != omitted_commitment["inventory_sha256"]
    assert len(str(omitted_commitment["inventory_sha256"])) == 64


def test_zero_explicit_context_budget_fails_instead_of_selecting_default(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    with pytest.raises(ContextBudgetError, match="package budget is invalid"):
        builder.build("source_audit", requested_budget=0)


def test_context_package_requires_and_enforces_explicit_source_ceiling(
    vulnerable_repo: Path,
    config_factory,
) -> None:
    package = _base_package(vulnerable_repo, config_factory)
    payload = package.model_dump(mode="python")
    without_ceiling = dict(payload)
    del without_ceiling["configured_maximum_source_tokens_per_request"]
    del without_ceiling["effective_source_byte_ceiling"]

    with pytest.raises(ValidationError, match="Field required"):
        type(package).model_validate(without_ceiling)

    delivered_source_bytes = sum(
        len(excerpt.content.encode("utf-8")) for excerpt in package.excerpts
    )
    payload["effective_source_byte_ceiling"] = max(0, delivered_source_bytes - 1)
    with pytest.raises(ValidationError, match="source content exceeds"):
        type(package).model_validate(payload)

    for field in (
        "configured_maximum_source_tokens_per_request",
        "effective_source_byte_ceiling",
    ):
        boolean_payload = package.model_dump(mode="python")
        boolean_payload[field] = True
        with pytest.raises(ValidationError, match="valid integer"):
            type(package).model_validate(boolean_payload)


def test_context_inventory_cache_hit_never_invokes_fallback_hashing(
    vulnerable_repo: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )
    assert builder._repository_map.files
    original = context_module._inventory_item_sha256
    fallback_calls = 0

    def counted_fallback(item: object) -> str:
        nonlocal fallback_calls
        fallback_calls += 1
        return original(item)

    monkeypatch.setattr(context_module, "_inventory_item_sha256", counted_fallback)

    cached = builder._inventory_snapshot.item_sha256(builder._repository_map.files[0])
    assert cached
    assert fallback_calls == 0

    assert builder._inventory_snapshot.item_sha256({"uncached": True})
    assert fallback_calls == 1
