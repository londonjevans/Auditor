from __future__ import annotations

import copy
import hashlib
import json
import pickle
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import repeat
from pathlib import Path
from types import FunctionType

import pytest

import mmaudit.models.public_lineage_authority as lineage_module
from mmaudit.models.public_lineage_authority import (
    PublicModelLineageAliasBinding,
    PublicModelLineageAuthorityError,
    PublicModelLineageCaptureJournal,
    PublicModelLineageCaptureObservation,
    PublicModelLineageClaim,
    PublicModelLineageClaimKind,
    PublicModelLineageConstraintKind,
    PublicModelLineageDecision,
    PublicModelLineageEvidenceBundle,
    PublicModelLineageNonIndependenceConstraint,
    PublicModelLineageSourceEvidence,
    VerifiedPublicModelLineage,
    _replay_public_model_lineage_for_test,
    _resolve_verified_public_model_lineage,
    _resolve_verified_public_model_lineage_for_test,
    approved_public_model_lineages,
    build_public_model_lineage_evidence_bundle,
    public_model_lineage_inventory,
    require_independent_public_model_lineage,
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.reporting.json_report import stable_json_bytes

RETRIEVED_AT = datetime(2026, 8, 18, 8, 0, tzinfo=UTC)
VERIFIED_AT = RETRIEVED_AT + timedelta(minutes=1)
VALID_UNTIL = VERIFIED_AT + timedelta(days=30)


def _binding(path: str, content: bytes) -> ManifestFileBinding:
    return ManifestFileBinding(
        path=path,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _capture_observation(
    source_id: str,
    publisher_id: str,
    content: bytes,
    *,
    retrieved_at: datetime = RETRIEVED_AT,
) -> PublicModelLineageCaptureObservation:
    url = (
        "https://raw.githubusercontent.com/"
        f"{publisher_id}/model/0123456789abcdef0123456789abcdef01234567/README.md"
    )
    provisional = PublicModelLineageCaptureObservation.model_construct(
        source_id=source_id,
        requested_url=url,
        final_url=url,
        redirect_chain=(url,),
        publisher_id=publisher_id,
        independence_key=publisher_id,
        source_kind="PRIMARY_PUBLISHER_MODEL_CARD",
        immutable_revision="0123456789abcdef0123456789abcdef01234567",
        retrieved_at=retrieved_at,
        media_type="text/markdown",
        file_binding=_binding(f"sources/{source_id}.md", content),
        observation_sha256="0" * 64,
    )
    return PublicModelLineageCaptureObservation(
        source_id=source_id,
        requested_url=url,
        final_url=url,
        redirect_chain=(url,),
        publisher_id=publisher_id,
        independence_key=publisher_id,
        source_kind="PRIMARY_PUBLISHER_MODEL_CARD",
        immutable_revision="0123456789abcdef0123456789abcdef01234567",
        retrieved_at=retrieved_at,
        media_type="text/markdown",
        file_binding=_binding(f"sources/{source_id}.md", content),
        observation_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"observation_sha256"})
        ),
    )


def _capture_journal(
    observations: tuple[PublicModelLineageCaptureObservation, ...],
) -> PublicModelLineageCaptureJournal:
    observation_set_sha256 = canonical_sha256([item.observation_sha256 for item in observations])
    provisional = PublicModelLineageCaptureJournal.model_construct(
        schema_version="1.0",
        sources=observations,
        lineage_identity_authorized=False,
        source_egress_authorized=False,
        provider_call_authorized=False,
        observation_set_sha256=observation_set_sha256,
        bundle_sha256="0" * 64,
    )
    return PublicModelLineageCaptureJournal(
        schema_version="1.0",
        sources=observations,
        lineage_identity_authorized=False,
        source_egress_authorized=False,
        provider_call_authorized=False,
        observation_set_sha256=observation_set_sha256,
        bundle_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"bundle_sha256"})
        ),
    )


def _alias(
    exact_model_id: str, documentary_model_id: str, publisher_id: str, source_id: str
) -> PublicModelLineageAliasBinding:
    alias_id = "alias-" + exact_model_id.replace("/", "-").replace(".", "-")
    provisional = PublicModelLineageAliasBinding.model_construct(
        alias_id=alias_id,
        exact_model_id=exact_model_id,
        documentary_model_id=documentary_model_id,
        publisher_id=publisher_id,
        source_ids=(source_id,),
        alias_sha256="0" * 64,
    )
    return PublicModelLineageAliasBinding(
        alias_id=alias_id,
        exact_model_id=exact_model_id,
        documentary_model_id=documentary_model_id,
        publisher_id=publisher_id,
        source_ids=(source_id,),
        alias_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"alias_sha256"})
        ),
    )


def _claim(
    *,
    claim_id: str,
    subject: str,
    source_id: str,
    content: bytes,
    marker: str,
    kind: PublicModelLineageClaimKind,
    target: str | None = None,
    decisive: bool = True,
) -> PublicModelLineageClaim:
    marker_bytes = marker.encode()
    start = content.index(marker_bytes)
    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    provisional = PublicModelLineageClaim.model_construct(
        claim_id=claim_id,
        subject_exact_model_id=subject,
        claim_kind=kind,
        target_exact_model_id=target,
        source_id=source_id,
        decisive_primary_publisher=decisive,
        byte_start=start,
        byte_end=start + len(marker_bytes),
        exact_marker=marker,
        marker_sha256=marker_sha256,
        claim_sha256="0" * 64,
    )
    return PublicModelLineageClaim(
        claim_id=claim_id,
        subject_exact_model_id=subject,
        claim_kind=kind,
        target_exact_model_id=target,
        source_id=source_id,
        decisive_primary_publisher=decisive,
        byte_start=start,
        byte_end=start + len(marker_bytes),
        exact_marker=marker,
        marker_sha256=marker_sha256,
        claim_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"claim_sha256"})
        ),
    )


def _constraint(
    members: tuple[str, str], claim_ids: tuple[str, ...] = ()
) -> PublicModelLineageNonIndependenceConstraint:
    provisional = PublicModelLineageNonIndependenceConstraint.model_construct(
        constraint_id="constraint-alpha-gamma",
        constraint_kind=PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL,
        member_exact_model_ids=members,
        supporting_claim_ids=claim_ids,
        negative_only=True,
        positive_root_assignment_authorized=False,
        constraint_sha256="0" * 64,
    )
    return PublicModelLineageNonIndependenceConstraint(
        constraint_id="constraint-alpha-gamma",
        constraint_kind=PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL,
        member_exact_model_ids=members,
        supporting_claim_ids=claim_ids,
        negative_only=True,
        positive_root_assignment_authorized=False,
        constraint_sha256=canonical_sha256(
            provisional.model_dump(mode="json", exclude={"constraint_sha256"})
        ),
    )


def _fixture(
    root: Path,
    *,
    include_beta: bool = True,
    include_gamma_claim: bool = True,
    constrain_alpha_gamma: bool = False,
    alpha_suffix: bytes = b"",
    retrieved_at: datetime = RETRIEVED_AT,
    clock: Callable[[], datetime] | None = None,
) -> tuple[str, VerifiedPublicModelLineage]:
    contents = {
        "alpha-card": b"Alpha is trained from scratch by Alpha.\n" + alpha_suffix,
        "beta-card": b"Beta is derived from Alpha.\n",
        "gamma-card": b"Gamma is trained from scratch by Gamma.\n",
    }
    publishers = {"alpha-card": "alpha", "beta-card": "beta", "gamma-card": "gamma"}
    observations = tuple(
        _capture_observation(
            source_id,
            publishers[source_id],
            contents[source_id],
            retrieved_at=retrieved_at,
        )
        for source_id in sorted(contents)
    )
    journal = _capture_journal(observations)
    root.mkdir()
    (root / "sources").mkdir()
    for observation in observations:
        (root / observation.file_binding.path).write_bytes(contents[observation.source_id])
    journal_bytes = stable_json_bytes(journal)
    (root / "capture-observations.json").write_bytes(journal_bytes)

    aliases = [
        _alias("alpha/model-a", "Alpha Model A", "alpha", "alpha-card"),
        _alias("gamma/model-c", "Gamma Model C", "gamma", "gamma-card"),
    ]
    if include_beta:
        aliases.append(_alias("beta/model-b", "Beta Model B", "beta", "beta-card"))
    claims = [
        _claim(
            claim_id="claim-alpha-anchor",
            subject="alpha/model-a",
            source_id="alpha-card",
            content=contents["alpha-card"],
            marker="trained from scratch by Alpha",
            kind=PublicModelLineageClaimKind.ROOT_ANCHOR,
        ),
    ]
    if include_beta:
        claims.append(
            _claim(
                claim_id="claim-beta-alpha",
                subject="beta/model-b",
                source_id="beta-card",
                content=contents["beta-card"],
                marker="derived from Alpha",
                kind=PublicModelLineageClaimKind.ROOTS_WITH,
                target="alpha/model-a",
            )
        )
    if include_gamma_claim:
        claims.append(
            _claim(
                claim_id="claim-gamma-anchor",
                subject="gamma/model-c",
                source_id="gamma-card",
                content=contents["gamma-card"],
                marker="trained from scratch by Gamma",
                kind=PublicModelLineageClaimKind.ROOT_ANCHOR,
            )
        )
    constraints = (
        (_constraint(("alpha/model-a", "gamma/model-c")),) if constrain_alpha_gamma else ()
    )
    bundle = build_public_model_lineage_evidence_bundle(
        capture_observations_file_binding=_binding("capture-observations.json", journal_bytes),
        verified_at=VERIFIED_AT,
        valid_until=VALID_UNTIL,
        sources=tuple(PublicModelLineageSourceEvidence.from_capture(item) for item in observations),
        aliases=tuple(sorted(aliases, key=lambda item: item.exact_model_id)),
        claims=tuple(sorted(claims, key=lambda item: item.claim_id)),
        conservative_non_independence_constraints=constraints,
    )
    manifest_bytes = stable_json_bytes(bundle)
    (root / "manifest.json").write_bytes(manifest_bytes)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    capability = _resolve_verified_public_model_lineage_for_test(
        evidence_root=root,
        expected_manifest_file_sha256=manifest_sha256,
        verification_time=VERIFIED_AT,
        clock=clock,
    )
    return manifest_sha256, capability


def _decision(
    bundle: PublicModelLineageEvidenceBundle, exact_model_id: str
) -> PublicModelLineageDecision:
    return next(item for item in bundle.decisions if item.exact_model_id == exact_model_id)


def test_opaque_capability_replays_exact_roots_and_negative_constraints(tmp_path: Path) -> None:
    _manifest, capability = _fixture(tmp_path / "lineage")
    bundle = _replay_public_model_lineage_for_test(capability)
    alpha = next(item for item in bundle.decisions if item.exact_model_id == "alpha/model-a")
    beta = next(item for item in bundle.decisions if item.exact_model_id == "beta/model-b")
    gamma = next(item for item in bundle.decisions if item.exact_model_id == "gamma/model-c")

    assert alpha.root_lineage == beta.root_lineage
    assert gamma.root_lineage != alpha.root_lineage
    assert bundle.serialized_authority is False
    assert bundle.provider_call_authorized is False
    assert bundle.runner_authority_authorized is False
    assert bundle.production_selection_authorized is False
    assert bundle.benchmark_authorized is False

    for operation in (
        lambda: public_model_lineage_inventory(capability),
        lambda: require_verified_public_model_lineage(capability, "alpha/model-a"),
        lambda: require_independent_public_model_lineage(
            capability, "alpha/model-a", "gamma/model-c"
        ),
        lambda: approved_public_model_lineages(capability),
    ):
        with pytest.raises(PublicModelLineageAuthorityError, match="compiled production"):
            operation()


def test_negative_constraint_never_assigns_a_positive_root(tmp_path: Path) -> None:
    _manifest, capability = _fixture(tmp_path / "lineage", constrain_alpha_gamma=True)
    bundle = _replay_public_model_lineage_for_test(capability)
    alpha = next(item for item in bundle.decisions if item.exact_model_id == "alpha/model-a")
    gamma = next(item for item in bundle.decisions if item.exact_model_id == "gamma/model-c")
    assert alpha.root_lineage != gamma.root_lineage
    assert bundle.conservative_non_independence_constraints[0].negative_only is True
    assert (
        bundle.conservative_non_independence_constraints[0].positive_root_assignment_authorized
        is False
    )


def test_anchor_root_is_stable_when_descendant_inventory_changes(tmp_path: Path) -> None:
    _full_manifest, full = _fixture(tmp_path / "full")
    _subset_manifest, subset = _fixture(tmp_path / "subset", include_beta=False)

    full_bundle = _replay_public_model_lineage_for_test(full)
    subset_bundle = _replay_public_model_lineage_for_test(subset)
    assert (
        _decision(full_bundle, "alpha/model-a").root_lineage
        == _decision(subset_bundle, "alpha/model-a").root_lineage
    )


def test_anchor_root_changes_when_exact_source_evidence_changes(tmp_path: Path) -> None:
    _first_manifest, first = _fixture(tmp_path / "first")
    _second_manifest, second = _fixture(
        tmp_path / "second", alpha_suffix=b"additional exact publisher context\n"
    )

    first_bundle = _replay_public_model_lineage_for_test(first)
    second_bundle = _replay_public_model_lineage_for_test(second)
    assert (
        _decision(first_bundle, "alpha/model-a").root_lineage
        != _decision(second_bundle, "alpha/model-a").root_lineage
    )


def test_anchor_root_is_stable_when_identical_bytes_are_recaptured_later(
    tmp_path: Path,
) -> None:
    _first_manifest, first = _fixture(tmp_path / "first")
    _second_manifest, second = _fixture(
        tmp_path / "second", retrieved_at=RETRIEVED_AT + timedelta(seconds=1)
    )

    first_bundle = _replay_public_model_lineage_for_test(first)
    second_bundle = _replay_public_model_lineage_for_test(second)
    assert first_bundle.bundle_sha256 != second_bundle.bundle_sha256
    assert (
        _decision(first_bundle, "alpha/model-a").root_lineage
        == _decision(second_bundle, "alpha/model-a").root_lineage
    )


def test_unconfirmed_candidate_is_excluded_without_blocking_confirmed(tmp_path: Path) -> None:
    _manifest, capability = _fixture(tmp_path / "lineage", include_gamma_claim=False)
    bundle = _replay_public_model_lineage_for_test(capability)

    assert bundle.confirmed_exact_model_ids == ("alpha/model-a", "beta/model-b")
    assert bundle.unconfirmed_exact_model_ids == ("gamma/model-c",)
    assert bundle.excluded_exact_model_ids == ("gamma/model-c",)
    assert _decision(bundle, "alpha/model-a").root_lineage
    assert _decision(bundle, "gamma/model-c").root_lineage is None


def test_source_tamper_after_issuance_invalidates_capability(tmp_path: Path) -> None:
    root = tmp_path / "lineage"
    _manifest, capability = _fixture(root)
    path = root / "sources" / "alpha-card.md"
    path.write_bytes(b"rewritten\n")
    with pytest.raises(PublicModelLineageAuthorityError, match="source differs"):
        _replay_public_model_lineage_for_test(capability)


def test_opaque_capability_rejects_construction_copy_and_pickle(tmp_path: Path) -> None:
    _manifest, capability = _fixture(tmp_path / "lineage")
    with pytest.raises(TypeError, match="constructed"):
        VerifiedPublicModelLineage()
    with pytest.raises(TypeError, match="copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="serialized"):
        pickle.dumps(capability)


def test_capability_rechecks_verifier_owned_clock_and_expires(tmp_path: Path) -> None:
    observed = [VERIFIED_AT]

    def clock() -> datetime:
        return observed[0]

    _manifest, capability = _fixture(tmp_path / "lineage", clock=clock)
    assert _replay_public_model_lineage_for_test(capability).bundle_sha256
    observed[0] = VALID_UNTIL + timedelta(seconds=1)
    with pytest.raises(PublicModelLineageAuthorityError, match="not current"):
        _replay_public_model_lineage_for_test(capability)


def test_serialized_manifest_never_contains_runtime_authority(tmp_path: Path) -> None:
    root = tmp_path / "lineage"
    _manifest, _capability = _fixture(root)
    payload = json.loads((root / "manifest.json").read_bytes())
    assert payload["serialized_authority"] is False
    assert payload["provider_call_authorized"] is False
    assert payload["source_egress_authorized"] is False
    assert payload["runner_authority_authorized"] is False
    assert payload["model_qualification_authorized"] is False
    assert payload["production_selection_authorized"] is False
    assert payload["seal_publication_authorized"] is False
    assert payload["release_authorized"] is False
    assert payload["benchmark_authorized"] is False
    rendered = (root / "manifest.json").read_text()
    for forbidden in ("api_key", "provider_endpoint", "private_key", "sigstore_bundle"):
        assert forbidden not in rendered


def test_duplicate_key_and_nonfinite_manifest_fail_before_authority(tmp_path: Path) -> None:
    for suffix in (b',"schema_version":"1.0"}', b',"unsafe":NaN}'):
        root = tmp_path / suffix.hex()
        manifest_sha, _capability = _fixture(root)
        original = (root / "manifest.json").read_bytes()
        mutated = original[:-1] + suffix
        (root / "manifest.json").write_bytes(mutated)
        with pytest.raises(PublicModelLineageAuthorityError, match="manifest"):
            _resolve_verified_public_model_lineage_for_test(
                evidence_root=root,
                expected_manifest_file_sha256=hashlib.sha256(mutated).hexdigest(),
                verification_time=VERIFIED_AT,
            )
        assert manifest_sha != hashlib.sha256(mutated).hexdigest()


def test_missing_stale_and_wrong_manifest_pin_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "lineage"
    manifest_sha, _capability = _fixture(root)
    with pytest.raises(PublicModelLineageAuthorityError, match="compiled pin"):
        _resolve_verified_public_model_lineage_for_test(
            evidence_root=root,
            expected_manifest_file_sha256="f" * 64,
            verification_time=VERIFIED_AT,
        )
    with pytest.raises(PublicModelLineageAuthorityError, match="not current"):
        _resolve_verified_public_model_lineage_for_test(
            evidence_root=root,
            expected_manifest_file_sha256=manifest_sha,
            verification_time=VALID_UNTIL + timedelta(seconds=1),
        )
    (root / "manifest.json").unlink()
    with pytest.raises(PublicModelLineageAuthorityError, match="cannot be read"):
        _resolve_verified_public_model_lineage_for_test(
            evidence_root=root,
            expected_manifest_file_sha256=manifest_sha,
            verification_time=VERIFIED_AT,
        )


def test_bundle_builder_bounds_lying_infinite_source_iterable(tmp_path: Path) -> None:
    root = tmp_path / "lineage"
    _manifest, capability = _fixture(root)
    bundle = _replay_public_model_lineage_for_test(capability)
    source = PublicModelLineageSourceEvidence.model_validate_json(
        stable_json_bytes(
            PublicModelLineageSourceEvidence.from_capture(
                _capture_observation("infinite-card", "infinite", b"infinite\n")
            )
        )
    )

    with pytest.raises(ValueError, match="sources exceeds"):
        build_public_model_lineage_evidence_bundle(
            capture_observations_file_binding=_binding("capture-observations.json", b"{}"),
            verified_at=VERIFIED_AT,
            valid_until=VALID_UNTIL,
            sources=repeat(source),
            aliases=(),
            claims=(),
        )
    assert bundle.confirmed_exact_model_ids


def test_direct_internal_resolver_cannot_upgrade_arbitrary_fixture_to_production(
    tmp_path: Path,
) -> None:
    root = tmp_path / "lineage"
    manifest_sha, _capability = _fixture(root)
    with pytest.raises(PublicModelLineageAuthorityError, match="production"):
        _resolve_verified_public_model_lineage(
            evidence_root=root,
            expected_manifest_file_sha256=manifest_sha,
            verification_time=VERIFIED_AT,
            require_production_inventory=True,
            clock=lambda: VERIFIED_AT,
        )


def test_public_resolver_issues_only_for_compiled_production_manifest() -> None:
    capability = resolve_verified_public_model_lineage()
    inventory = public_model_lineage_inventory(capability)
    assert len(inventory.confirmed_exact_model_ids) == 11
    assert inventory.unconfirmed_exact_model_ids == (
        "mistralai/mistral-small-2603",
        "openai/gpt-oss-120b",
        "tencent/hunyuan-a13b-instruct",
        "z-ai/glm-4.7",
    )
    assert inventory.excluded_exact_model_ids == inventory.unconfirmed_exact_model_ids
    assert len(inventory.approved_root_lineages) == 10
    assert inventory.lineage_identity_authorized is True


def test_precaptured_public_authority_rejects_complete_manifest_retarget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    resolver_ref = resolve_verified_public_model_lineage
    inventory_ref = public_model_lineage_inventory
    require_ref = require_verified_public_model_lineage
    production = resolver_ref()
    expected = require_ref(production, "deepseek/deepseek-v3.2-exp")

    forged_root = tmp_path / "forged"
    forged_manifest_sha256, forged_capability = _fixture(forged_root)
    forged = _replay_public_model_lineage_for_test(forged_capability)
    forged_source_pins = tuple(
        (
            item.source_id,
            item.requested_url,
            item.publisher_id,
            item.independence_key,
            item.immutable_revision,
            item.file_binding.path,
        )
        for item in forged.sources
    )
    forged_constraints = tuple(
        (item.constraint_id, item.member_exact_model_ids)
        for item in forged.conservative_non_independence_constraints
    )

    monkeypatch.setattr(lineage_module, "PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT", forged_root)
    monkeypatch.setattr(
        lineage_module,
        "PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256",
        forged_manifest_sha256,
    )
    monkeypatch.setattr(
        lineage_module,
        "PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS",
        tuple(item.exact_model_id for item in forged.aliases),
    )
    monkeypatch.setattr(
        lineage_module,
        "_COMPILED_SOURCE_IDS",
        tuple(item.source_id for item in forged.sources),
    )
    monkeypatch.setattr(lineage_module, "_COMPILED_SOURCE_PINS", forged_source_pins)
    monkeypatch.setattr(
        lineage_module,
        "_COMPILED_CONSERVATIVE_CONSTRAINTS",
        forged_constraints,
    )
    monkeypatch.setattr(lineage_module, "_public_lineage_utc_now", lambda: VERIFIED_AT)

    for operation in (
        resolver_ref,
        lambda: inventory_ref(production),
        lambda: require_ref(production, "alpha/model-a"),
    ):
        with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
            operation()
    assert expected.lineage_identity_authorized is True


@pytest.mark.parametrize(
    "symbol",
    (
        "_derive_public_lineage_decisions",
        "_load_and_verify_bundle",
        "_require_compiled_production_inventory",
        "_stable_root_source_evidence_sha256",
        "read_json_evidence",
        "read_file_evidence",
        "canonical_sha256",
        "stable_json",
    ),
)
def test_precaptured_public_authority_rejects_verifier_helper_reassignment(
    monkeypatch: pytest.MonkeyPatch,
    symbol: str,
) -> None:
    resolver_ref = resolve_verified_public_model_lineage
    monkeypatch.setattr(lineage_module, symbol, object())
    with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
        resolver_ref()


def test_precaptured_consumer_rejects_exported_callable_reassignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver_ref = resolve_verified_public_model_lineage
    require_ref = require_verified_public_model_lineage
    capability = resolver_ref()
    monkeypatch.setattr(lineage_module, "public_model_lineage_inventory", object())
    with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
        require_ref(capability, "deepseek/deepseek-v3.2-exp")


def test_precaptured_resolver_rejects_transitive_hash_and_json_reassignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver_ref = resolve_verified_public_model_lineage
    canonical_helper = vars(lineage_module)["canonical_sha256"]
    stable_helper = vars(lineage_module)["stable_json"]
    assert isinstance(canonical_helper, FunctionType)
    assert isinstance(stable_helper, FunctionType)
    canonical_globals = canonical_helper.__globals__
    stable_globals = stable_helper.__globals__

    with monkeypatch.context() as scoped:
        scoped.setattr(canonical_globals["hashlib"], "sha256", object())
        with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
            resolver_ref()
    with monkeypatch.context() as scoped:
        scoped.setattr(canonical_globals["json"], "dumps", object())
        with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
            resolver_ref()
    with monkeypatch.context() as scoped:
        scoped.setitem(stable_globals, "BaseModel", object())
        with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
            resolver_ref()


@pytest.mark.parametrize(
    ("symbol", "consumer"),
    (
        (
            "VerifiedPublicModelLineageInventory",
            lambda capability: public_model_lineage_inventory(capability),
        ),
        (
            "VerifiedPublicModelLineageBindingProjection",
            lambda capability: require_verified_public_model_lineage(
                capability, "deepseek/deepseek-v3.2-exp"
            ),
        ),
        (
            "VerifiedIndependentPublicModelLineageProjection",
            lambda capability: require_independent_public_model_lineage(
                capability,
                "deepseek/deepseek-v3.2-exp",
                "mistralai/mistral-small-2603",
            ),
        ),
    ),
)
def test_precaptured_consumers_reject_authority_projection_constructor_reassignment(
    monkeypatch: pytest.MonkeyPatch,
    symbol: str,
    consumer: Callable[[VerifiedPublicModelLineage], object],
) -> None:
    capability = resolve_verified_public_model_lineage()
    monkeypatch.setattr(lineage_module, symbol, object())
    with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
        consumer(capability)


def test_precaptured_inventory_rejects_verifier_clock_reassignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver_ref = resolve_verified_public_model_lineage
    inventory_ref = public_model_lineage_inventory
    capability = resolver_ref()

    class ForgedDateTime:
        @classmethod
        def now(cls, _timezone: object) -> datetime:
            del cls
            return VERIFIED_AT

    monkeypatch.setattr(lineage_module, "datetime", ForgedDateTime)
    monkeypatch.setattr(lineage_module, "UTC", object())
    with pytest.raises(PublicModelLineageAuthorityError, match="not pristine"):
        inventory_ref(capability)
