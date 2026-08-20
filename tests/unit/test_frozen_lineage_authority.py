from __future__ import annotations

import copy
import dataclasses
import json
import os
import pickle
import shutil
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import mmaudit.models.frozen_lineage_authority as lineage_module
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealDecisionProjection,
    EvidenceSealLineagePair,
)
from mmaudit.models.frozen_lineage_authority import (
    FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILE_SHA256,
    FROZEN_MODEL_LINEAGE_PROVENANCE_FILE_SHA256,
    FROZEN_MODEL_LINEAGE_PROVENANCE_SHA256,
    FROZEN_MODEL_LINEAGE_REGRESSION_FILE_SHA256,
    FROZEN_MODEL_LINEAGE_SOURCE_FILE_SHA256,
    FrozenModelLineageProvenance,
    ModelLineageOriginKind,
    PublicEstablishedModelLineageOrigin,
    SyntheticModelLineageConstruction,
    SyntheticModelLineageGroup,
    VerifiedFrozenModelLineage,
    load_frozen_model_lineage_provenance,
    require_independent_frozen_model_lineage,
    require_verified_frozen_model_lineage,
    resolve_verified_frozen_model_lineage,
)
from mmaudit.models.lineage_authority import TrustedModelLineageReviewVerification
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "model_lineage"
PROVENANCE_PATH = FIXTURE_ROOT / "provenance.json"
REGRESSION_CONTRACT_PATH = FIXTURE_ROOT / "regression_contract.txt"
ALPHA = "synthetic-lineage:alpha/model-core"
ALPHA_ALIAS = "synthetic-lineage:alpha/model-core-v1"
BETA = "synthetic-lineage:beta/model-core"
ALPHA_ROOT = "sha256:a9d4f8d87d11015029ae19cd6bd5beae62363a656d793fda3c02f3be1c687aba"
BETA_ROOT = "sha256:cb7d3388821742bb53f768f6e5bef33cb910e277ec71afd4c49726e4c35173c3"

FALSE_AUTHORITY_FIELDS = (
    "completion_eligible",
    "non_model_authorship_verified",
    "external_provenance_verified",
    "real_provider_model_applicable",
    "lineage_identity_authorized",
    "provider_lineage_authorized",
    "runner_authority_authorized",
    "authority_issuance_authorized",
    "model_qualification_authorized",
    "production_selection_authorized",
    "release_authorized",
    "source_egress_authorized",
    "provider_access_authorized",
)


def _payload() -> dict[str, Any]:
    value = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _parse_provenance(payload: dict[str, Any]) -> FrozenModelLineageProvenance:
    return FrozenModelLineageProvenance.model_validate_json(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        strict=True,
    )


def _reseal_provenance(payload: dict[str, Any]) -> FrozenModelLineageProvenance:
    payload["binding_set_sha256"] = canonical_sha256(payload["bindings"])
    payload.pop("provenance_sha256", None)
    payload["provenance_sha256"] = canonical_sha256(payload)
    return _parse_provenance(payload)


def _copy_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "model-lineage"
    target.mkdir(parents=True)
    for name in ("provenance.json", "manifest.json", "source.txt", "regression_contract.txt"):
        shutil.copyfile(FIXTURE_ROOT / name, target / name)
    return target


def test_committed_fixture_resolves_only_mechanism_projection() -> None:
    provenance = load_frozen_model_lineage_provenance(PROVENANCE_PATH)
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    projection = require_verified_frozen_model_lineage(capability, ALPHA)

    assert provenance.authority_basis == "MECHANISM_ONLY"
    assert provenance.projection_scope == "LOCAL_SYNTHETIC_MECHANISM_TEST"
    assert provenance.provenance_sha256 == FROZEN_MODEL_LINEAGE_PROVENANCE_SHA256
    assert projection.provenance_file_sha256 == FROZEN_MODEL_LINEAGE_PROVENANCE_FILE_SHA256
    assert projection.construction_file_sha256 == FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILE_SHA256
    assert projection.construction_source_file_sha256 == FROZEN_MODEL_LINEAGE_SOURCE_FILE_SHA256
    assert projection.regression_contract_file_sha256 == FROZEN_MODEL_LINEAGE_REGRESSION_FILE_SHA256
    assert projection.exact_model_id == ALPHA
    assert projection.canonical_model_id == ALPHA
    assert projection.root_lineage == ALPHA_ROOT
    assert projection.origin_kind is ModelLineageOriginKind.SYNTHETIC_CONSTRUCTED
    for field in FALSE_AUTHORITY_FIELDS:
        assert getattr(provenance, field) is False
        assert getattr(projection, field) is False


def test_alias_and_independence_are_derived_from_one_registry_state() -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    canonical = require_verified_frozen_model_lineage(capability, ALPHA)
    alias = require_verified_frozen_model_lineage(capability, ALPHA_ALIAS)
    fresh = require_verified_frozen_model_lineage(capability, ALPHA)
    pair = require_independent_frozen_model_lineage(capability, ALPHA, BETA)

    assert canonical == fresh
    assert canonical is not fresh
    assert alias.canonical_model_id == ALPHA
    assert alias.root_lineage == canonical.root_lineage == ALPHA_ROOT
    assert pair.candidate_root_lineage == ALPHA_ROOT
    assert pair.runner_root_lineage == BETA_ROOT
    assert pair.same_root is False


def test_pair_hash_and_all_pair_authority_flags_are_exact() -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    pair = require_independent_frozen_model_lineage(capability, ALPHA, BETA)
    payload = dataclasses.asdict(pair)
    pair_sha256 = payload.pop("pair_sha256")

    assert pair_sha256 == canonical_sha256(payload)
    for field in FALSE_AUTHORITY_FIELDS:
        assert getattr(pair, field) is False


@pytest.mark.parametrize(
    ("candidate", "runner", "message"),
    [
        (ALPHA, ALPHA, "distinct exact"),
        (ALPHA, ALPHA_ALIAS, "same-root"),
    ],
)
def test_independence_rejects_exact_and_alias_collisions(
    candidate: str,
    runner: str,
    message: str,
) -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    with pytest.raises(ValueError, match=message):
        require_independent_frozen_model_lineage(capability, candidate, runner)


@pytest.mark.parametrize(
    "model_id",
    ["openai/gpt-4o", "synthetic-lineage:unknown/model-core", "Synthetic-lineage:x/y"],
)
def test_require_rejects_provider_unknown_and_noncanonical_ids(model_id: str) -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    with pytest.raises(ValueError, match=r"reserved synthetic-lineage|absent"):
        require_verified_frozen_model_lineage(capability, model_id)


def test_capability_blocks_construction_copy_serialization_and_forgery() -> None:
    with pytest.raises(TypeError, match="cannot be constructed"):
        VerifiedFrozenModelLineage()

    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"cannot be copied|cannot be serialized"):
            operation(capability)

    forged = object.__new__(VerifiedFrozenModelLineage)
    with pytest.raises(ValueError, match="authority is absent"):
        require_verified_frozen_model_lineage(forged, ALPHA)

    class CapabilitySubclass(VerifiedFrozenModelLineage):
        pass

    subclass = object.__new__(CapabilitySubclass)
    duck = cast(VerifiedFrozenModelLineage, object())
    for unregistered in (subclass, duck):
        with pytest.raises(ValueError, match="authority is absent"):
            require_verified_frozen_model_lineage(unregistered, ALPHA)
    assert not hasattr(VerifiedFrozenModelLineage, "model_validate")
    assert not hasattr(VerifiedFrozenModelLineage, "model_dump")
    assert not hasattr(VerifiedFrozenModelLineage, "require_model")


def test_projection_mutation_cannot_change_closure_state() -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    projection = require_verified_frozen_model_lineage(capability, ALPHA)
    object.__setattr__(projection, "root_lineage", "sha256:" + "0" * 64)

    rebuilt = require_verified_frozen_model_lineage(capability, ALPHA)
    assert rebuilt.root_lineage == ALPHA_ROOT
    assert rebuilt is not projection


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_capability_and_resolver_fail_before_lock_after_fork() -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    child = os.fork()
    if child == 0:  # pragma: no cover - asserted through the child exit status
        status = 1
        try:
            require_verified_frozen_model_lineage(capability, ALPHA)
        except ValueError as exc:
            if "process fork" in str(exc):
                try:
                    resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
                except ValueError as resolver_exc:
                    if "process fork" in str(resolver_exc):
                        status = 0
        os._exit(status)
    _, wait_status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(wait_status) == 0


def test_compiled_bytes_reject_tamper_and_coherent_reseal(tmp_path: Path) -> None:
    fixture = _copy_fixture(tmp_path)
    (fixture / "source.txt").write_bytes((fixture / "source.txt").read_bytes() + b"\n")
    with pytest.raises(ValueError, match="compiled pins"):
        resolve_verified_frozen_model_lineage(fixture)

    fixture = _copy_fixture(tmp_path / "second")
    payload = _payload()
    payload["objective_sha256"] = "0" * 64
    resealed = _reseal_provenance(payload)
    (fixture / "provenance.json").write_text(stable_json(resealed), encoding="utf-8")
    assert load_frozen_model_lineage_provenance(fixture / "provenance.json") == resealed
    with pytest.raises(ValueError, match="compiled pins"):
        resolve_verified_frozen_model_lineage(fixture)


@pytest.mark.parametrize(
    "filename",
    ("provenance.json", "manifest.json", "source.txt", "regression_contract.txt"),
)
def test_each_compiled_fixture_file_rejects_raw_byte_tamper(
    tmp_path: Path,
    filename: str,
) -> None:
    fixture = _copy_fixture(tmp_path)
    path = fixture / filename
    path.write_bytes(path.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="compiled pins"):
        resolve_verified_frozen_model_lineage(fixture)


def test_descriptor_safe_reads_reject_links_and_path_subclasses(tmp_path: Path) -> None:
    fixture = _copy_fixture(tmp_path)
    source = fixture / "source.txt"
    outside = tmp_path / "outside.txt"
    outside.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(outside)
    with pytest.raises(ValueError, match=r"regular|opened safely|observed safely"):
        resolve_verified_frozen_model_lineage(fixture)

    hardlink_fixture = _copy_fixture(tmp_path / "hardlink")
    linked_source = hardlink_fixture / "source.txt"
    shared_source = tmp_path / "shared-source.txt"
    linked_source.replace(shared_source)
    os.link(shared_source, linked_source)
    with pytest.raises(ValueError, match=r"regular|opened safely|observed safely"):
        resolve_verified_frozen_model_lineage(hardlink_fixture)

    concrete_type = type(Path())

    class PathSubclass(concrete_type):  # type: ignore[misc, valid-type]
        pass

    with pytest.raises(ValueError, match="concrete Path"):
        resolve_verified_frozen_model_lineage(PathSubclass(FIXTURE_ROOT))
    with pytest.raises(ValueError, match="must be a Path"):
        load_frozen_model_lineage_provenance(PathSubclass(PROVENANCE_PATH))


def test_public_established_claim_is_structural_but_has_no_issuer(tmp_path: Path) -> None:
    origin_payload: dict[str, Any] = {
        "origin_kind": "PUBLIC_ESTABLISHED",
        "exact_model_id": "vendor/model-a",
        "non_model_authorship_verified": False,
        "external_provenance_verified": False,
        "public_lineage_id": "PUBLIC-LINEAGE-1",
        "publication_uri": "https://example.org/lineage/PUBLIC-LINEAGE-1",
        "published_at": "2025-01-01T00:00:00Z",
        "publication_artifact_sha256": "1" * 64,
        "publication_proof_kind": "EXTERNAL_TRANSPARENCY_INCLUSION",
        "publication_proof_sha256": "2" * 64,
        "upstream_source_revision": "3" * 64,
    }
    origin_payload["origin_sha256"] = canonical_sha256(origin_payload)
    origin = PublicEstablishedModelLineageOrigin.model_validate_json(
        json.dumps(origin_payload),
        strict=True,
    )
    assert origin.external_provenance_verified is False

    binding_payload: dict[str, Any] = {
        "exact_model_id": "vendor/model-a",
        "canonical_model_id": "vendor/model-a",
        "root_lineage": "sha256:" + "4" * 64,
        "origin": origin.model_dump(mode="json"),
    }
    binding_payload["binding_sha256"] = canonical_sha256(binding_payload)
    payload = _payload()
    payload["bindings"] = [binding_payload]
    provenance = _reseal_provenance(payload)
    fixture = _copy_fixture(tmp_path)
    (fixture / "provenance.json").write_text(stable_json(provenance), encoding="utf-8")

    with pytest.raises(ValueError, match="independent publication verification capability"):
        resolve_verified_frozen_model_lineage(fixture)


def test_construction_enforces_flattened_model_bound() -> None:
    groups: list[dict[str, Any]] = []
    for group_index in range(5):
        author = f"a{group_index:03d}"
        model_ids = [f"synthetic-lineage:{author}/model-{index:02d}" for index in range(32)]
        group_payload: dict[str, Any] = {
            "group_id": f"constructed-root-{author}",
            "canonical_model_id": model_ids[0],
            "model_ids": model_ids,
        }
        group_payload["group_sha256"] = canonical_sha256(group_payload)
        groups.append(group_payload)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "model_identity_domain": "MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1",
        "deployable": False,
        "groups": groups,
    }
    payload["construction_sha256"] = canonical_sha256(payload)

    with pytest.raises(ValidationError, match="total model bound"):
        SyntheticModelLineageConstruction.model_validate_json(
            json.dumps(payload),
            strict=True,
        )


def test_structural_alias_and_canonical_conflicts_fail() -> None:
    payload = _payload()
    payload["bindings"][2]["canonical_model_id"] = ALPHA
    binding = payload["bindings"][2]
    binding.pop("binding_sha256")
    binding["binding_sha256"] = canonical_sha256(binding)
    payload["binding_set_sha256"] = canonical_sha256(payload["bindings"])
    payload.pop("provenance_sha256")
    payload["provenance_sha256"] = canonical_sha256(payload)

    with pytest.raises(
        ValidationError, match=r"canonical model|group inventory|split across roots"
    ):
        _parse_provenance(payload)


def test_root_uses_complete_member_inventory_not_labels_or_canonical_preference() -> None:
    assert REGRESSION_CONTRACT_PATH.read_text(encoding="utf-8") == (
        "MMAUDIT_SYNTHETIC_MODEL_LINEAGE_REGRESSION_V1\n"
        "This fixture is mechanism-only and completion-ineligible.\n"
        "Every model ID uses the reserved non-provider synthetic-lineage: namespace.\n"
        "Canonical membership and alias closure are explicit construction facts.\n"
        "Root identities derive from the reserved domain and complete sorted member inventory; "
        "labels, canonical preference, and unrelated groups do not alter a root.\n"
        "No external provenance, real provider lineage, runner authority, qualification, "
        "selection, release, or authority issuance is established.\n"
    )
    members = (ALPHA, ALPHA_ALIAS)
    expected = lineage_module._synthetic_root_lineage(members)
    assert expected == ALPHA_ROOT
    assert lineage_module._synthetic_root_lineage((ALPHA,)) != expected

    group_payload = {
        "group_id": "constructed-root-renamed",
        "canonical_model_id": ALPHA_ALIAS,
        "model_ids": list(members),
    }
    group = SyntheticModelLineageGroup.model_validate_json(
        json.dumps({**group_payload, "group_sha256": canonical_sha256(group_payload)}),
        strict=True,
    )
    assert lineage_module._synthetic_root_lineage(group.model_ids) == expected


def test_resolver_dependencies_are_captured_against_ordinary_monkeypatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    expected_pair = require_independent_frozen_model_lineage(capability, ALPHA, BETA)

    def forged(*_args: object, **_kwargs: object) -> object:
        return object()

    for name in (
        "_parse_construction_source",
        "_rebuild_synthetic_bindings",
        "_synthetic_root_lineage",
    ):
        monkeypatch.setattr(lineage_module, name, forged)

    with pytest.raises(ValueError):
        resolve_verified_frozen_model_lineage(tmp_path)
    with pytest.raises(ValueError, match="absent"):
        require_verified_frozen_model_lineage(
            capability,
            "synthetic-lineage:forged/model-a",
        )
    assert require_independent_frozen_model_lineage(capability, ALPHA, BETA) == expected_pair


def test_inner_parser_globals_and_exported_pins_cannot_retarget_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forged(*_args: object, **_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(lineage_module, "_parse_json_model", forged)
    monkeypatch.setattr(lineage_module, "stable_json", forged)
    monkeypatch.setattr(lineage_module, "_model_from_json_payload", forged, raising=False)
    monkeypatch.setattr(lineage_module, "read_json_evidence", forged)
    monkeypatch.setattr(lineage_module, "read_file_evidence", forged)
    monkeypatch.setattr(lineage_module, "_parse_construction_source", forged)
    monkeypatch.setattr(lineage_module, "_rebuild_synthetic_bindings", forged)
    for name in (
        "FROZEN_MODEL_LINEAGE_PROVENANCE_FILE_SHA256",
        "FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILE_SHA256",
        "FROZEN_MODEL_LINEAGE_SOURCE_FILE_SHA256",
        "FROZEN_MODEL_LINEAGE_REGRESSION_FILE_SHA256",
        "FROZEN_MODEL_LINEAGE_PROVENANCE_SHA256",
    ):
        monkeypatch.setattr(lineage_module, name, "0" * 64)

    assert not hasattr(lineage_module, "_COMPILED_FIXTURE_PINS")
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    assert require_verified_frozen_model_lineage(capability, ALPHA).root_lineage == ALPHA_ROOT
    with pytest.raises(ValueError, match="absent"):
        require_verified_frozen_model_lineage(
            capability,
            "synthetic-lineage:forged/model-a",
        )


def test_mechanism_values_do_not_bridge_to_existing_authority_consumers() -> None:
    capability = resolve_verified_frozen_model_lineage(FIXTURE_ROOT)
    projection = require_verified_frozen_model_lineage(capability, ALPHA)
    pair = require_independent_frozen_model_lineage(capability, ALPHA, BETA)

    assert not isinstance(capability, TrustedModelLineageReviewVerification)
    with pytest.raises(ValidationError):
        EvidenceSealDecisionProjection.model_validate(dataclasses.asdict(projection))
    with pytest.raises(ValidationError):
        EvidenceSealLineagePair.model_validate(dataclasses.asdict(pair))


def test_durable_models_are_strict_nonauthorizing_values() -> None:
    payload = _payload()
    payload["completion_eligible"] = True
    with pytest.raises(ValidationError, match="literal false"):
        _parse_provenance(payload)

    payload = _payload()
    payload["caller_label"] = "authority"
    with pytest.raises(ValidationError, match="extra"):
        _parse_provenance(payload)


def test_documented_threat_boundary_does_not_claim_hostile_interpreter_security() -> None:
    doc = VerifiedFrozenModelLineage.__doc__ or ""
    assert "interpreter and imported verifier code are trusted" in doc
    assert "hostile same-interpreter reflection" in doc
