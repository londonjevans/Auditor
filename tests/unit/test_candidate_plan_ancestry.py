from __future__ import annotations

import copy
import gc
import hashlib
import json
import os
import pickle
import sys
import weakref
from pathlib import Path
from types import FunctionType
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry
from typer.testing import CliRunner

import mmaudit.cli as cli_module
import mmaudit.models.candidate_plan_ancestry as ancestry_module
import mmaudit.models.candidate_selection as candidate_selection_module
import mmaudit.release_io as release_io_module
import mmaudit.repository.secrets as secrets_module
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_plan_ancestry import (
    MATCHED_REVOCATION_SET_SHA256,
    SELECTED_ANCESTOR_PLAN_SHA256,
    SELECTED_ANCESTOR_RAW_SHA256,
    UNAVAILABLE_PREDECESSOR_PLAN_SHA256,
    UNAVAILABLE_PREDECESSOR_RAW_SHA256,
    UNAVAILABLE_STATE_SHA256,
    CandidateSelectionPlanAncestryError,
    VerifiedCandidateSelectionPlanAncestry,
    candidate_selection_plan_ancestry_projection,
    derive_candidate_selection_plan_reactivation,
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
    write_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import (
    NO_ACTIVE_CANDIDATE_REQUIREMENT,
    CandidateSelectionError,
    CandidateSelectionPlan,
    load_candidate_selection_plan,
    seal_authenticated_runner_selection,
    validate_candidate_selection_plan_successor,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    ProviderPriceCapAlgorithm,
    RoutePredicateProfile,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

ROOT = Path(__file__).parents[2]
ACTIVE_PLAN_PATH = ROOT / "config" / "models.selection-plan.json"
ANCESTOR_PLAN_PATH = (
    ROOT / "tests" / "fixtures" / "model_selection" / "revoked-active-plan-v1.4.json"
)
RUNNER = CliRunner()
SAFE_CANDIDATE_MODEL_ID = "anthropic/claude-opus-5"
SAFE_CANDIDATE_ENDPOINT = "amazon-bedrock"
REVOKED_CANDIDATE_MODEL_ID = "deepseek/deepseek-v4-pro-0813"
REVOKED_CANDIDATE_ENDPOINT = "parasail/fp8"


def _capability_and_successor() -> tuple[
    VerifiedCandidateSelectionPlanAncestry,
    CandidateSelectionPlan,
]:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    successor = derive_candidate_selection_plan_reactivation(
        capability,
        candidate_model_id=SAFE_CANDIDATE_MODEL_ID,
        provider_endpoint=SAFE_CANDIDATE_ENDPOINT,
    )
    return capability, successor


def _copy_exact_plan_pair(root: Path) -> tuple[str, str]:
    selected_relative = "history/selected.json"
    unavailable_relative = "active/unavailable.json"
    selected_path = root / selected_relative
    unavailable_path = root / unavailable_relative
    selected_path.parent.mkdir(parents=True)
    unavailable_path.parent.mkdir(parents=True)
    selected_path.write_bytes(ANCESTOR_PLAN_PATH.read_bytes())
    unavailable_path.write_bytes(ACTIVE_PLAN_PATH.read_bytes())
    return selected_relative, unavailable_relative


def _verify_test_pair(
    root: Path,
    selected_relative: str,
    unavailable_relative: str,
    *,
    between_reads: Any = None,
) -> object:
    return ancestry_module._verify_candidate_selection_plan_ancestry_for_test(
        root=root,
        selected_relative_path=selected_relative,
        unavailable_relative_path_value=unavailable_relative,
        expected_selected_raw_sha256=SELECTED_ANCESTOR_RAW_SHA256,
        expected_selected_plan_sha256=SELECTED_ANCESTOR_PLAN_SHA256,
        expected_unavailable_raw_sha256=UNAVAILABLE_PREDECESSOR_RAW_SHA256,
        expected_unavailable_plan_sha256=UNAVAILABLE_PREDECESSOR_PLAN_SHA256,
        expected_unavailable_state_sha256=UNAVAILABLE_STATE_SHA256,
        expected_matched_revocation_set_sha256=MATCHED_REVOCATION_SET_SHA256,
        between_reads=between_reads,
    )


def test_repository_plan_ancestry_resolver_replays_exact_chain_and_is_nonauthorizing() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    first = candidate_selection_plan_ancestry_projection(capability)
    second = candidate_selection_plan_ancestry_projection(capability)

    assert first == second
    assert first is not second
    assert first.selected_ancestor_raw_sha256 == SELECTED_ANCESTOR_RAW_SHA256
    assert first.selected_ancestor_plan_sha256 == SELECTED_ANCESTOR_PLAN_SHA256
    assert first.selected_ancestor_byte_count == 14_918
    assert first.unavailable_predecessor_raw_sha256 == UNAVAILABLE_PREDECESSOR_RAW_SHA256
    assert first.unavailable_predecessor_plan_sha256 == UNAVAILABLE_PREDECESSOR_PLAN_SHA256
    assert first.unavailable_predecessor_byte_count == 15_163
    assert first.unavailable_state_sha256 == UNAVAILABLE_STATE_SHA256
    assert first.matched_revocation_set_sha256 == MATCHED_REVOCATION_SET_SHA256
    assert first.exact_successor_replay_verified is True
    assert first.candidate_reactivation_authorized is False
    assert first.provider_call_authorized is False
    assert first.source_egress_authorized is False
    assert first.qualification_authorized is False
    assert first.production_selection_authorized is False
    assert first.runner_authority_authorized is False
    assert first.benchmark_authorized is False
    assert first.seal_publication_authorized is False
    assert first.release_authorized is False
    assert first.serialized_authority is False


def test_reactivation_is_deterministic_immediate_predecessor_bound_and_nonauthorizing() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    first = derive_candidate_selection_plan_reactivation(
        capability,
        candidate_model_id=SAFE_CANDIDATE_MODEL_ID,
        provider_endpoint=SAFE_CANDIDATE_ENDPOINT,
    )
    second = derive_candidate_selection_plan_reactivation(
        capability,
        candidate_model_id=SAFE_CANDIDATE_MODEL_ID,
        provider_endpoint=SAFE_CANDIDATE_ENDPOINT,
    )

    assert first == second
    assert first.schema_version == "1.8"
    assert first.predecessor_plan_sha256 == UNAVAILABLE_PREDECESSOR_PLAN_SHA256
    assert first.endpoint_inventory_refresh is None
    assert first.authenticated_runner_unavailability is None
    assert NO_ACTIVE_CANDIDATE_REQUIREMENT not in first.unresolved_requirements
    selection = first.authenticated_runner_selection
    transition = first.ancestry_transition_binding
    active = load_candidate_selection_plan(ACTIVE_PLAN_PATH)
    unavailable = active.authenticated_runner_unavailability
    assert selection is not None
    assert transition is not None
    assert unavailable is not None
    assert selection.candidate_model_id == SAFE_CANDIDATE_MODEL_ID
    assert selection.primary_judge_model_id == unavailable.primary_judge_model_id
    assert selection.replay_judge_model_id == unavailable.replay_judge_model_id
    assert selection.route_predicate_profile == unavailable.route_predicate_profile
    assert selection.route_predicate_profile.schema_version == "1.0"
    assert (
        selection.route_predicate_profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    )
    assert selection.route_predicate_profile.price_component_unit_envelopes is None
    assert (
        tuple(
            item
            for item in selection.route_constraints
            if item.role is not ExactRouteRole.CANDIDATE
        )
        == unavailable.judge_route_constraints
    )
    candidate_constraint = next(
        item for item in selection.route_constraints if item.role is ExactRouteRole.CANDIDATE
    )
    assert candidate_constraint.provider_endpoint == SAFE_CANDIDATE_ENDPOINT
    assert transition.selected_ancestor_raw_sha256 == SELECTED_ANCESTOR_RAW_SHA256
    assert transition.selected_ancestor_plan_sha256 == SELECTED_ANCESTOR_PLAN_SHA256
    assert transition.unavailable_predecessor_raw_sha256 == UNAVAILABLE_PREDECESSOR_RAW_SHA256
    assert transition.unavailable_predecessor_plan_sha256 == UNAVAILABLE_PREDECESSOR_PLAN_SHA256
    assert transition.unavailable_state_sha256 == UNAVAILABLE_STATE_SHA256
    assert transition.matched_revocation_set_sha256 == MATCHED_REVOCATION_SET_SHA256
    assert transition.replacement_candidate_constraint_sha256 == (
        candidate_constraint.constraint_sha256
    )
    assert transition.opaque_ancestry_capability_required is True
    assert transition.endpoint_inventory_refresh_authorized is False
    assert transition.price_cap_profile_upgrade_authorized is False
    assert transition.production_selection_authorized is False
    assert transition.serialized_authority is False
    assert validate_candidate_selection_plan_reactivation(capability, successor=first) == first

    with pytest.raises(
        CandidateSelectionError, match="separately authenticated ancestry transition"
    ):
        validate_candidate_selection_plan_successor(predecessor=active, successor=first)


def test_reactivation_private_writer_is_fresh_mode_0600_and_collision_safe(
    tmp_path: Path,
) -> None:
    capability, successor = _capability_and_successor()
    output = tmp_path / "private" / "reactivated.json"

    assert (
        write_candidate_selection_plan_reactivation(
            capability,
            path=output,
            successor=successor,
        )
        == successor
    )
    assert output.stat().st_mode & 0o777 == 0o600
    frozen = output.read_bytes()
    assert load_candidate_selection_plan(output) == successor

    with pytest.raises(CandidateSelectionPlanAncestryError, match="could not be published safely"):
        write_candidate_selection_plan_reactivation(
            capability,
            path=output,
            successor=successor,
        )
    assert output.read_bytes() == frozen


@pytest.mark.parametrize(
    ("model_id", "endpoint", "message"),
    (
        (
            REVOKED_CANDIDATE_MODEL_ID,
            REVOKED_CANDIDATE_ENDPOINT,
            "reactivation route is revoked",
        ),
        ("not/in-the-plan", "provider", "outside the plan"),
        (SAFE_CANDIDATE_MODEL_ID, "unlisted-provider", "unlisted endpoint"),
        ("z-ai/glm-5.2", "sail-research/fp8", "collide with a judge"),
    ),
)
def test_reactivation_rejects_revoked_unlisted_and_judge_routes(
    model_id: str,
    endpoint: str,
    message: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()

    with pytest.raises(CandidateSelectionPlanAncestryError, match=message):
        derive_candidate_selection_plan_reactivation(
            capability,
            candidate_model_id=model_id,
            provider_endpoint=endpoint,
        )


def test_reactivation_validator_rejects_coherently_resealed_ancestry_binding() -> None:
    capability, successor = _capability_and_successor()
    payload = successor.model_dump(mode="json")
    transition = payload["ancestry_transition_binding"]
    assert isinstance(transition, dict)
    transition["selected_ancestor_raw_sha256"] = "0" * 64
    transition["binding_sha256"] = canonical_sha256(
        {key: value for key, value in transition.items() if key != "binding_sha256"}
    )
    payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )
    coherently_resealed = CandidateSelectionPlan.model_validate_json(
        stable_json(payload),
        strict=True,
    )

    with pytest.raises(
        CandidateSelectionPlanAncestryError,
        match="differs from exact derivation",
    ):
        validate_candidate_selection_plan_reactivation(
            capability,
            successor=coherently_resealed,
        )


def test_reactivation_binding_rejects_mismatched_revocation_set_digest() -> None:
    _capability, successor = _capability_and_successor()
    transition = successor.ancestry_transition_binding
    assert transition is not None
    payload = transition.model_dump(mode="python")
    payload["matched_revocation_set_sha256"] = "0" * 64
    payload["binding_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "binding_sha256"}
    )

    with pytest.raises(ValueError, match="matched revocation set is inconsistent"):
        type(transition).model_validate(payload, strict=True)


def test_reactivation_schema_rejects_downgrade_and_extra_ancestry_fields() -> None:
    _capability, successor = _capability_and_successor()
    payload = successor.model_dump(mode="json")
    payload["schema_version"] = "1.5"
    payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="ancestry transition differs from its schema"):
        CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)

    root_payload = load_candidate_selection_plan(ANCESTOR_PLAN_PATH).model_dump(mode="json")
    root_payload["unexpected_ancestry_authority"] = True
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        CandidateSelectionPlan.model_validate_json(stable_json(root_payload), strict=True)


def test_ancestry_verifier_rejects_coherent_reseal_wrong_direction_and_format_drift(
    tmp_path: Path,
) -> None:
    selected_relative, unavailable_relative = _copy_exact_plan_pair(tmp_path)
    projection = _verify_test_pair(tmp_path, selected_relative, unavailable_relative)
    assert projection == candidate_selection_plan_ancestry_projection(
        resolve_verified_candidate_selection_plan_ancestry()
    )

    unavailable_path = tmp_path / unavailable_relative
    payload = json.loads(unavailable_path.read_text(encoding="utf-8"))
    payload["unresolved_requirements"] = sorted(
        [*payload["unresolved_requirements"], "Coherently resealed but unpinned."]
    )
    payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )
    unavailable_path.write_text(stable_json(payload), encoding="utf-8")
    with pytest.raises(CandidateSelectionPlanAncestryError, match="raw byte identity changed"):
        _verify_test_pair(tmp_path, selected_relative, unavailable_relative)

    selected_relative, unavailable_relative = _copy_exact_plan_pair(tmp_path / "swapped")
    with pytest.raises(CandidateSelectionPlanAncestryError):
        _verify_test_pair(tmp_path / "swapped", unavailable_relative, selected_relative)

    selected_relative, unavailable_relative = _copy_exact_plan_pair(tmp_path / "formatted")
    formatted_path = tmp_path / "formatted" / unavailable_relative
    formatted_path.write_bytes(formatted_path.read_bytes() + b"\n")
    with pytest.raises(CandidateSelectionPlanAncestryError, match="raw byte identity changed"):
        _verify_test_pair(tmp_path / "formatted", selected_relative, unavailable_relative)


def test_ancestry_verifier_rejects_cross_read_drift(tmp_path: Path) -> None:
    selected_relative, unavailable_relative = _copy_exact_plan_pair(tmp_path)
    unavailable_path = tmp_path / unavailable_relative

    def mutate_between_reads() -> None:
        unavailable_path.write_bytes(unavailable_path.read_bytes() + b"\n")

    with pytest.raises(CandidateSelectionPlanAncestryError, match="raw byte identity changed"):
        _verify_test_pair(
            tmp_path,
            selected_relative,
            unavailable_relative,
            between_reads=mutate_between_reads,
        )


@pytest.mark.parametrize("link_kind", ("symbolic", "hard"))
def test_ancestry_verifier_rejects_link_substitution(
    tmp_path: Path,
    link_kind: str,
) -> None:
    root = tmp_path / link_kind
    selected_relative, unavailable_relative = _copy_exact_plan_pair(root)
    selected_path = root / selected_relative
    linked_target = root / "linked-selected.json"
    linked_target.write_bytes(selected_path.read_bytes())
    selected_path.unlink()
    if link_kind == "symbolic":
        selected_path.symlink_to(linked_target)
    else:
        os.link(linked_target, selected_path)

    with pytest.raises(
        CandidateSelectionPlanAncestryError,
        match="could not be read safely",
    ):
        _verify_test_pair(root, selected_relative, unavailable_relative)


def test_ancestry_capability_rejects_direct_forged_copied_and_serialized_instances() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    with pytest.raises(TypeError, match="cannot be constructed directly"):
        VerifiedCandidateSelectionPlanAncestry()
    with pytest.raises(TypeError, match="cannot be subclassed"):
        type("ForgedAncestry", (VerifiedCandidateSelectionPlanAncestry,), {})
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)

    forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="absent or fork-inherited"):
        candidate_selection_plan_ancestry_projection(forged)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_ancestry_capability_is_rejected_after_fork() -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    read_descriptor, write_descriptor = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_descriptor)
        try:
            candidate_selection_plan_ancestry_projection(capability)
        except CandidateSelectionPlanAncestryError:
            result = b"rejected"
        else:
            result = b"accepted"
        os.write(write_descriptor, result)
        os.close(write_descriptor)
        os._exit(0)
    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"rejected"
    finally:
        os.close(read_descriptor)
        _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_ancestry_runtime_rejects_successor_validator_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        candidate_selection_module,
        "validate_candidate_selection_plan_successor",
        lambda **_kwargs: load_candidate_selection_plan(ACTIVE_PLAN_PATH),
    )

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        resolve_verified_candidate_selection_plan_ancestry()


def test_emit_selection_plan_reactivation_is_provider_free_and_does_not_adopt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_before = ACTIVE_PLAN_PATH.read_bytes()
    external_access: list[str] = []

    def forbidden_external_access(*_args: object, **_kwargs: object) -> None:
        external_access.append("accessed")
        raise AssertionError("reactivation emission must remain provider-free")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_external_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden_external_access)
    output = tmp_path / "private" / "reactivation.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            f"{SAFE_CANDIDATE_MODEL_ID}={SAFE_CANDIDATE_ENDPOINT}",
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.output
    normalized = " ".join(result.output.split())
    assert "NONAUTHORIZING schema-v1.8" in normalized
    assert "retained V1 profile" in normalized
    assert "no provider access occurred" in normalized
    assert "plan was not adopted" in normalized
    assert output.stat().st_mode & 0o777 == 0o600
    assert load_candidate_selection_plan(output).schema_version == "1.8"
    assert ACTIVE_PLAN_PATH.read_bytes() == active_before
    assert external_access == []


def test_emit_selection_plan_reactivation_rejects_revoked_route_before_output_or_egress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external_access: list[str] = []

    def forbidden_external_access(*_args: object, **_kwargs: object) -> None:
        external_access.append("accessed")
        raise AssertionError("revoked reactivation must remain provider-free")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden_external_access)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden_external_access)
    output = tmp_path / "private" / "revoked.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            f"{REVOKED_CANDIDATE_MODEL_ID}={REVOKED_CANDIDATE_ENDPOINT}",
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "reactivation route is revoked" in " ".join(result.output.split())
    assert not output.exists()
    assert external_access == []


def test_compiled_ancestry_raw_hashes_match_repository_bytes() -> None:
    assert hashlib.sha256(ANCESTOR_PLAN_PATH.read_bytes()).hexdigest() == (
        SELECTED_ANCESTOR_RAW_SHA256
    )
    assert hashlib.sha256(ACTIVE_PLAN_PATH.read_bytes()).hexdigest() == (
        UNAVAILABLE_PREDECESSOR_RAW_SHA256
    )


def _runtime_function(name: str) -> FunctionType:
    """Locate one nested runtime function for local integrity regression only."""

    pending = [
        function
        for function in vars(ancestry_module).values()
        if type(function) is FunctionType and function.__module__ == ancestry_module.__name__
    ]
    visited: set[int] = set()
    while pending:
        function = pending.pop()
        if id(function) in visited:
            continue
        visited.add(id(function))
        if function.__name__ == name:
            return function
        for cell in function.__closure__ or ():
            value = cell.cell_contents
            if type(value) is FunctionType and value.__module__ == ancestry_module.__name__:
                pending.append(value)
            elif type(value) is dict:
                pending.extend(item for item in value.values() if type(item) is FunctionType)
    raise AssertionError(f"missing nested runtime function: {name}")


def test_capability_identity_cannot_alias_an_issued_instance_after_class_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
    issued_hash = hash(capability)
    monkeypatch.setattr(
        VerifiedCandidateSelectionPlanAncestry, "__hash__", lambda _self: issued_hash
    )
    monkeypatch.setattr(
        VerifiedCandidateSelectionPlanAncestry, "__eq__", lambda _self, _other: True
    )

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(forged)


@pytest.mark.parametrize(
    "type_name",
    (
        "VerifiedCandidateSelectionPlanAncestry",
        "_VerifiedCandidateSelectionPlanAncestryState",
        "_ObservedCandidateSelectionPlanAncestry",
        "CandidateSelectionPlanAncestryProjection",
    ),
)
def test_ancestry_runtime_rejects_mutated_custody_classes(
    monkeypatch: pytest.MonkeyPatch,
    type_name: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = getattr(ancestry_module, type_name)
    monkeypatch.setattr(
        target,
        "__getattribute__",
        lambda self, name: (
            os.getpid() if name == "process_id" else object.__getattribute__(self, name)
        ),
    )

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize(
    "name",
    (
        "replay",
        "observe_pair",
        "observe_once",
        "load_exact_plan",
        "derive_impl",
        "validate_impl",
        "require_pristine",
        "canonical_sha256_bytes",
        "candidate_selection_plan_ancestry_projection",
    ),
)
def test_ancestry_runtime_rejects_nested_and_exported_function_code_drift(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = _runtime_function(name)
    monkeypatch.setattr(target, "__code__", target.__code__.replace(co_filename="changed-local.py"))

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        resolve_verified_candidate_selection_plan_ancestry()
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        derive_candidate_selection_plan_reactivation(
            capability,
            candidate_model_id=SAFE_CANDIDATE_MODEL_ID,
            provider_endpoint=SAFE_CANDIDATE_ENDPOINT,
        )


@pytest.mark.parametrize("part", ("defaults", "keyword_defaults", "closure", "attributes"))
def test_ancestry_runtime_rejects_nested_function_state_drift(
    monkeypatch: pytest.MonkeyPatch,
    part: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = _runtime_function("observe_pair")
    if part == "defaults":
        monkeypatch.setattr(target, "__defaults__", (None,))
    elif part == "keyword_defaults":
        assert target.__kwdefaults__ is not None
        monkeypatch.setitem(target.__kwdefaults__, "between_reads", lambda: None)
    elif part == "closure":
        assert target.__closure__ is not None
        cell = dict(zip(target.__code__.co_freevars, target.__closure__, strict=True))[
            "observe_once"
        ]
        original = cell.cell_contents
        monkeypatch.setattr(cell, "cell_contents", lambda **kwargs: original(**kwargs))
    else:
        monkeypatch.setitem(target.__dict__, "untrusted_runtime_override", True)

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize(
    "helper",
    (
        "_observe_file_twice",
        "_read_file_once",
        "_open_root",
        "_open_parent",
        "_read_descriptor",
        "_write_file_content",
        "_unlink_created_file_at",
        "_require_same_root",
        "_require_same_relative_file",
        "_stat_identity",
        "_binding",
        "_decode_json",
        "normalize_relative_path",
        "is_sensitive_workspace_path",
    ),
)
def test_ancestry_rejects_transitive_release_io_function_drift_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, helper: str
) -> None:
    capability, successor = _capability_and_successor()
    target = getattr(release_io_module, helper)
    monkeypatch.setattr(target, "__code__", target.__code__.replace(co_filename="changed-local.py"))
    output = tmp_path / "private" / "rejected.json"
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        write_candidate_selection_plan_reactivation(capability, path=output, successor=successor)
    assert not output.parent.exists()


@pytest.mark.parametrize(
    "binding", ("_READ_CHUNK_BYTES", "_NOFOLLOW_FLAG", "_DESCRIPTOR_TRAVERSAL_SUPPORTED")
)
def test_ancestry_rejects_transitive_release_io_global_drift(
    monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    monkeypatch.setattr(release_io_module, binding, 1)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize("name", ("_RootHandle", "_FileObservation", "FileEvidenceObservation"))
def test_ancestry_rejects_transitive_release_io_class_drift(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = getattr(release_io_module, name)
    monkeypatch.setattr(target, "__eq__", lambda _self, _other: True)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize("mutation", ("binding", "defaults", "keyword_defaults", "attributes"))
def test_ancestry_rejects_transitive_release_io_helper_state_drift(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    target = release_io_module._read_file_once
    if mutation == "binding":
        monkeypatch.setattr(release_io_module, "_read_file_once", lambda **kwargs: target(**kwargs))
    elif mutation == "defaults":
        monkeypatch.setattr(target, "__defaults__", (None,))
    elif mutation == "keyword_defaults":
        monkeypatch.setattr(target, "__kwdefaults__", {"max_bytes": 17})
    else:
        monkeypatch.setitem(target.__dict__, "untrusted_override", True)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize("mutation", ("primitive", "nested_helper", "nested_constant", "shadow"))
def test_ancestry_rejects_release_io_dependencies_beyond_the_module(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    if mutation == "primitive":
        original = os.dup
        monkeypatch.setattr(os, "dup", lambda descriptor: original(descriptor))
    elif mutation == "nested_helper":
        target = secrets_module.is_sensitive_workspace_name
        monkeypatch.setattr(target, "__code__", target.__code__.replace(co_filename="changed.py"))
    elif mutation == "nested_constant":
        monkeypatch.setattr(secrets_module, "_CONTROL_PLANE_PATH_SEQUENCES", ())
    else:
        monkeypatch.setattr(release_io_module, "len", len, raising=False)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


def test_ancestry_final_validation_failure_rolls_back_its_private_output(tmp_path: Path) -> None:
    capability, successor = _capability_and_successor()
    output = tmp_path / "private" / "rejected.json"
    target_code = _runtime_function("validate_impl").__code__
    triggered = False
    previous_profile = sys.getprofile()

    def reject_after_write(frame, event, _arg):
        nonlocal triggered
        if event == "call" and frame.f_code is target_code and output.exists():
            triggered = True
            raise CandidateSelectionPlanAncestryError("synthetic final ancestry validation failure")

    try:
        sys.setprofile(reject_after_write)
        with pytest.raises(CandidateSelectionPlanAncestryError, match="synthetic final ancestry"):
            write_candidate_selection_plan_reactivation(
                capability, path=output, successor=successor
            )
    finally:
        sys.setprofile(previous_profile)
    assert triggered
    assert not output.exists()


@pytest.mark.parametrize(
    "entrypoint", ("resolve", "project", "derive", "validate", "write", "test")
)
def test_ancestry_entrypoints_reject_a_disabled_runtime_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    entrypoint: str,
) -> None:
    capability, successor = _capability_and_successor()
    selected_path, unavailable_path = _copy_exact_plan_pair(tmp_path)
    guard = _runtime_function("require_pristine")
    replacement = (lambda: None).__code__.replace(co_freevars=guard.__code__.co_freevars)
    monkeypatch.setattr(guard, "__code__", replacement)
    output = tmp_path / "private" / "should-not-exist.json"

    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        match entrypoint:
            case "resolve":
                resolve_verified_candidate_selection_plan_ancestry()
            case "project":
                candidate_selection_plan_ancestry_projection(capability)
            case "derive":
                derive_candidate_selection_plan_reactivation(
                    capability,
                    candidate_model_id=SAFE_CANDIDATE_MODEL_ID,
                    provider_endpoint=SAFE_CANDIDATE_ENDPOINT,
                )
            case "validate":
                validate_candidate_selection_plan_reactivation(capability, successor=successor)
            case "write":
                write_candidate_selection_plan_reactivation(
                    capability, path=output, successor=successor
                )
            case "test":
                _verify_test_pair(tmp_path, selected_path, unavailable_path)
            case _:
                raise AssertionError("unknown synthetic entrypoint")
    assert not output.exists()


@pytest.mark.parametrize("helper", ("snapshot_function", "function_state_is_current"))
def test_ancestry_runtime_rejects_verifier_metadata_helper_replacement(
    monkeypatch: pytest.MonkeyPatch,
    helper: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    function = _runtime_function(helper)
    replacement = (lambda _state: True).__code__.replace(co_freevars=function.__code__.co_freevars)
    monkeypatch.setattr(function, "__code__", replacement)
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


def test_ancestry_capability_registry_uses_weak_exact_identity_without_retention() -> None:
    function = resolve_verified_candidate_selection_plan_ancestry
    assert function.__closure__ is not None
    cells = dict(zip(function.__code__.co_freevars, function.__closure__, strict=True))
    registry = cells["states"].cell_contents
    capability = resolve_verified_candidate_selection_plan_ancestry()
    identity = id(capability)
    reference = weakref.ref(capability)
    assert type(registry) is dict
    assert registry[identity][0]() is capability
    del capability
    gc.collect()
    assert reference() is None
    assert identity not in registry


@pytest.mark.parametrize("method", ("__new__", "__init_subclass__", "__copy__", "__reduce_ex__"))
def test_ancestry_runtime_seals_capability_descriptor_function_bodies(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    descriptor = vars(VerifiedCandidateSelectionPlanAncestry)[method]
    function = (
        descriptor.__func__ if type(descriptor) in {staticmethod, classmethod} else descriptor
    )
    assert type(function) is FunctionType
    monkeypatch.setattr(
        function, "__code__", function.__code__.replace(co_filename="changed-descriptor.py")
    )
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize(
    "cell_name",
    ("function_states", "function_states_seal", "class_bindings", "mutable_class_bindings"),
)
def test_ancestry_runtime_rejects_replaced_verification_metadata(
    monkeypatch: pytest.MonkeyPatch,
    cell_name: str,
) -> None:
    capability = resolve_verified_candidate_selection_plan_ancestry()
    guard = _runtime_function("require_pristine")
    assert guard.__closure__ is not None
    cells = dict(zip(guard.__code__.co_freevars, guard.__closure__, strict=True))
    monkeypatch.setattr(cells[cell_name], "cell_contents", ())
    with pytest.raises(CandidateSelectionPlanAncestryError, match="runtime boundary changed"):
        candidate_selection_plan_ancestry_projection(capability)


@pytest.mark.parametrize(
    ("model_id", "endpoint"),
    (
        ("google/gemini-3.7-flash", "together"),
        ("x-ai/grok-4.6", "deepinfra"),
        ("meta/muse-spark-1.2", "novita"),
    ),
)
def test_reactivation_narrows_only_the_existing_selected_roster_entry(
    model_id: str,
    endpoint: str,
) -> None:
    before = ACTIVE_PLAN_PATH.read_bytes()
    predecessor = load_candidate_selection_plan(ACTIVE_PLAN_PATH)
    original = {entry.exact_model_id: entry for entry in predecessor.entries}
    assert len(original[model_id].allowed_provider_endpoints) > 1
    capability = resolve_verified_candidate_selection_plan_ancestry()
    successor = derive_candidate_selection_plan_reactivation(
        capability, candidate_model_id=model_id, provider_endpoint=endpoint
    )
    assert (
        validate_candidate_selection_plan_reactivation(capability, successor=successor) == successor
    )
    for entry in successor.entries:
        previous = original[entry.exact_model_id]
        if entry.exact_model_id == model_id:
            assert entry.allowed_provider_endpoints == (endpoint,)
            assert entry.priority_rank == previous.priority_rank
            assert entry.lineage_group_seed_sha256 == previous.lineage_group_seed_sha256
            assert entry.entry_sha256 != previous.entry_sha256
        else:
            assert entry == previous
    assert successor.endpoint_inventory_refresh is None
    assert successor.ancestry_transition_binding is not None
    assert successor.ancestry_transition_binding.endpoint_inventory_refresh_authorized is False
    assert successor.ancestry_transition_binding.price_cap_profile_upgrade_authorized is False
    assert ACTIVE_PLAN_PATH.read_bytes() == before


def _coherently_upgraded_reactivation_payload() -> dict[str, Any]:
    _capability, successor = _capability_and_successor()
    selection = successor.authenticated_runner_selection
    assert selection is not None
    old = selection.route_predicate_profile
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=old.reasoning_policy_sha256,
        reasoning_role_profile_sha256=old.reasoning_role_profile_sha256,
        reasoning_role_binding_sha256=old.reasoning_role_binding_sha256,
        reasoning_control_profile_sha256=old.reasoning_control_profile_sha256,
        reserved_reasoning_tokens=old.reserved_reasoning_tokens,
        minimum_prompt_tokens=old.minimum_prompt_tokens,
        required_output_tokens=old.required_output_tokens,
        minimum_context_tokens=old.minimum_context_tokens,
        price_cap_algorithm=ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2,
    )
    constraints = tuple(
        ExactRouteConstraint.build(
            role=item.role,
            exact_model_id=item.exact_model_id,
            provider_endpoint=item.provider_endpoint,
            profile=profile,
        )
        for item in selection.route_constraints
    )
    rebuilt = seal_authenticated_runner_selection(
        candidate_model_id=selection.candidate_model_id,
        primary_judge_model_id=selection.primary_judge_model_id,
        replay_judge_model_id=selection.replay_judge_model_id,
        route_predicate_profile=profile,
        route_constraints=constraints,
    )
    payload = successor.model_dump(mode="json")
    payload["authenticated_runner_selection"] = rebuilt.model_dump(mode="json")
    binding = payload["ancestry_transition_binding"]
    binding["retained_route_predicate_profile_sha256"] = profile.profile_sha256
    binding["retained_judge_constraint_sha256s"] = sorted(
        item.constraint_sha256 for item in constraints if item.role is not ExactRouteRole.CANDIDATE
    )
    binding["replacement_candidate_constraint_sha256"] = next(
        item.constraint_sha256 for item in constraints if item.role is ExactRouteRole.CANDIDATE
    )
    binding["binding_sha256"] = canonical_sha256(
        {key: value for key, value in binding.items() if key != "binding_sha256"}
    )
    payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "plan_sha256"}
    )
    return payload


@pytest.mark.parametrize("schema_source", ("exported", "model"))
@pytest.mark.parametrize("invalidity", ("missing_selection", "null_selection", "coherent_v2"))
def test_reactivation_schema_requires_selection_and_forbids_coherent_profile_upgrade(
    schema_source: str,
    invalidity: str,
) -> None:
    _capability, successor = _capability_and_successor()
    schema = (
        json.loads((ROOT / "schemas" / "candidate_selection_plan.schema.json").read_bytes())
        if schema_source == "exported"
        else CandidateSelectionPlan.model_json_schema()
    )
    validator = Draft202012Validator(schema, registry=Registry())
    validator.check_schema(schema)
    payload = successor.model_dump(mode="json")
    assert validator.is_valid(payload)
    if invalidity == "missing_selection":
        del payload["authenticated_runner_selection"]
    elif invalidity == "null_selection":
        payload["authenticated_runner_selection"] = None
    else:
        payload = _coherently_upgraded_reactivation_payload()
    assert not validator.is_valid(payload)
    expected = (
        "ancestry transition differs from its reactivated assignment"
        if invalidity == "coherent_v2"
        else "ancestry transition differs from its schema"
    )
    with pytest.raises(ValueError, match=expected):
        CandidateSelectionPlan.model_validate_json(stable_json(payload), strict=True)
