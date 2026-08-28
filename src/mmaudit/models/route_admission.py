"""Selection-bound route admission shared by authenticated runner surfaces.

Discovery publication, registry custody, and live equivalence are deliberately
separate transitions.  This module joins their already-validated evidence without
inventing empirical structured-output or token-detail facts.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from types import CellType, CodeType, FunctionType
from typing import TYPE_CHECKING, Any, cast

from mmaudit.models.candidate_revocation import (
    CandidateSelectionRevocationError,
    require_candidate_assignment_eligible,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    _validate_discovery_route_predicate_evidence,
    require_openrouter_constrained_discovery_publication,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    NormalizedRouteFacts,
    RouteConstraintError,
    RouteConstraintPurpose,
    RoutePredicateProfile,
    RoutePredicateReport,
    bind_live_route_facts,
    bind_registry_route_facts,
    bind_runtime_route_facts,
    evaluate_route_predicates,
    require_route_predicates,
    route_constraint_callables_are_pristine,
    transition_full_campaign_runtime_predicates,
)

if TYPE_CHECKING:
    from mmaudit.models.qualification import CandidateModel, CandidateRegistry, QualificationPolicy
    from mmaudit.models.route_runtime_evidence import VerifiedThreeRouteRuntimeEvidence

type AuthenticatedRunnerRouteArtifacts = tuple[
    CandidateRegistry,
    OpenRouterModelDiscoveryRunManifest,
    tuple[OpenRouterModelDiscoveryEvidence, ...],
]
type _RouteAdmissionFunctionState = tuple[
    FunctionType,
    CodeType,
    tuple[Any, ...] | None,
    dict[str, Any] | None,
    tuple[tuple[str, Any], ...],
    dict[str, Any],
    tuple[CellType, ...] | None,
    tuple[tuple[CellType, object], ...],
    dict[str, Any],
    tuple[tuple[str, Any], ...],
]
type _CandidateRegistryValidationSurface = tuple[
    type[Any],
    type[Any],
    FunctionType,
    FunctionType,
]


class AuthenticatedRunnerRouteAdmissionError(RouteConstraintError):
    """A runner route lacked exact constrained discovery or registry custody."""


def _build_candidate_registry_validation_authority() -> tuple[
    Callable[..., None],
    Callable[[], _CandidateRegistryValidationSurface],
    Callable[[], bool],
]:
    """Install the qualification join once, after its import cycle has completed."""

    empty_cell = object()
    issuer_callable_states: tuple[object, ...] | None = None
    issuer_callable_states_seal: tuple[object, ...] | None = None

    def snapshot(function: FunctionType) -> _RouteAdmissionFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for cell in closure or ():
            try:
                value = cell.cell_contents
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
            function.__globals__,
            closure,
            tuple(closure_values),
            attributes,
            tuple(sorted(attributes.items())),
        )

    def function_state_is_current(state: _RouteAdmissionFunctionState) -> bool:
        (
            function,
            code,
            defaults,
            kwdefaults,
            kwdefault_items,
            function_globals,
            closure,
            closure_values,
            attributes,
            attribute_items,
        ) = state
        current_kwdefaults = function.__kwdefaults__
        current_attributes = function.__dict__
        if (
            type(function) is not FunctionType
            or type(current_kwdefaults) not in {dict, type(None)}
            or type(current_attributes) is not dict
            or function.__code__ is not code
            or function.__defaults__ is not defaults
            or current_kwdefaults is not kwdefaults
            or function.__globals__ is not function_globals
            or function.__closure__ is not closure
            or current_attributes is not attributes
            or len(current_kwdefaults or {}) != len(kwdefault_items)
            or any(
                (current_kwdefaults or {}).get(name) is not value for name, value in kwdefault_items
            )
            or len(current_attributes) != len(attribute_items)
            or any(current_attributes.get(name) is not value for name, value in attribute_items)
        ):
            return False
        current_closure = function.__closure__ or ()
        if len(current_closure) != len(closure_values):
            return False
        for current_cell, (expected_cell, expected_value) in zip(
            current_closure,
            closure_values,
            strict=True,
        ):
            if current_cell is not expected_cell:
                return False
            try:
                current_value = current_cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if current_value is not expected_value:
                return False
        return True

    def pristine_unchecked() -> bool:
        if issuer_callable_states is None or issuer_callable_states_seal is None:
            return issuer_callable_states is None and issuer_callable_states_seal is None
        if (
            type(issuer_callable_states) is not tuple
            or issuer_callable_states_seal is not issuer_callable_states
            or len(issuer_callable_states) != 6
        ):
            return False
        (
            surface,
            module_globals,
            function_states,
            referenced_globals,
            class_bindings,
            mutable_class_bindings,
        ) = issuer_callable_states
        if (
            type(surface) is not tuple
            or len(surface) != 4
            or type(module_globals) is not dict
            or type(function_states) is not tuple
            or not function_states
            or type(referenced_globals) is not tuple
            or type(class_bindings) is not tuple
            or len(class_bindings) != 2
            or type(mutable_class_bindings) is not tuple
        ):
            return False
        candidate_model_type, candidate_registry_type, validator, custody_validator = surface
        qualification_module = sys.modules.get("mmaudit.models.qualification")
        if (
            qualification_module is None
            or vars(qualification_module) is not module_globals
            or module_globals.get("CandidateModel") is not candidate_model_type
            or module_globals.get("CandidateRegistry") is not candidate_registry_type
            or module_globals.get("validate_candidate_registry_discovery") is not validator
            or module_globals.get("_validate_candidate_route_constraint_custody")
            is not custody_validator
            or any(
                globals_dict.get(name) is not expected
                for globals_dict, name, expected in referenced_globals
            )
            or any(not function_state_is_current(state) for state in function_states)
        ):
            return False
        for guarded_type, expected_bindings in class_bindings:
            current_bindings = vars(guarded_type)
            if len(current_bindings) != len(expected_bindings) or any(
                current_bindings.get(name) is not expected for name, expected in expected_bindings
            ):
                return False
        for guarded_type, name, container, expected_items in mutable_class_bindings:
            if vars(guarded_type).get(name) is not container:
                return False
            if type(container) is dict:
                current_items = tuple(container.items())
                if len(current_items) != len(expected_items) or any(
                    not any(
                        current_key is expected_key and current_value is expected_value
                        for current_key, current_value in current_items
                    )
                    for expected_key, expected_value in expected_items
                ):
                    return False
            elif type(container) in {list, set}:
                current_values = tuple(container)
                if len(current_values) != len(expected_items) or any(
                    not any(current is expected for current in current_values)
                    for expected in expected_items
                ):
                    return False
            else:
                return False
        return True

    def pristine() -> bool:
        try:
            return pristine_unchecked()
        except BaseException:
            return False

    def register(
        *,
        module_globals: dict[str, object],
        candidate_model_type: type[Any],
        candidate_registry_type: type[Any],
        validator: FunctionType,
        custody_validator: FunctionType,
    ) -> None:
        nonlocal issuer_callable_states, issuer_callable_states_seal
        qualification_module = sys.modules.get("mmaudit.models.qualification")
        if (
            issuer_callable_states is not None
            or issuer_callable_states_seal is not None
            or type(module_globals) is not dict
            or qualification_module is None
            or vars(qualification_module) is not module_globals
            or not isinstance(candidate_model_type, type)
            or not isinstance(candidate_registry_type, type)
            or candidate_model_type.__module__ != "mmaudit.models.qualification"
            or candidate_model_type.__name__ != "CandidateModel"
            or candidate_registry_type.__module__ != "mmaudit.models.qualification"
            or candidate_registry_type.__name__ != "CandidateRegistry"
            or type(validator) is not FunctionType
            or validator.__module__ != "mmaudit.models.qualification"
            or validator.__name__ != "validate_candidate_registry_discovery"
            or validator.__globals__ is not module_globals
            or type(custody_validator) is not FunctionType
            or custody_validator.__module__ != "mmaudit.models.qualification"
            or custody_validator.__name__ != "_validate_candidate_route_constraint_custody"
            or custody_validator.__globals__ is not module_globals
            or module_globals.get("CandidateModel") is not candidate_model_type
            or module_globals.get("CandidateRegistry") is not candidate_registry_type
            or module_globals.get("validate_candidate_registry_discovery") is not validator
            or module_globals.get("_validate_candidate_route_constraint_custody")
            is not custody_validator
        ):
            raise RuntimeError("candidate registry validation authority registration is invalid")

        roots: list[FunctionType] = [validator, custody_validator]
        descriptor_functions: list[FunctionType] = []
        class_bindings = tuple(
            (guarded_type, tuple(vars(guarded_type).items()))
            for guarded_type in (candidate_model_type, candidate_registry_type)
        )
        mutable_class_bindings = tuple(
            (
                guarded_type,
                name,
                value,
                tuple(value.items()) if type(value) is dict else tuple(value),
            )
            for guarded_type, bindings in class_bindings
            for name, value in bindings
            if type(value) in {dict, list, set}
        )
        for _guarded_type, bindings in class_bindings:
            for _name, descriptor in bindings:
                functions: tuple[FunctionType, ...]
                if type(descriptor) is FunctionType:
                    functions = (descriptor,)
                elif type(descriptor) in {classmethod, staticmethod}:
                    functions = (cast(FunctionType, cast(Any, descriptor).__func__),)
                elif type(descriptor) is property:
                    functions = tuple(
                        function
                        for function in (descriptor.fget, descriptor.fset, descriptor.fdel)
                        if type(function) is FunctionType
                    )
                else:
                    functions = ()
                descriptor_functions.extend(functions)
        roots.extend(descriptor_functions)
        roots = list(dict.fromkeys(roots))
        seen = {id(function) for function in roots}
        cursor = 0
        referenced: dict[tuple[int, str], tuple[dict[str, Any], str, object]] = {}
        while cursor < len(roots):
            function = roots[cursor]
            cursor += 1
            for name in function.__code__.co_names:
                if name not in function.__globals__:
                    continue
                value = function.__globals__[name]
                referenced[(id(function.__globals__), name)] = (
                    function.__globals__,
                    name,
                    value,
                )
                if type(value) is FunctionType and id(value) not in seen:
                    seen.add(id(value))
                    roots.append(value)
        function_states = tuple(snapshot(function) for function in dict.fromkeys(roots))
        installed = (
            (
                candidate_model_type,
                candidate_registry_type,
                validator,
                custody_validator,
            ),
            module_globals,
            function_states,
            tuple(referenced.values()),
            class_bindings,
            mutable_class_bindings,
        )
        issuer_callable_states = installed
        issuer_callable_states_seal = installed
        if not pristine():
            issuer_callable_states = None
            issuer_callable_states_seal = None
            raise RuntimeError("candidate registry validation authority failed to seal")

    def resolve() -> _CandidateRegistryValidationSurface:
        if issuer_callable_states is None:
            __import__("mmaudit.models.qualification")
        if not pristine():
            raise AuthenticatedRunnerRouteAdmissionError(
                "candidate registry validation authority changed"
            )
        if issuer_callable_states is None:
            raise AuthenticatedRunnerRouteAdmissionError(
                "candidate registry validation authority is unavailable"
            )
        surface = issuer_callable_states[0]
        if type(surface) is not tuple or len(surface) != 4:
            raise AuthenticatedRunnerRouteAdmissionError(
                "candidate registry validation authority is unavailable"
            )
        return cast(_CandidateRegistryValidationSurface, surface)

    return register, resolve, pristine


(
    _register_candidate_registry_validation_surface,
    _resolve_candidate_registry_validation_surface,
    _candidate_registry_validation_surface_is_pristine,
) = _build_candidate_registry_validation_authority()
del _build_candidate_registry_validation_authority


def require_authenticated_runner_route_admission(
    *,
    model: CandidateModel,
    evidence: OpenRouterModelDiscoveryEvidence,
    expected_role: ExactRouteRole,
    purpose: RouteConstraintPurpose,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest | None = None,
    runtime_evidence: VerifiedThreeRouteRuntimeEvidence | None = None,
    qualification_policy: QualificationPolicy | None = None,
    frozen_live_equivalent: bool | None = None,
    runtime_required_output_tokens: int | None = None,
) -> RoutePredicateReport:
    """Require one registry-bound route report for an exact runtime purpose."""

    if not route_admission_callables_are_pristine():
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission boundary changed"
        )
    if type(purpose) is not RouteConstraintPurpose:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route purpose has the wrong exact type"
        )
    if (
        runtime_evidence is not None
        and purpose is not RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "runtime route evidence is accepted only for full campaign admission"
        )
    if (
        runtime_evidence is not None
        and type(discovery_manifest) is not OpenRouterModelDiscoveryRunManifest
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "runtime route evidence requires the exact discovery manifest"
        )
    if (runtime_evidence is None) != (qualification_policy is None):
        raise AuthenticatedRunnerRouteAdmissionError(
            "runtime route evidence and qualification policy must be supplied together"
        )
    if purpose in {
        RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
    }:
        if (
            type(runtime_required_output_tokens) is not int
            or not 256 <= runtime_required_output_tokens <= 65_536
        ):
            raise AuthenticatedRunnerRouteAdmissionError(
                "runtime route admission requires an exact output-token envelope"
            )
    elif runtime_required_output_tokens is not None:
        raise AuthenticatedRunnerRouteAdmissionError(
            "publication route admission cannot carry a runtime output-token envelope"
        )
    report = _evaluate_authenticated_runner_route_admission(
        model=model,
        evidence=evidence,
        expected_role=expected_role,
        discovery_manifest=discovery_manifest,
        runtime_evidence=runtime_evidence,
        qualification_policy=qualification_policy,
        frozen_live_equivalent=frozen_live_equivalent,
        runtime_required_output_tokens=runtime_required_output_tokens,
    )
    return require_route_predicates(report, purpose=purpose)


def require_authenticated_runner_three_route_admission(
    *,
    candidate: AuthenticatedRunnerRouteArtifacts,
    primary_judge: AuthenticatedRunnerRouteArtifacts,
    replay_judge: AuthenticatedRunnerRouteArtifacts,
    purpose: RouteConstraintPurpose,
    runtime_evidence: VerifiedThreeRouteRuntimeEvidence | None = None,
    qualification_policy: QualificationPolicy | None = None,
    frozen_live_equivalent: bool | None = None,
    runtime_required_output_tokens: int | None = None,
) -> tuple[RoutePredicateReport, RoutePredicateReport, RoutePredicateReport]:
    """Require candidate, PRIMARY, and REPLAY route reports in exact role order."""

    if not route_admission_callables_are_pristine():
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission boundary changed"
        )
    if type(purpose) is not RouteConstraintPurpose:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route purpose has the wrong exact type"
        )
    if (
        runtime_evidence is not None
        and purpose is not RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "runtime route evidence is accepted only for full campaign admission"
        )
    if (runtime_evidence is None) != (qualification_policy is None):
        raise AuthenticatedRunnerRouteAdmissionError(
            "runtime route evidence and qualification policy must be supplied together"
        )
    if frozen_live_equivalent is not None and type(frozen_live_equivalent) is not bool:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner live-equivalence result has the wrong exact type"
        )
    if purpose in {
        RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
    }:
        if (
            type(runtime_required_output_tokens) is not int
            or not 256 <= runtime_required_output_tokens <= 65_536
        ):
            raise AuthenticatedRunnerRouteAdmissionError(
                "runtime route admission requires an exact output-token envelope"
            )
    elif runtime_required_output_tokens is not None:
        raise AuthenticatedRunnerRouteAdmissionError(
            "publication route admission cannot carry a runtime output-token envelope"
        )
    if (
        purpose is RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION
        and frozen_live_equivalent is None
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "noncrediting smoke admission requires a live-equivalence result"
        )
    reports = (
        _evaluate_singleton_route_artifacts(
            artifacts=candidate,
            expected_role=ExactRouteRole.CANDIDATE,
            runtime_evidence=runtime_evidence,
            qualification_policy=qualification_policy,
            frozen_live_equivalent=frozen_live_equivalent,
            runtime_required_output_tokens=runtime_required_output_tokens,
        ),
        _evaluate_singleton_route_artifacts(
            artifacts=primary_judge,
            expected_role=ExactRouteRole.PRIMARY_JUDGE,
            runtime_evidence=runtime_evidence,
            qualification_policy=qualification_policy,
            frozen_live_equivalent=frozen_live_equivalent,
            runtime_required_output_tokens=runtime_required_output_tokens,
        ),
        _evaluate_singleton_route_artifacts(
            artifacts=replay_judge,
            expected_role=ExactRouteRole.REPLAY_JUDGE,
            runtime_evidence=runtime_evidence,
            qualification_policy=qualification_policy,
            frozen_live_equivalent=frozen_live_equivalent,
            runtime_required_output_tokens=runtime_required_output_tokens,
        ),
    )
    for report in reports:
        require_route_predicates(report, purpose=purpose)
    return reports


def _evaluate_singleton_route_artifacts(
    *,
    artifacts: AuthenticatedRunnerRouteArtifacts,
    expected_role: ExactRouteRole,
    runtime_evidence: VerifiedThreeRouteRuntimeEvidence | None,
    qualification_policy: QualificationPolicy | None,
    frozen_live_equivalent: bool | None,
    runtime_required_output_tokens: int | None,
) -> RoutePredicateReport:
    (
        _candidate_model_type,
        candidate_registry_type,
        _validator,
        _custody_validator,
    ) = _resolve_candidate_registry_validation_surface()
    if not route_admission_callables_are_pristine():
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission boundary changed"
        )

    if type(artifacts) is not tuple or len(artifacts) != 3:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route artifacts have the wrong exact shape"
        )
    registry, manifest, evidence = artifacts
    if (
        type(registry) is not candidate_registry_type
        or type(manifest) is not OpenRouterModelDiscoveryRunManifest
        or type(evidence) is not tuple
        or len(registry.candidates) != 1
        or len(evidence) != 1
        or type(evidence[0]) is not OpenRouterModelDiscoveryEvidence
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route requires one exact registry and discovery"
        )
    try:
        _validate_candidate_registry_discovery(
            registry=registry,
            run_manifest=manifest,
            evidence=evidence,
        )
    except (TypeError, ValueError) as exc:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner registry differs from its discovery"
        ) from exc
    return _evaluate_authenticated_runner_route_admission(
        model=registry.candidates[0],
        evidence=evidence[0],
        expected_role=expected_role,
        discovery_manifest=manifest,
        runtime_evidence=runtime_evidence,
        qualification_policy=qualification_policy,
        frozen_live_equivalent=frozen_live_equivalent,
        runtime_required_output_tokens=runtime_required_output_tokens,
    )


def _evaluate_authenticated_runner_route_admission(
    *,
    model: CandidateModel,
    evidence: OpenRouterModelDiscoveryEvidence,
    expected_role: ExactRouteRole,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest | None,
    runtime_evidence: VerifiedThreeRouteRuntimeEvidence | None,
    qualification_policy: QualificationPolicy | None,
    frozen_live_equivalent: bool | None,
    runtime_required_output_tokens: int | None,
) -> RoutePredicateReport:
    (
        candidate_model_type,
        _candidate_registry_type,
        _validator,
        _custody_validator,
    ) = _resolve_candidate_registry_validation_surface()
    if not route_admission_callables_are_pristine():
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission boundary changed"
        )

    if (
        type(model) is not candidate_model_type
        or type(evidence) is not OpenRouterModelDiscoveryEvidence
        or type(expected_role) is not ExactRouteRole
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission has the wrong exact input type"
        )
    try:
        for model_id in {model.exact_model_id, model.canonical_model_slug}:
            require_candidate_assignment_eligible(
                exact_model_id=model_id,
                provider_endpoint=model.approved_provider_endpoint,
            )
    except CandidateSelectionRevocationError as exc:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner candidate assignment is revoked"
        ) from exc
    if frozen_live_equivalent is not None and type(frozen_live_equivalent) is not bool:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner live-equivalence result has the wrong exact type"
        )
    snapshot = evidence.endpoint_snapshot
    profile = snapshot.route_predicate_profile
    constraint = snapshot.exact_route_constraint
    discovery_facts = snapshot.normalized_route_facts
    discovery_report = snapshot.route_predicate_report
    if (
        type(profile) is not RoutePredicateProfile
        or type(constraint) is not ExactRouteConstraint
        or type(discovery_facts) is not NormalizedRouteFacts
        or type(discovery_report) is not RoutePredicateReport
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route lacks constrained discovery evidence"
        )
    if (
        model.exact_model_id != evidence.exact_model_id
        or model.approved_provider_endpoint != evidence.approved_provider_endpoint
        or constraint.role is not expected_role
        or model.selection_plan_sha256 is None
        or model.route_predicate_profile_sha256 is None
        or model.exact_route_constraint_sha256 is None
        or model.route_predicate_report_sha256 is None
        or model.route_predicate_profile_sha256 != profile.profile_sha256
        or model.exact_route_constraint_sha256 != constraint.constraint_sha256
        or model.selection_plan_sha256 != discovery_facts.expected_selection_plan_sha256
    ):
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner registry route custody differs from constrained discovery"
        )
    try:
        published_report = require_openrouter_constrained_discovery_publication(
            evidence,
            route_predicate_profile=profile,
            exact_route_constraint=constraint,
            expected_selection_plan_sha256=model.selection_plan_sha256,
        )
        if published_report != discovery_report:
            raise AuthenticatedRunnerRouteAdmissionError(
                "authenticated runner discovery report changed before admission"
            )
        registry_facts = bind_registry_route_facts(
            discovery_facts,
            registry_selection_plan_sha256=model.selection_plan_sha256,
            profile=profile,
            constraint=constraint,
        )
        registry_report = evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=registry_facts,
        )
        require_route_predicates(
            registry_report,
            purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
        )
    except AuthenticatedRunnerRouteAdmissionError:
        raise
    except (TypeError, ValueError) as exc:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner registry route report is invalid"
        ) from exc
    if model.route_predicate_report_sha256 != registry_report.report_sha256:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner registry report hash differs from reevaluation"
        )
    admission_facts = registry_facts
    try:
        if frozen_live_equivalent is not None:
            admission_facts = bind_live_route_facts(
                admission_facts,
                frozen_live_equivalent=frozen_live_equivalent,
            )
        if runtime_required_output_tokens is not None:
            admission_facts = bind_runtime_route_facts(
                admission_facts,
                required_output_tokens=runtime_required_output_tokens,
            )
        report = evaluate_route_predicates(
            profile=profile,
            constraint=constraint,
            facts=admission_facts,
        )
        if runtime_evidence is not None:
            if type(discovery_manifest) is not OpenRouterModelDiscoveryRunManifest:
                raise AuthenticatedRunnerRouteAdmissionError(
                    "runtime route evidence requires the exact discovery manifest"
                )
            report = transition_full_campaign_runtime_predicates(
                report,
                runtime_evidence=runtime_evidence,
                qualification_policy=qualification_policy,
                role=expected_role,
                model=model,
                discovery_manifest=discovery_manifest,
                discovery_evidence=evidence,
                facts=admission_facts,
            )
        return report
    except (TypeError, ValueError) as exc:
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner live route report is invalid"
        ) from exc


def _validate_candidate_registry_discovery(
    *,
    registry: CandidateRegistry,
    run_manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
) -> None:
    """Invoke the one-shot registered registry/discovery validator."""

    (
        _candidate_model_type,
        _candidate_registry_type,
        validator,
        _custody_validator,
    ) = _resolve_candidate_registry_validation_surface()
    if not route_admission_callables_are_pristine():
        raise AuthenticatedRunnerRouteAdmissionError(
            "authenticated runner route admission boundary changed"
        )
    validator(
        registry=registry,
        run_manifest=run_manifest,
        evidence=evidence,
    )


def _build_route_admission_callable_guard() -> Callable[[], bool]:
    """Freeze the finite function and alias surface that decides route admission."""

    empty_cell = object()
    late_registered_state = object()
    module_globals = globals()
    root_queue = list(
        cast(
            tuple[FunctionType, ...],
            (
                require_authenticated_runner_route_admission,
                require_authenticated_runner_three_route_admission,
                _evaluate_singleton_route_artifacts,
                _evaluate_authenticated_runner_route_admission,
                _validate_candidate_registry_discovery,
                _register_candidate_registry_validation_surface,
                _resolve_candidate_registry_validation_surface,
                _candidate_registry_validation_surface_is_pristine,
                require_openrouter_constrained_discovery_publication,
                _validate_discovery_route_predicate_evidence,
                bind_registry_route_facts,
                bind_live_route_facts,
                bind_runtime_route_facts,
                evaluate_route_predicates,
                require_route_predicates,
                route_constraint_callables_are_pristine,
            ),
        )
    )
    roots_list: list[FunctionType] = []
    referenced_aliases: dict[tuple[int, str], tuple[dict[str, Any], str, object]] = {}
    seen: set[int] = set()
    while root_queue:
        function = root_queue.pop()
        if id(function) in seen:
            continue
        seen.add(id(function))
        roots_list.append(function)
        for name in function.__code__.co_names:
            if name not in function.__globals__:
                continue
            value = function.__globals__[name]
            referenced_aliases[(id(function.__globals__), name)] = (
                function.__globals__,
                name,
                value,
            )
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in function.__defaults__ or ():
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in (function.__kwdefaults__ or {}).values():
            if type(value) is FunctionType:
                root_queue.append(value)
        for cell in function.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if type(value) is FunctionType:
                root_queue.append(value)
        for value in function.__dict__.values():
            if type(value) is FunctionType:
                root_queue.append(value)
    roots = tuple(roots_list)
    aliases = (
        *(
            (function.__name__, function)
            for function in roots
            if function.__globals__ is module_globals
            and module_globals.get(function.__name__) is function
        ),
        ("_validate_candidate_registry_discovery", _validate_candidate_registry_discovery),
        (
            "_register_candidate_registry_validation_surface",
            _register_candidate_registry_validation_surface,
        ),
        (
            "_resolve_candidate_registry_validation_surface",
            _resolve_candidate_registry_validation_surface,
        ),
        (
            "_candidate_registry_validation_surface_is_pristine",
            _candidate_registry_validation_surface_is_pristine,
        ),
        (
            "require_openrouter_constrained_discovery_publication",
            require_openrouter_constrained_discovery_publication,
        ),
        (
            "_validate_discovery_route_predicate_evidence",
            _validate_discovery_route_predicate_evidence,
        ),
        ("bind_registry_route_facts", bind_registry_route_facts),
        ("bind_live_route_facts", bind_live_route_facts),
        ("evaluate_route_predicates", evaluate_route_predicates),
        ("require_route_predicates", require_route_predicates),
        ("route_constraint_callables_are_pristine", route_constraint_callables_are_pristine),
    )

    def snapshot(function: FunctionType) -> _RouteAdmissionFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for name, cell in zip(
            function.__code__.co_freevars,
            closure or (),
            strict=True,
        ):
            try:
                value = (
                    late_registered_state
                    if name
                    in {
                        "consumer_state",
                        "consumer_state_seal",
                        "issuer_callable_states",
                        "issuer_callable_states_seal",
                    }
                    else cell.cell_contents
                )
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
            function.__globals__,
            closure,
            tuple(closure_values),
            attributes,
            tuple(sorted(attributes.items())),
        )

    states = tuple(snapshot(function) for function in roots)
    external_aliases = tuple(referenced_aliases.values())
    aliases_seal = aliases
    empty_cell_seal = empty_cell
    module_globals_seal = module_globals
    external_aliases_seal = external_aliases
    states_seal = states

    def pristine() -> bool:
        if (
            aliases is not aliases_seal
            or empty_cell is not empty_cell_seal
            or external_aliases is not external_aliases_seal
            or module_globals is not module_globals_seal
            or states is not states_seal
            or module_globals.get("route_admission_callables_are_pristine") is not pristine
        ):
            return False
        if any(module_globals.get(name) is not expected for name, expected in aliases):
            return False
        if any(
            globals_dict.get(name) is not expected
            for globals_dict, name, expected in external_aliases
        ):
            return False
        for state in states:
            (
                function,
                code,
                defaults,
                kwdefaults,
                kwdefault_items,
                function_globals,
                closure,
                closure_values,
                attributes,
                attribute_items,
            ) = state
            current_kwdefaults = function.__kwdefaults__
            current_attributes = function.__dict__
            if (
                type(function) is not FunctionType
                or type(current_kwdefaults) not in {dict, type(None)}
                or type(current_attributes) is not dict
            ):
                return False
            if (
                function.__code__ is not code
                or function.__defaults__ is not defaults
                or current_kwdefaults is not kwdefaults
                or function.__globals__ is not function_globals
                or function.__closure__ is not closure
                or current_attributes is not attributes
                or len(current_kwdefaults or {}) != len(kwdefault_items)
                or any(
                    (current_kwdefaults or {}).get(name) is not value
                    for name, value in kwdefault_items
                )
                or len(current_attributes) != len(attribute_items)
                or any(current_attributes.get(name) is not value for name, value in attribute_items)
            ):
                return False
            current_closure = function.__closure__ or ()
            if len(current_closure) != len(closure_values):
                return False
            for current_cell, (expected_cell, expected_value) in zip(
                current_closure,
                closure_values,
                strict=True,
            ):
                if current_cell is not expected_cell:
                    return False
                try:
                    current_value = current_cell.cell_contents
                except ValueError:
                    current_value = empty_cell
                if (
                    expected_value is not late_registered_state
                    and current_value is not expected_value
                ):
                    return False
        try:
            return bool(
                route_constraint_callables_are_pristine()
                and _candidate_registry_validation_surface_is_pristine()
            )
        except BaseException:
            return False

    return pristine


route_admission_callables_are_pristine = _build_route_admission_callable_guard()
del _build_route_admission_callable_guard
if not route_admission_callables_are_pristine():
    raise RuntimeError("route admission callable boundary failed its initial integrity check")
