"""Non-authorizing configuration projection for verified public model lineage.

This module deliberately does not mutate :class:`~mmaudit.config.AuditConfig`.
The existing ``approved_model_lineages`` field participates in provider-egress
checks, while documentary lineage alone authorizes identity only.  The values
below are therefore a frozen handoff to the later authenticated-runner ticket,
and can be derived only by replaying an opaque
:class:`~mmaudit.models.public_lineage_authority.VerifiedPublicModelLineage`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

import mmaudit.models.public_lineage_authority as public_lineage_authority
from mmaudit.models.public_lineage_authority import (
    PublicModelLineageNonIndependenceConstraint,
    VerifiedPublicModelLineage,
    VerifiedPublicModelLineageBindingProjection,
    VerifiedPublicModelLineageInventory,
    approved_public_model_lineages,
    public_model_lineage_inventory,
    require_verified_public_model_lineage,
)


@dataclass(frozen=True, slots=True)
class PublicModelLineageConfigurationProjection:
    """Config-ready identity values that grant no runtime or release authority."""

    bundle_sha256: str
    manifest_file_sha256: str
    eligible_exact_candidate_ids: tuple[str, ...]
    excluded_unconfirmed_exact_model_ids: tuple[str, ...]
    approved_model_lineages: tuple[str, ...]
    confirmed_bindings: tuple[VerifiedPublicModelLineageBindingProjection, ...]
    conservative_non_independence_constraints: tuple[
        PublicModelLineageNonIndependenceConstraint, ...
    ]
    serialized_authority: Literal[False] = field(default=False, init=False)
    provider_call_authorized: Literal[False] = field(default=False, init=False)
    source_egress_authorized: Literal[False] = field(default=False, init=False)
    runner_authority_authorized: Literal[False] = field(default=False, init=False)
    model_qualification_authorized: Literal[False] = field(default=False, init=False)
    production_selection_authorized: Literal[False] = field(default=False, init=False)
    seal_publication_authorized: Literal[False] = field(default=False, init=False)
    release_authorized: Literal[False] = field(default=False, init=False)
    benchmark_authorized: Literal[False] = field(default=False, init=False)


def _build_public_lineage_configuration_projector() -> Callable[
    [VerifiedPublicModelLineage], PublicModelLineageConfigurationProjection
]:
    """Capture every positive input and output binding against ordinary reassignment."""

    namespace = globals()
    trusted_authority_module = public_lineage_authority
    trusted_inventory = public_model_lineage_inventory
    trusted_require = require_verified_public_model_lineage
    trusted_approved = approved_public_model_lineages
    trusted_capability_type = VerifiedPublicModelLineage
    trusted_inventory_type = VerifiedPublicModelLineageInventory
    trusted_binding_type = VerifiedPublicModelLineageBindingProjection
    trusted_constraint_type = PublicModelLineageNonIndependenceConstraint
    trusted_projection_type = PublicModelLineageConfigurationProjection
    trusted_tuple = tuple
    trusted_set = set
    trusted_sorted = sorted
    trusted_any = any
    trusted_type = type
    public_binding: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            namespace.get("public_lineage_authority") is not trusted_authority_module
            or namespace.get("public_model_lineage_inventory") is not trusted_inventory
            or namespace.get("require_verified_public_model_lineage") is not trusted_require
            or namespace.get("approved_public_model_lineages") is not trusted_approved
            or namespace.get("VerifiedPublicModelLineage") is not trusted_capability_type
            or namespace.get("VerifiedPublicModelLineageInventory") is not trusted_inventory_type
            or namespace.get("VerifiedPublicModelLineageBindingProjection")
            is not trusted_binding_type
            or namespace.get("PublicModelLineageNonIndependenceConstraint")
            is not trusted_constraint_type
            or namespace.get("PublicModelLineageConfigurationProjection")
            is not trusted_projection_type
            or trusted_authority_module.public_model_lineage_inventory is not trusted_inventory
            or trusted_authority_module.require_verified_public_model_lineage is not trusted_require
            or trusted_authority_module.approved_public_model_lineages is not trusted_approved
            or trusted_any(
                namespace.get(name) is not value for name, value in public_binding.items()
            )
        ):
            raise ValueError("trusted public lineage resolver binding changed")

    def project(
        capability: VerifiedPublicModelLineage,
    ) -> PublicModelLineageConfigurationProjection:
        """Derive confirmed config values from one exact live documentary capability."""

        require_pristine()
        inventory = trusted_inventory(capability)
        if trusted_type(inventory) is not trusted_inventory_type:
            raise ValueError("public lineage inventory has an invalid authority type")

        confirmed_ids = inventory.confirmed_exact_model_ids
        unconfirmed_ids = inventory.unconfirmed_exact_model_ids
        excluded_ids = inventory.excluded_exact_model_ids
        if (
            confirmed_ids != trusted_tuple(trusted_sorted(trusted_set(confirmed_ids)))
            or unconfirmed_ids != trusted_tuple(trusted_sorted(trusted_set(unconfirmed_ids)))
            or excluded_ids != unconfirmed_ids
            or trusted_set(confirmed_ids) & trusted_set(unconfirmed_ids)
        ):
            raise ValueError("public lineage inclusion and exclusion inventory is inconsistent")

        bindings = trusted_tuple(
            trusted_require(capability, exact_model_id) for exact_model_id in confirmed_ids
        )
        if (
            trusted_tuple(binding.exact_model_id for binding in bindings) != confirmed_ids
            or bindings != inventory.confirmed_bindings
            or trusted_any(
                trusted_type(binding) is not trusted_binding_type
                or binding.bundle_sha256 != inventory.bundle_sha256
                or binding.manifest_file_sha256 != inventory.manifest_file_sha256
                or binding.lineage_identity_authorized is not True
                or binding.provider_call_authorized is not False
                or binding.source_egress_authorized is not False
                or binding.runner_authority_authorized is not False
                or binding.model_qualification_authorized is not False
                or binding.production_selection_authorized is not False
                or binding.seal_publication_authorized is not False
                or binding.release_authorized is not False
                or binding.benchmark_authorized is not False
                for binding in bindings
            )
        ):
            raise ValueError("public lineage confirmed bindings are inconsistent")

        approved_roots = trusted_approved(capability)
        binding_roots = trusted_tuple(
            trusted_sorted({binding.root_lineage for binding in bindings})
        )
        if (
            approved_roots != inventory.approved_root_lineages
            or approved_roots != binding_roots
            or approved_roots != trusted_tuple(trusted_sorted(trusted_set(approved_roots)))
        ):
            raise ValueError("public lineage approved-root projection is inconsistent")

        constraints = inventory.conservative_non_independence_constraints
        if trusted_any(
            trusted_type(constraint) is not trusted_constraint_type
            or constraint.negative_only is not True
            or constraint.positive_root_assignment_authorized is not False
            for constraint in constraints
        ):
            raise ValueError("public lineage non-independence constraint is not negative-only")

        if (
            inventory.lineage_identity_authorized is not True
            or inventory.provider_call_authorized is not False
            or inventory.source_egress_authorized is not False
            or inventory.runner_authority_authorized is not False
            or inventory.model_qualification_authorized is not False
            or inventory.production_selection_authorized is not False
            or inventory.seal_publication_authorized is not False
            or inventory.release_authorized is not False
            or inventory.benchmark_authorized is not False
        ):
            raise ValueError(
                "public lineage inventory crosses its identity-only authority boundary"
            )

        result = trusted_projection_type(
            bundle_sha256=inventory.bundle_sha256,
            manifest_file_sha256=inventory.manifest_file_sha256,
            eligible_exact_candidate_ids=confirmed_ids,
            excluded_unconfirmed_exact_model_ids=excluded_ids,
            approved_model_lineages=approved_roots,
            confirmed_bindings=bindings,
            conservative_non_independence_constraints=constraints,
        )
        require_pristine()
        return result

    public_binding["project_public_model_lineage_configuration"] = project
    return project


project_public_model_lineage_configuration = _build_public_lineage_configuration_projector()
del _build_public_lineage_configuration_projector
