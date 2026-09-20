"""Native-origin synthetic AST bytes, never execution or applicability authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from mmaudit.benchmark.mutation_discovery import (
    PortfolioMutationDiscovery,
    discover_portfolio_mutations,
)
from mmaudit.benchmark.mutation_portfolio import SecurityMutationClass
from mmaudit.benchmark.mutations import (
    MutationApplicabilityBinding,
    MutationApplicabilityPlan,
    MutationNonApplicabilityReason,
    MutationNonApplicabilityRecord,
    build_discovered_mutation_plan,
    mutation_repository_sha256,
)
from mmaudit.scanners.foundry_inventory import FoundrySourceInput
from tests.mutation_portfolio_support import CASES, FIXTURE, SOURCE_PATH, property_id

COMPILER_FIXTURE = Path(__file__).parent / "fixtures" / "mutation_discovery"


def fixture_inputs() -> tuple[dict[str, Any], tuple[FoundrySourceInput, ...], str]:
    payload = json.loads((COMPILER_FIXTURE / "build-info.json").read_bytes())
    metadata = json.loads((COMPILER_FIXTURE / "compiler.json").read_bytes())
    content = (FIXTURE / SOURCE_PATH).read_bytes()
    sources = (FoundrySourceInput(SOURCE_PATH, content, hashlib.sha256(content).hexdigest()),)
    assert sources[0].source_sha256 == metadata["source_sha256"]
    return payload, sources, str(metadata["binary_sha256"])


def discover_fixture(**changes: Any) -> PortfolioMutationDiscovery:
    payload, sources, compiler_sha = fixture_inputs()
    values: dict[str, Any] = dict(
        build_info_jsons=(json.dumps(payload).encode(),),
        sources=sources,
        target_paths=(SOURCE_PATH,),
        compiler_version="0.8.30",
        compiler_sha256=compiler_sha,
    )
    return discover_portfolio_mutations(**{**values, **changes})


def declared_fixture_plan(
    discovery: PortfolioMutationDiscovery, source_repository: Path = FIXTURE
) -> MutationApplicabilityPlan:
    """Explicit synthetic class/property assertions, not a production inference rule."""

    bindings = []
    exclusions = []
    for candidate in discovery.candidates:
        spec = candidate.specification
        for kind in SecurityMutationClass:
            if kind is spec.kind:
                bindings.append(
                    MutationApplicabilityBinding(
                        property_id=property_id(kind),
                        mutation_id=spec.id,
                        test_ids=[CASES[kind][1]],
                    )
                )
            else:
                exclusions.append(
                    MutationNonApplicabilityRecord(
                        property_id=property_id(kind),
                        mutation_id=spec.id,
                        reason=MutationNonApplicabilityReason.PROPERTY_SCOPE_MISMATCH,
                        rationale="This synthetic control asserts another explicitly declared class.",
                    )
                )
    return build_discovered_mutation_plan(
        discovery=discovery,
        property_corpus_hash="a" * 64,
        source_repository_sha256=mutation_repository_sha256(source_repository),
        approved_executor_sha256="b" * 64,
        approved_isolation_policy_sha256="c" * 64,
        property_repositories=dict(
            sorted((property_id(kind), "synthetic") for kind in SecurityMutationClass)
        ),
        bindings=sorted(bindings, key=lambda b: (b.property_id, b.mutation_id)),
        non_applicability=sorted(exclusions, key=lambda b: (b.property_id, b.mutation_id)),
    )


def all_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    pending = [payload]
    result = []
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "nodeType" in value:
                result.append(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return result
