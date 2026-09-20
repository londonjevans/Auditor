"""Synthetic typed guard properties and original normalized compiler snapshots."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.models.schemas import (
    DynamicPropertySpec,
    FoundryInvariantHarnessSpec,
    InvariantTemplate,
    PropertyCorpus,
    RepositorySuiteInventoryEvidence,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.scanners.foundry_inventory import (
    FoundryInventoryLimits,
    FoundrySourceInput,
    parse_foundry_compiler_statement_catalog,
    parse_foundry_test_inventory,
)
from mmaudit.scanners.foundry_inventory_runner import (
    FoundryCompilerInputSnapshot,
    FoundryInventoryRunResult,
)
from mmaudit.solidity.properties import _corpus, generated_local_property_source
from tests.property_mutation_support import property_inputs

FIXTURE = Path(__file__).parent / "fixtures/property_reachability"
SOURCE = "src/GuardedValue.sol"


def guard_inputs(
    project_root: str = ".",
    *,
    source_text: str | None = None,
) -> tuple[PropertyCorpus, list[FoundryInvariantHarnessSpec]]:
    original, harnesses = property_inputs()
    base = next(p for p in original.properties if p.property_id == "Authorization")
    harness = next(h for h in harnesses if h.name == "Authorization")
    text = (FIXTURE / SOURCE).read_text() if source_text is None else source_text
    lines = text.splitlines()
    properties = []
    selected = []
    for name, function, probe, template in (
        ("Pause", "changePaused", "pausedValue()", InvariantTemplate.PAUSE_ENFORCEMENT),
        ("Fresh", "changeFresh", "freshValue()", InvariantTemplate.ORACLE_GUARD_SANITY),
    ):
        start = next(i for i, line in enumerate(lines, 1) if f"function {function}(" in line)
        end = next(i for i in range(start, len(lines) + 1) if lines[i - 1].strip() == "}")
        value = harness.model_dump(mode="python")
        value["name"] = name
        value["invariant_id"] = "inv-" + name
        value["actions"][0].update(target="GuardedValue", function_signature=function + "(uint256)")
        value["properties"][0]["property_id"] = name
        value["properties"][0]["left"].update(target="GuardedValue", function_signature=probe)
        value["local_deployments"][0].update(
            target_alias="GuardedValue", contract_name="GuardedValue", source_path=SOURCE
        )
        generated = FoundryInvariantHarnessSpec.model_validate(value)
        prop = base.model_dump(mode="json")
        prop.update(
            invariant_id=generated.invariant_id,
            harness_name=name,
            property_id=name,
            title=f"Synthetic {name} guard preserves its counter",
            template=template.value,
            predicate=generated.properties[0].model_dump(mode="json"),
            actions=[a.model_dump(mode="json") for a in generated.actions],
            target_aliases=["GuardedValue"],
            covered_entity_ids=["synthetic:" + name],
            covered_functions=sorted([probe, function + "(uint256)"]),
        )
        prop["source_evidence"][0].update(entity_id="synthetic:" + name)
        prop["source_evidence"][0]["location"].update(
            path=(PurePosixPath(project_root) / SOURCE).as_posix(),
            start_line=start,
            end_line=end,
            symbol=function,
            content_hash=line_range_hash(text, start, end),
        )
        digest = DynamicPropertySpec.calculate_hash(prop)
        prop.update(id="prop-" + digest[:24], property_hash=digest)
        properties.append(DynamicPropertySpec.model_validate(prop))
        selected.append(generated)
    return _corpus(properties, []), selected


def inventory_snapshot(result: FoundryInventoryRunResult) -> dict[str, Any]:
    return {
        "scope": "SYNTHETIC_COMPILER_REFERENCE_GUARDS_MOCK_NO_RUNTIME_AUTHORITY",
        "evidence": result.evidence.model_dump(mode="json"),
        "accounted_output_bytes": result.accounted_output_bytes,
        "generated_artifact_bytes": result.generated_artifact_bytes,
        "snapshots": [
            dict(
                project_root=s.project_root,
                forge_list_json=s.forge_list_json.decode(),
                build_info_jsons=[raw.decode() for raw in s.build_info_jsons],
                sources=[dict(path=x.path, source_sha256=x.source_sha256) for x in s.sources],
                parser_limits=s.parser_limits.model_dump(mode="json"),
            )
            for s in result.compiler_inputs
        ],
    }


def retained_guard_fixture() -> FoundryInventoryRunResult:
    value = json.loads((FIXTURE / "snapshot.json").read_bytes())
    evidence = RepositorySuiteInventoryEvidence.model_validate(value["evidence"])
    _, harnesses = guard_inputs()
    sources = {SOURCE: (FIXTURE / SOURCE).read_bytes()}
    for harness in harnesses:
        generated = generated_local_property_source(
            harness, project_root=".", expected_chain_id=31337
        )
        assert generated is not None
        sources[generated[0]] = generated[1]
    snapshots = tuple(
        FoundryCompilerInputSnapshot(
            project_root=s["project_root"],
            forge_list_json=s["forge_list_json"].encode(),
            build_info_jsons=tuple(raw.encode() for raw in s["build_info_jsons"]),
            sources=tuple(
                FoundrySourceInput(x["path"], sources[x["path"]], x["source_sha256"])
                for x in s["sources"]
            ),
            parser_limits=FoundryInventoryLimits.model_validate(s["parser_limits"]),
        )
        for s in value["snapshots"]
    )
    inventories, catalogs = [], []
    for snapshot in snapshots:
        common: dict[str, Any] = dict(
            build_info_jsons=snapshot.build_info_jsons,
            sources=snapshot.sources,
            project_root=snapshot.project_root,
            compiler_version=evidence.compiler_version,
            compiler_sha256=evidence.compiler_sha256,
            limits=snapshot.parser_limits,
        )
        inventories.append(
            parse_foundry_test_inventory(forge_list_json=snapshot.forge_list_json, **common)
        )
        catalogs.append(parse_foundry_compiler_statement_catalog(**common))
    return FoundryInventoryRunResult(
        inventories=tuple(inventories),
        statement_catalogs=tuple(catalogs),
        evidence=evidence,
        accounted_output_bytes=value["accounted_output_bytes"],
        generated_artifact_bytes=value["generated_artifact_bytes"],
        compiler_inputs=snapshots,
    )
