"""Source-backed synthetic predicates and original native compiler snapshots; no audit authority."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from mmaudit.benchmark.mutations import (
    MutationApplicabilityPlan,
    build_property_bound_inventory_mutation_plan,
)
from mmaudit.models.schemas import (
    AnalysisState,
    ForkActor,
    ForkArgument,
    ForkArgumentKind,
    FoundryInvariantHarnessSpec,
    HarnessArgument,
    HarnessArgumentSource,
    InvariantCategory,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    InvariantSpec,
    InvariantSuite,
    InvariantTemplate,
    LocalInvariantDeployment,
    PropertyCorpus,
    RepositorySuiteInventoryEvidence,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProvenance,
    SoliditySymbolIndex,
    StatefulActionSpec,
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
from mmaudit.solidity.properties import build_property_corpus, generated_local_property_source

FIXTURE = Path(__file__).parent / "fixtures/property_mutation"
SOURCE = "src/LocalAccounting.sol"


def property_inputs(
    project_root: str = ".",
) -> tuple[PropertyCorpus, list[FoundryInvariantHarnessSpec]]:
    raw = (FIXTURE / SOURCE).read_bytes()
    text = raw.decode()
    path = (PurePosixPath(project_root) / SOURCE).as_posix()
    entities = []
    invariants = []
    harnesses = []
    for name, function, probe, expected, template in (
        (
            "Authorization",
            "setAccounted",
            "accounted()",
            0,
            InvariantTemplate.AUTHORIZED_ADMIN_CHANGE,
        ),
        ("Scaling", "scaled", "scaled(uint256)", 10**18, InvariantTemplate.ROUNDING_BOUNDS),
    ):
        lines = text.splitlines(keepends=True)
        start = next(i for i, line in enumerate(lines, 1) if f"function {function}(" in line)
        end = next(i for i in range(start, len(lines) + 1) if lines[i - 1].strip() == "}")
        entity = SolidityEntity(
            id=f"synthetic:{name}",
            kind=SolidityEntityKind.FUNCTION,
            name=function,
            contract_name="LocalAccounting",
            path=path,
            start_line=start,
            end_line=end,
            byte_start=len("".join(lines[: start - 1]).encode()),
            byte_end=len("".join(lines[:end]).encode()),
            source_hash=line_range_hash(text, start, end),
            provenance=SolidityProvenance.FALLBACK,
            confidence=0.7,
            transformation="synthetic_explicit_source_entity",
            signature=f"{function}(uint256)",
            visibility="external",
        )
        invariant = InvariantSpec(
            id=f"inv-{name}",
            title=f"Synthetic {name} property",
            category=InvariantCategory.ACCOUNTING,
            description="Local-only source-backed defensive control, not a protocol audit.",
            template=template,
            locations=[
                dict(
                    path=path,
                    start_line=start,
                    end_line=end,
                    symbol=function,
                    content_hash=entity.source_hash,
                )
            ],
            entity_ids=[entity.id],
            functions=[entity.signature],
            provenance=SolidityProvenance.FALLBACK,
            confidence=0.7,
            template_available=True,
            executable=True,
            analysis_state=AnalysisState.FALLBACK_PARSER,
            evidence_hash=hashlib.sha256(name.encode() + raw).hexdigest(),
        )
        harness = FoundryInvariantHarnessSpec(
            invariant_id=invariant.id,
            name=name,
            actors=[ForkActor(name="alice", address="0x1000000000000000000000000000000000000001")],
            actions=[
                StatefulActionSpec(
                    action_id="Exercise",
                    target="LocalAccounting",
                    function_signature=f"{function}(uint256)",
                    actor_names=["alice"],
                    arguments=[
                        HarnessArgument(
                            kind=ForkArgumentKind.UINT256,
                            source=HarnessArgumentSource.CONSTANT,
                            value="1",
                        )
                    ],
                )
            ],
            properties=[
                InvariantPropertySpec(
                    property_id=name,
                    left=InvariantProbe(
                        target="LocalAccounting",
                        function_signature=probe,
                        arguments=[]
                        if name == "Authorization"
                        else [ForkArgument(kind=ForkArgumentKind.UINT256, value="1")],
                    ),
                    relation=InvariantRelation.EQ,
                    expected_uint=expected,
                    required_action_ids=["Exercise"],
                )
            ],
            local_deployments=[
                LocalInvariantDeployment(
                    target_alias="LocalAccounting",
                    contract_name="LocalAccounting",
                    source_path=SOURCE,
                )
            ],
            runs=8,
            depth=4,
            seed=1,
        )
        entities.append(entity)
        invariants.append(invariant)
        harnesses.append(harness)
    index = SoliditySymbolIndex(projects=[], entities=entities, fallback_sources=[path])
    suite = InvariantSuite(invariants=invariants, templates_available_count=2, executable_count=2)
    return build_property_corpus(suite, index, harnesses), harnesses


def property_plan(
    result: FoundryInventoryRunResult, project_root: str = "."
) -> MutationApplicabilityPlan:
    corpus, harnesses = property_inputs(project_root)
    return build_property_bound_inventory_mutation_plan(
        inventory_result=result,
        project_root=project_root,
        target_paths=(SOURCE,),
        corpus=corpus,
        harnesses=harnesses,
        repository_id="synthetic-property-control",
        approved_executor_sha256="d" * 64,
        approved_isolation_policy_sha256="e" * 64,
    )


def retained_property_fixture() -> FoundryInventoryRunResult:
    data = json.loads((FIXTURE / "snapshot.json").read_bytes())
    evidence = RepositorySuiteInventoryEvidence.model_validate(data["evidence"])
    corpus, harnesses = property_inputs()
    assert len(corpus.properties) == 2
    sources = {SOURCE: (FIXTURE / SOURCE).read_bytes()}
    for harness in harnesses:
        generated = generated_local_property_source(harness, project_root=".")
        assert generated is not None
        sources[generated[0]] = generated[1]
    snapshots = tuple(
        FoundryCompilerInputSnapshot(
            project_root=s["project_root"],
            forge_list_json=s["forge_list_json"].encode(),
            build_info_jsons=tuple(raw.encode() for raw in s["build_info_jsons"]),
            sources=tuple(
                FoundrySourceInput(item["path"], sources[item["path"]], item["source_sha256"])
                for item in s["sources"]
            ),
            parser_limits=FoundryInventoryLimits.model_validate(s["parser_limits"]),
        )
        for s in data["snapshots"]
    )
    inventories = []
    catalogs = []
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
        accounted_output_bytes=data["accounted_output_bytes"],
        generated_artifact_bytes=data["generated_artifact_bytes"],
        compiler_inputs=snapshots,
    )
