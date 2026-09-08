"""Safe source-local state-machine inputs for prepared invariant-runner plumbing."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from mmaudit.models.schemas import (
    ForkActor,
    FoundryInvariantHarnessSpec,
    InvariantProbe,
    InvariantPropertySpec,
    LocalInvariantDeployment,
    SolidityProjectMetadata,
    SolidityProjectType,
    StatefulActionSpec,
)

SYNTHETIC_TARGET = "0x2000000000000000000000000000000000000002"


def local_invariant_inputs(
    repository: Path,
) -> tuple[SolidityProjectMetadata, FoundryInvariantHarnessSpec]:
    source_dir = repository / "src"
    source_dir.mkdir()
    shutil.copyfile(
        Path(__file__).parent / "fixtures/solidity/economic_state_ordering/src/StateOrdering.sol",
        source_dir / "StateOrdering.sol",
    )
    project = SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-managed-local-state",
        name="ManagedLocalState",
        actors=[ForkActor(name="observer", address="0x1000000000000000000000000000000000000001")],
        local_deployments=[
            LocalInvariantDeployment(
                target_alias="FixtureMachine",
                contract_name="SafePreparedStateMachine",
                source_path="src/StateOrdering.sol",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="PrepareState",
                target="FixtureMachine",
                function_signature="preparePreset()",
                actor_names=["observer"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="PreparedStateIsNotFinalized",
                left=InvariantProbe(target="FixtureMachine", function_signature="invalidState()"),
                relation="eq",
                expected_uint=0,
            )
        ],
        runs=2,
        depth=1,
        seed=7,
        assumptions=["Synthetic local plumbing fixture; no live addresses or external RPC."],
    )
    return project, specification


def local_invariant_control_output() -> str:
    """Fixed process-control response; not actual Forge or Solidity evidence."""

    return json.dumps(
        {
            "test/MMAuditInvariant.t.sol:MMAuditInvariant": {
                "test_results": {
                    "invariant_PreparedStateIsNotFinalized()": {
                        "status": "Success",
                        "kind": {
                            "Invariant": {
                                "runs": 2,
                                "calls": 2,
                                "metrics": {"MMAuditHandler.action_PrepareState": {"calls": 2}},
                            }
                        },
                    }
                }
            }
        },
        sort_keys=True,
    )
