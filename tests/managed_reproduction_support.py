"""Typed controls for the non-deployable ControlB administrator invariant."""

from __future__ import annotations

from mmaudit.models.schemas import GeneratedFoundryTestSpec, SolidityProjectMetadata

SYNTHETIC_TARGET = "0x2000000000000000000000000000000000000002"
SYNTHETIC_RPC_ENV = "MMAUDIT_SYNTHETIC_REPRODUCTION_RPC"
SYNTHETIC_RPC = "http://127.0.0.1:18547"


def managed_reproduction_inputs() -> tuple[SolidityProjectMetadata, GeneratedFoundryTestSpec]:
    """Describe a safe local control; the RPC literal is never connected in these tests."""

    return (
        SolidityProjectMetadata(project_type="foundry", project_root=".", source_directories=["."]),
        GeneratedFoundryTestSpec(
            candidate_id="candidate-managed-control",
            name="AdministratorRequired",
            test_type="authorization_matrix",
            rationale="Synthetic ControlB invariant: only its administrator may change the limit.",
            actors=[{"name": "observer", "address": "0x1000000000000000000000000000000000000001"}],
            attacker_policy={"attacker_controlled_actors": ["observer"]},
            attack_calls=[
                {
                    "step_id": "UnauthorizedChange",
                    "actor": "observer",
                    "target": "ControlB",
                    "function_signature": "setLimit(uint256)",
                    "arguments": [{"kind": "uint256", "value": "1"}],
                }
            ],
            assertions=[{"kind": "call_reverts", "step_id": "UnauthorizedChange"}],
            assumptions=["Synthetic non-deployable control; no real address, chain or RPC use."],
            required_block_number=7,
            expected_chain_id=31337,
        ),
    )
