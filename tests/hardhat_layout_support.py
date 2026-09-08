"""Synthetic layout declarations, never tool/image or semantic execution evidence."""

from __future__ import annotations

from pathlib import Path

from mmaudit.isolation.container import (
    HardhatReadOnlyRpcBridgeBinding,
    SingleLoopbackHardhatBackend,
)
from mmaudit.models.schemas import HardhatInventoryPhaseRequest, HardhatTestPhaseRequest
from mmaudit.scanners.read_only_rpc import ReadOnlyRpcBridge
from tests.unit.test_hardhat_protocol import _inventory_request

type LiveLayoutBridge = tuple[
    Path, Path, SingleLoopbackHardhatBackend, ReadOnlyRpcBridge, HardhatReadOnlyRpcBridgeBinding
]


def layout_requests(
    live: LiveLayoutBridge,
) -> tuple[HardhatInventoryPhaseRequest, HardhatTestPhaseRequest]:
    """Join synthetic requests to the owned bridge's actual configuration/state observations."""

    _, _, backend, bridge, _ = live
    values = _inventory_request().model_dump(exclude={"request_sha256"})
    values.update(
        image=backend.image,
        isolation_capability_sha256=backend.hardhat_loopback_capability_sha256,
        bridge_policy_sha256=bridge.live_unix_listener_observation().policy_sha256,
    )
    inventory = HardhatInventoryPhaseRequest.sealed(**values)
    test = HardhatTestPhaseRequest.sealed(
        **inventory.model_dump(exclude={"phase", "phase_sequence", "request_sha256"}),
        inventory_request_sha256=inventory.request_sha256,
        inventory_sha256="b" * 64,
        source_authority_sha256="c" * 64,
        selection_sha256="d" * 64,
        selected_test_count=1,
        per_test_timeout_seconds=1,
        maximum_output_bytes_per_test=1024,
    )
    return inventory, test
