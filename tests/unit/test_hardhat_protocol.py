from __future__ import annotations

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import HardhatInventoryPhaseRequest, HardhatTestPhaseRequest
from mmaudit.scanners.hardhat_protocol import seal_hardhat_inventory_phase_request

_BLOCK_HASH = "0x" + "f" * 64
_SEED = "0x" + "0" * 63 + "1"


def _inventory_request() -> HardhatInventoryPhaseRequest:
    return seal_hardhat_inventory_phase_request(
        attempt_sha256="1" * 64,
        repository_sha256="2" * 64,
        repository_exclusion_path=".mmaudit",
        configuration_sha256="3" * 64,
        image="registry.example/mmaudit-hardhat@sha256:" + "4" * 64,
        container_executable_sha256="5" * 64,
        isolation_capability_sha256="6" * 64,
        bridge_policy_sha256="7" * 64,
        reporter_version="1.0.0",
        reporter_sha256="8" * 64,
        reporter_schema_sha256="9" * 64,
        chain_id=31_337,
        block_number=0,
        block_hash=_BLOCK_HASH,
        fuzz_seed=_SEED,
        timeout_seconds=10,
        maximum_output_bytes=100_000,
    )


def test_inventory_phase_request_is_strict_self_hashed_and_non_crediting() -> None:
    request = _inventory_request()
    assert request.request_sha256 == request.expected_request_sha256()
    assert request.execution_credit is False

    tampered = request.model_dump(mode="json")
    tampered["image"] = "registry.example/other@sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="request hash"):
        HardhatInventoryPhaseRequest.model_validate(tampered)

    extra = request.model_dump(mode="json")
    extra["execution_credit"] = True
    extra["untrusted_extension"] = "ignored only by unsafe parsers"
    with pytest.raises(ValidationError):
        HardhatInventoryPhaseRequest.model_validate(extra)


def test_test_phase_request_rejects_zero_bindings_and_inconsistent_limits() -> None:
    inventory = _inventory_request()
    values = {
        **inventory.model_dump(mode="json", exclude={"phase", "phase_sequence", "request_sha256"}),
        "reporter_schema_sha256": "a" * 64,
        "inventory_request_sha256": inventory.request_sha256,
        "inventory_sha256": "b" * 64,
        "source_authority_sha256": "c" * 64,
        "selection_sha256": "d" * 64,
        "selected_test_count": 1,
        "per_test_timeout_seconds": 5,
        "maximum_output_bytes_per_test": 10_000,
    }
    request = HardhatTestPhaseRequest.sealed(**values)
    assert request.execution_credit is False
    assert request.request_sha256 == request.expected_request_sha256()

    with pytest.raises(ValidationError, match="zero phase identity"):
        HardhatTestPhaseRequest.sealed(**{**values, "inventory_sha256": "0" * 64})
    with pytest.raises(ValidationError, match="per-test timeout"):
        HardhatTestPhaseRequest.sealed(
            **{**values, "timeout_seconds": 1, "per_test_timeout_seconds": 2}
        )
    with pytest.raises(ValidationError, match="output ceiling"):
        HardhatTestPhaseRequest.sealed(
            **{
                **values,
                "maximum_output_bytes": 2_048,
                "maximum_output_bytes_per_test": 4_096,
            }
        )
