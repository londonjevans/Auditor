"""Bounded expansions of a local abstract fixture, never real protocol or provider metadata."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from tests.development_cost_support import FIXTURE
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_tree_support import tree_policy

TEMPLATE = Path(__file__).parent / "fixtures/solidity/development_tree_capacity/CapacityFixture.sol"


def capacity_source(index, size=None, *, imports=()):
    source = TEMPLATE.read_bytes().replace(b"CapacityFixture", f"Capacity{index:03d}".encode())
    source = source.replace(
        b"// CAPACITY_IMPORTS", b"\n".join(f'import "{p}";'.encode() for p in imports)
    )
    if size is not None:
        assert len(source) + 6 <= size <= 8_388_608 + 1
        source += b"\n/*" + b"x" * (size - len(source) - 6) + b"*/\n"
        assert len(source) == size
    return source


def capacity_policy(count, *, prompt=12_000_000):
    """Cheap fake prices isolate source capacity without weakening the real spending policy."""
    roles = []
    for model in ENSEMBLE_MODELS:
        endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
        endpoint.update(
            max_prompt_tokens=prompt,
            context_length=prompt + 65_536,
            max_completion_tokens=65_536,
            pricing={
                "prompt": "0.000000001",
                "completion": "0.000000001",
                "input_cache_read": "0.000000001",
                "input_cache_write": "0",
                "request": "0.02",
                "web_search": "0",
                "image": "0",
            },
        )
        roles.append(
            validate_openrouter_endpoint_snapshot(
                exact_model_id=model,
                configured_provider_endpoints=(endpoint["tag"],),
                provider_policy_mode="only",
                endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
                require_zdr=True,
                zdr_payload={"data": [{**endpoint, "model_id": model}]},
            )
        )
    return tree_policy(
        role_metadata=tuple(roles),
        cost_policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("250"),
            per_attempt_budget_usd=Decimal("0.05"),
            request_timeout_seconds=1,
        ),
        maximum_total_seconds=count * 60,
    )


def capacity_inputs(tmp_path, files, *, policy=None):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    for name, content in files:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    remappings = tmp_path / "remappings.txt"
    remappings.write_bytes(b"")
    policy_file = tmp_path / "policy.json"
    policy_file.write_text((policy or capacity_policy(len(files))).model_dump_json())
    return dict(
        corpus_root=source,
        remappings_file=remappings,
        policy_file=policy_file,
        corpus_id="synthetic-capacity-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        output_dir=tmp_path / "planned",
    )
