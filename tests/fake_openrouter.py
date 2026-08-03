"""Deterministic local OpenRouter transport used by integration tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from tests.conftest import MODEL_IDS

_OUTPUT_PROTOCOL_OPEN = "<MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL>"
_OUTPUT_PROTOCOL_CLOSE = "</MMAUDIT_STRUCTURED_OUTPUT_PROTOCOL>"


def _request_schema_name(body: dict[str, Any]) -> str:
    response_format = body.get("response_format")
    if isinstance(response_format, dict):
        json_schema = response_format.get("json_schema")
        if isinstance(json_schema, dict) and isinstance(json_schema.get("name"), str):
            return json_schema["name"]
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages or not isinstance(messages[0], dict):
        raise AssertionError("synthetic request omitted structured-output protocol")
    system_prompt = messages[0].get("content")
    if not isinstance(system_prompt, str):
        raise AssertionError("synthetic request omitted system prompt")
    try:
        protocol_text = system_prompt.split(_OUTPUT_PROTOCOL_OPEN, 1)[1].split(
            _OUTPUT_PROTOCOL_CLOSE,
            1,
        )[0]
        protocol = json.loads(protocol_text)
    except (IndexError, json.JSONDecodeError) as exc:
        raise AssertionError("synthetic request has an invalid output protocol") from exc
    schema_name = protocol.get("schema_name") if isinstance(protocol, dict) else None
    if not isinstance(schema_name, str):
        raise AssertionError("synthetic request output protocol omitted schema name")
    return schema_name


def _candidate(
    *,
    candidate_id: str,
    role: str,
    title: str = "SQL injection in user search",
    path: str = "app.py",
    start_line: int = 11,
    end_line: int = 14,
    cwe: str = "CWE-89",
    symbol: str | None = None,
    severity: str = "high",
) -> dict[str, Any]:
    source_line = start_line
    sink_line = end_line
    if symbol is None:
        symbol = (
            "search_users" if path == "app.py" else ("withdraw" if path.endswith(".sol") else None)
        )
    return {
        "candidate_id": candidate_id,
        "origin_kind": "model_review",
        "execution_provenance": None,
        "title": title,
        "severity": severity,
        "confidence": 0.92,
        "cwe": [cwe],
        "owasp": ["A03:2021"],
        "summary": "Attacker-controlled text reaches a synthetic dangerous operation.",
        "impact": "An authenticated user can affect synthetic data outside intended constraints.",
        "preconditions": ["The attacker can invoke the local fixture function"],
        "locations": [
            {
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "symbol": symbol,
                "content_hash": None,
            }
        ],
        "source": {
            "description": "Attacker-controlled function argument",
            "path": path,
            "line": source_line,
        },
        "sink": {
            "description": "Dangerous synthetic operation",
            "path": path,
            "line": sink_line,
        },
        "attack_path": [
            "Call the local fixture with crafted input",
            "Input reaches the synthetic operation",
        ],
        "evidence": [
            {
                "type": "model",
                "source": role,
                "description": "Direct source-to-sink trace in supplied lines",
                "rule_id": None,
                "fingerprint": None,
            }
        ],
        "compensating_controls": [],
        "false_positive_conditions": ["A control outside supplied context blocks the operation"],
        "recommendation": "Use a constrained, parameterized operation.",
        "verification_test": {
            "type": "local",
            "description": "Exercise the function with a synthetic in-memory dependency",
            "safe": True,
        },
        "role": role,
        "model_family": "caller-overwrites-this",
        "model_votes": [],
    }


def _threat_model() -> dict[str, Any]:
    return {
        "assets": ["Synthetic tenant data", "Synthetic account balances"],
        "trust_boundaries": [
            {
                "name": "Function input boundary",
                "description": "Untrusted arguments enter fixture functions",
                "locations": [],
            }
        ],
        "attacker_controlled_inputs": ["query", "filename", "project_id", "user_url"],
        "identities_and_roles": ["authenticated synthetic user"],
        "sensitive_data": ["synthetic project records"],
        "external_integrations": ["URL fetch helper"],
        "attack_surfaces": ["user search", "file download", "URL preview"],
        "missing_controls": ["tenant constraint", "URL allowlist"],
        "review_targets": ["app.py"],
    }


def _solidity_candidate(candidate_id: str, role: str) -> dict[str, Any]:
    return _candidate(
        candidate_id=candidate_id,
        role=role,
        title="Vault withdrawal authorization bypass",
        path="src/Vault.sol",
        start_line=20,
        end_line=22,
        cwe="CWE-862",
        symbol="withdraw",
    )


def _exploit_tests(user: str) -> dict[str, Any]:
    payload = _extract_json(user, "REPRODUCTION_INPUT_JSON")
    available_targets = payload.get("available_targets") or ["Vault"]
    attacker_address = "0x1000000000000000000000000000000000000001"
    signatures = {
        ("AccessVault", "drain"): (
            "drain(address)",
            [{"kind": "address", "value": attacker_address}],
        ),
        ("Vault", "withdraw"): (
            "withdraw(uint256)",
            [{"kind": "uint256", "value": "1"}],
        ),
        ("ReentrantBank", "withdraw"): ("withdraw()", []),
        ("SpotOracleLender", "borrow"): (
            "borrow(uint256)",
            [{"kind": "uint256", "value": "1"}],
        ),
        ("UnsafeUUPS", "upgradeTo"): (
            "upgradeTo(address)",
            [{"kind": "address", "value": attacker_address}],
        ),
        ("SafeControls", "rescue"): (
            "rescue(address)",
            [{"kind": "address", "value": attacker_address}],
        ),
    }
    tests: list[dict[str, Any]] = []
    for index, candidate in enumerate(payload.get("candidates", []), start=1):
        locations = candidate.get("locations") or []
        if not locations or not str(locations[0].get("path", "")).endswith(".sol"):
            continue
        location = locations[0]
        contract_name = str(location["path"]).rsplit("/", 1)[-1].removesuffix(".sol")
        symbol = str(location.get("symbol") or "withdraw")
        default_signature = (
            "withdraw(uint256)",
            [{"kind": "uint256", "value": "1"}],
        )
        function_signature, arguments = signatures.get(
            (contract_name, symbol),
            default_signature,
        )
        target = contract_name if contract_name in available_targets else str(available_targets[0])
        tests.append(
            {
                "candidate_id": candidate["candidate_id"],
                "name": f"Exploit{index}",
                "test_type": "authorization_matrix",
                "rationale": "Check whether an unprivileged actor can call the claimed sensitive function.",
                "actors": [
                    {
                        "name": "Attacker",
                        "address": "0x1000000000000000000000000000000000000001",
                        "initial_native_balance_wei": 10**18,
                    }
                ],
                "attacker_policy": {
                    "attacker_controlled_actors": ["Attacker"],
                    "attacker_controlled_contracts": [],
                    "starting_native_capital_wei": 10**18,
                    "flash_liquidity_wei": 0,
                    "token_approval_targets": [],
                    "max_time_shift_seconds": 0,
                    "max_block_advance": 0,
                    "transaction_ordering": "none",
                    "oracle_influence": "none",
                    "governance_rights": False,
                    "privileged_roles": [],
                    "cross_chain_messages": "none",
                    "capability_justifications": {
                        "starting_capital": "Synthetic local starting balance."
                    },
                },
                "setup_calls": [],
                "attack_calls": [
                    {
                        "step_id": "UnauthorizedWithdraw",
                        "actor": "Attacker",
                        "target": target,
                        "function_signature": function_signature,
                        "arguments": arguments,
                        "value_wei": 0,
                        "required_capabilities": [],
                    }
                ],
                "assertions": [
                    {
                        "kind": "call_succeeds",
                        "step_id": "UnauthorizedWithdraw",
                        "address": None,
                        "expected_uint": None,
                        "expected_bool": None,
                    }
                ],
                "financial_settlement": None,
                "assumptions": [
                    "Configured Vault address points to the target contract on the pinned local fork."
                ],
                "required_block_number": payload.get("pinned_block_number"),
                "expected_chain_id": payload.get("expected_chain_id"),
                "generator_role": "",
                "generator_model_family": "",
            }
        )
    return {"tests": tests}


def _falsification(user: str) -> dict[str, Any]:
    payload = _extract_json(user, "FALSIFICATION_INPUT_JSON")
    results = {
        (result["candidate_id"], result["test_name"]): result
        for result in payload.get("execution_results", [])
    }
    decisions: list[dict[str, Any]] = []
    for test in payload.get("test_specifications", []):
        result = results.get((test["candidate_id"], test["name"]), {})
        state = result.get("state")
        if state in {"reproduced", "reproduced_and_minimized"}:
            verdict = "accepted"
            rationale = "The generated test matches the authorization claim and reproduced it."
        elif state == "not_reproduced":
            verdict = "falsified"
            rationale = "The generated test fully exercised the claim and did not reproduce it."
        else:
            verdict = "inconclusive"
            rationale = "The execution result was not sufficient to prove or disprove the claim."
        decisions.append(
            {
                "candidate_id": test["candidate_id"],
                "test_name": test["name"],
                "verdict": verdict,
                "test_matches_claim": True,
                "assumptions_validated": state
                in {"reproduced", "reproduced_and_minimized", "not_reproduced"},
                "rationale": rationale,
                "contradictions": []
                if verdict != "falsified"
                else ["patched access control blocked the claim"],
            }
        )
    return {"decisions": decisions}


def _invariant_review(user: str) -> dict[str, Any]:
    payload = _extract_json(user, "DETERMINISTIC_SOLIDITY_FACTS_JSON")
    entities = (payload.get("symbol_index") or {}).get("entities") or []
    borrow = next(
        (
            entity
            for entity in entities
            if entity.get("name") == "borrow" and entity.get("path") == "src/SpotOracleLender.sol"
        ),
        None,
    )
    if borrow is None:
        return {"decisions": [], "proposals": []}
    return {
        "decisions": [],
        "proposals": [
            {
                "title": "Borrowing should resist same-transaction spot-price movement",
                "category": "economic",
                "description": (
                    "Borrowing power should not increase solely because the configured spot "
                    "price moves within the attack transaction."
                ),
                "template": "oracle_manipulation_resistance",
                "locations": [
                    {
                        "path": borrow["path"],
                        "start_line": borrow["start_line"],
                        "end_line": borrow["end_line"],
                        "symbol": "borrow",
                        "content_hash": None,
                    }
                ],
                "entity_ids": [borrow["id"]],
                "state_variables": [],
                "functions": ["borrow"],
                "protocol_profiles": ["lending"],
                "assumptions": ["The configured pool exposes a manipulable spot price."],
                "confidence": 0.9,
                "rationale": "The indexed borrow function consumes spotPrice directly.",
            }
        ],
    }


def _extract_json(content: str, tag: str) -> Any:
    start = f"<{tag}>\n"
    end = f"\n</{tag}>"
    return json.loads(content.split(start, 1)[1].split(end, 1)[0])


def _extract_optional_json(content: str, tag: str) -> Any | None:
    start = f"<{tag}>\n"
    end = f"\n</{tag}>"
    if start not in content or end not in content:
        return None
    return json.loads(content.split(start, 1)[1].split(end, 1)[0])


def _requested_surface_ids_for_path(
    user_prompt: str,
    expected_path: str,
) -> tuple[str, ...]:
    """Return exact typed surface identities bound to one indexed source path."""

    requests = _extract_json(user_prompt, "TRUSTED_MODEL_SURFACE_REQUESTS_JSON")
    solidity_facts = _extract_json(user_prompt, "DETERMINISTIC_SOLIDITY_FACTS_JSON")
    if not isinstance(requests, list):
        raise AssertionError("synthetic model surface requests must be a list")
    if not isinstance(solidity_facts, dict):
        raise AssertionError("synthetic Solidity facts must be an object")
    symbol_index = solidity_facts.get("symbol_index")
    if not isinstance(symbol_index, dict):
        raise AssertionError("synthetic Solidity facts omitted the symbol index")
    entities = symbol_index.get("entities")
    if not isinstance(entities, list):
        raise AssertionError("synthetic Solidity symbol index omitted entities")
    allowed_surface_kinds_by_entity_kind = {
        "abstract_contract": {"contract"},
        "contract": {"contract"},
        "interface": {"contract"},
        "library": {"contract"},
        "constructor": {"entry_point", "privilege_function", "asset_function"},
        "fallback": {"entry_point", "privilege_function", "asset_function"},
        "function": {
            "entry_point",
            "internal_function",
            "privilege_function",
            "asset_function",
        },
        "modifier": {"internal_function", "privilege_function"},
        "receive": {"entry_point", "privilege_function", "asset_function"},
        "constant": {"state"},
        "immutable": {"state"},
        "state_variable": {"state"},
    }
    matching_surface_ids: set[str] = set()
    for surface in requests:
        if not isinstance(surface, dict):
            raise AssertionError("synthetic model surface request must be an object")
        surface_id = surface.get("surface_id")
        if not isinstance(surface_id, str) or not surface_id:
            raise AssertionError("synthetic model surface request omitted its surface ID")
        locations = surface.get("allowed_locations")
        if not isinstance(locations, list):
            raise AssertionError("synthetic model surface request omitted allowed locations")
        for location in locations:
            if not isinstance(location, dict) or location.get("path") != expected_path:
                continue
            for entity in entities:
                if not isinstance(entity, dict):
                    raise AssertionError("synthetic Solidity entity must be an object")
                allowed_surface_kinds = allowed_surface_kinds_by_entity_kind.get(entity.get("kind"))
                if (
                    allowed_surface_kinds is None
                    or surface.get("kind") not in allowed_surface_kinds
                ):
                    continue
                if (
                    surface.get("subject_id") == entity.get("id")
                    and location.get("path") == entity.get("path")
                    and location.get("start_line") == entity.get("start_line")
                    and location.get("end_line") == entity.get("end_line")
                    and location.get("content_hash") == entity.get("source_hash")
                ):
                    matching_surface_ids.add(surface_id)
    return tuple(sorted(matching_surface_ids))


def _requested_surface_covers_path(user_prompt: str, expected_path: str) -> bool:
    """Return whether one typed request has an exact indexed location binding."""

    return bool(_requested_surface_ids_for_path(user_prompt, expected_path))


def _delivered_excerpt_descriptors_for_location(
    user_prompt: str,
    expected_path: str,
    expected_start_line: int,
    expected_end_line: int,
) -> tuple[dict[str, Any], ...]:
    """Return exact provider-visible excerpts that contain one candidate location."""

    if expected_start_line < 1 or expected_end_line < expected_start_line:
        raise AssertionError("synthetic candidate location must be a valid line range")
    metadata_open = "<REPOSITORY_EXCERPT_METADATA_JSON>\n"
    metadata_close = "\n</REPOSITORY_EXCERPT_METADATA_JSON>"
    descriptors: dict[tuple[str, int, int, str], dict[str, Any]] = {}
    cursor = 0
    while True:
        metadata_offset = user_prompt.find(metadata_open, cursor)
        if metadata_offset < 0:
            break
        metadata_start = metadata_offset + len(metadata_open)
        metadata_end = user_prompt.find(metadata_close, metadata_start)
        if metadata_end < 0:
            raise AssertionError("synthetic prompt has an unterminated excerpt descriptor")
        try:
            metadata = json.loads(user_prompt[metadata_start:metadata_end])
        except json.JSONDecodeError as exc:
            raise AssertionError("synthetic prompt has invalid excerpt metadata") from exc
        if not isinstance(metadata, dict) or set(metadata) != {
            "path",
            "start_line",
            "end_line",
            "content_sha256",
        }:
            raise AssertionError("synthetic prompt excerpt metadata is not canonical")
        path = metadata["path"]
        start_line = metadata["start_line"]
        end_line = metadata["end_line"]
        content_sha256 = metadata["content_sha256"]
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(start_line, int)
            or isinstance(start_line, bool)
            or not isinstance(end_line, int)
            or isinstance(end_line, bool)
            or start_line < 1
            or end_line < start_line
            or not isinstance(content_sha256, str)
            or len(content_sha256) != 64
            or any(character not in "0123456789abcdef" for character in content_sha256)
        ):
            raise AssertionError("synthetic prompt excerpt metadata is invalid")
        sentinel = f"MMAUDIT-UNTRUSTED-{content_sha256.upper()}"
        content_open = f"\n-----BEGIN {sentinel}-----\n"
        content_close = f"\n-----END {sentinel}-----"
        content_open_offset = metadata_end + len(metadata_close)
        if not user_prompt.startswith(content_open, content_open_offset):
            raise AssertionError("synthetic prompt excerpt lacks its hash-bound opening sentinel")
        content_start = content_open_offset + len(content_open)
        content_end = user_prompt.find(content_close, content_start)
        if content_end < 0:
            raise AssertionError("synthetic prompt excerpt lacks its hash-bound closing sentinel")
        content = user_prompt[content_start:content_end]
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != content_sha256:
            raise AssertionError("synthetic prompt excerpt hash differs from delivered bytes")
        if len(content.splitlines()) != end_line - start_line + 1:
            raise AssertionError("synthetic prompt excerpt line range differs from delivered bytes")
        if (
            path == expected_path
            and start_line <= expected_start_line
            and expected_end_line <= end_line
        ):
            identity = (path, start_line, end_line, content_sha256)
            descriptors[identity] = {
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "content_sha256": content_sha256,
            }
        cursor = content_end + len(content_close)
    return tuple(descriptors[key] for key in sorted(descriptors))


def _request_scoped_candidate_id(
    base_candidate_id: str,
    user_prompt: str,
    expected_path: str,
    expected_start_line: int,
    expected_end_line: int,
    *,
    logical_request_id: str,
) -> str | None:
    """Bind a synthetic candidate identity to exact delivered source and request scope."""

    source_excerpts = _delivered_excerpt_descriptors_for_location(
        user_prompt,
        expected_path,
        expected_start_line,
        expected_end_line,
    )
    if not source_excerpts:
        return None
    if not logical_request_id:
        raise AssertionError("synthetic candidate request omitted its logical request ID")
    payload = {
        "base_candidate_id": base_candidate_id,
        "logical_request_id": logical_request_id,
        "source_excerpts": source_excerpts,
    }
    scope_sha256 = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"{base_candidate_id}-{scope_sha256[:20]}"


def _entity_citation(entity: dict[str, Any], *, symbol: str | None = None) -> dict[str, Any]:
    resolved_symbol = symbol or entity["id"]
    return {
        "location": None,
        "symbol": resolved_symbol,
    }


def _entry_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        entity
        for entity in entities
        if entity["kind"] in {"function", "constructor"}
        and (entity["kind"] == "constructor" or entity.get("visibility") in {"public", "external"})
    ]


def _surface_review_path(
    request: dict[str, Any],
    *,
    entities: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    entities_by_id = {entity["id"]: entity for entity in entities}
    entries = _entry_entities(entities)
    entry_by_id = {entry["id"]: entry for entry in entries}
    subject = entities_by_id.get(request["subject_id"])
    allowed_symbols = set(request["allowed_symbols"])
    allowed_locations = request["allowed_locations"]

    if subject is not None:
        terminal_symbol = next(
            (
                symbol
                for symbol in (
                    subject["id"],
                    subject.get("signature"),
                    subject["name"],
                )
                if symbol in allowed_symbols
            ),
            None,
        )
        if terminal_symbol is None:
            return None
        terminal = _entity_citation(subject, symbol=terminal_symbol)
        if subject["id"] in entry_by_id and request["kind"] in {
            "entry_point",
            "privilege_function",
            "asset_function",
        }:
            return terminal, [terminal]
        if subject["kind"] in {"contract", "interface", "library"}:
            entry = next(
                (item for item in entries if item.get("contract_name") == subject["name"]),
                None,
            )
            if entry is not None:
                return terminal, [_entity_citation(entry), terminal]
        edge = next(
            (
                edge
                for edge in edges
                if edge["target_id"] == subject["id"] and edge["source_id"] in entry_by_id
            ),
            None,
        )
        if edge is not None:
            return terminal, [_entity_citation(entry_by_id[edge["source_id"]]), terminal]

    if request["kind"] == "call" and allowed_locations:
        location = allowed_locations[0]
        edge = next(
            (
                item
                for item in edges
                if _fake_edge_subject_id(item) == request["subject_id"]
                if item["path"] == location["path"]
                and item["start_line"] == location["start_line"]
                and item["end_line"] == location["end_line"]
                and item["source_hash"] == location["content_hash"]
                and item["source_id"] in entry_by_id
            ),
            None,
        )
        if edge is not None:
            terminal = {"location": location, "symbol": None}
            return terminal, [_entity_citation(entry_by_id[edge["source_id"]]), terminal]

    if request["kind"] == "source_file" and len(allowed_locations) == 1:
        terminal = {"location": allowed_locations[0], "symbol": None}
        return terminal, [terminal]

    if request["kind"] in {"invariant", "template"}:
        exactly_bound_target_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity_id in allowed_symbols
            and any(
                location["path"] == entity["path"]
                and location["start_line"] == entity["start_line"]
                and location["end_line"] == entity["end_line"]
                and location["content_hash"] == entity["source_hash"]
                for location in allowed_locations
            )
        }
        exact_reachable = [
            (
                entry_by_id[edge["source_id"]],
                entities_by_id[edge["target_id"]],
            )
            for edge in edges
            if edge["source_id"] in entry_by_id
            and edge["target_id"] in entities_by_id
            and edge["target_id"] in exactly_bound_target_ids
        ]
        reachable = exact_reachable or [
            (
                entry_by_id[edge["source_id"]],
                entities_by_id[edge["target_id"]],
            )
            for edge in edges
            if not exactly_bound_target_ids
            and edge["source_id"] in entry_by_id
            and edge["target_id"] in entities_by_id
            and {
                entities_by_id[edge["target_id"]]["id"],
                entities_by_id[edge["target_id"]]["name"],
                entities_by_id[edge["target_id"]].get("signature"),
            }
            & allowed_symbols
        ]
        if reachable:
            entry, terminal_entity = reachable[0]
            terminal_symbol = next(
                symbol
                for symbol in (
                    terminal_entity["id"],
                    terminal_entity.get("signature"),
                    terminal_entity["name"],
                )
                if symbol in allowed_symbols
            )
            terminal = {"location": None, "symbol": terminal_symbol}
            return terminal, [_entity_citation(entry), terminal]
    return None


def _fake_edge_subject_id(edge: dict[str, Any]) -> str:
    payload = {
        "graph": edge["graph"],
        "source_id": edge["source_id"],
        "target_id": edge["target_id"],
        "label": edge["label"],
        "path": edge["path"],
        "start_line": edge["start_line"],
        "end_line": edge["end_line"],
        "source_hash": edge["source_hash"],
        "metadata": edge["metadata"],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f"graph-edge:{digest}"


def _surface_reviews(
    user_prompt: str,
    *,
    role: str,
    status: str = "REVIEWED_NO_ISSUE",
    force_inconclusive: bool = False,
) -> list[dict[str, Any]]:
    requests = _extract_json(user_prompt, "TRUSTED_MODEL_SURFACE_REQUESTS_JSON")
    solidity_facts = _extract_optional_json(user_prompt, "DETERMINISTIC_SOLIDITY_FACTS_JSON") or {}
    symbol_index = solidity_facts.get("symbol_index") or {}
    graphs = solidity_facts.get("graphs") or {}
    entities = symbol_index.get("entities") or []
    edges = graphs.get("edges") or []
    reviews: list[dict[str, Any]] = []
    for request in requests:
        path_evidence = _surface_review_path(
            request,
            entities=entities,
            edges=edges,
        )
        if force_inconclusive:
            path_evidence = None
        resolved_status = status if path_evidence is not None else "INCONCLUSIVE"
        if path_evidence is None:
            allowed_locations = request["allowed_locations"]
            allowed_symbols = request["allowed_symbols"]
            citation = {
                "location": None if allowed_symbols else allowed_locations[0],
                "symbol": allowed_symbols[0] if allowed_symbols else None,
            }
            path: list[dict[str, Any]] = []
        else:
            citation, path = path_evidence
        anchor = citation["symbol"] or request["function_or_state_surface"] or request["contract"]
        invariant_words = [
            word.strip(".,:;()[]").casefold()
            for word in request["invariant_considered"].split()
            if len(word.strip(".,:;()[]")) >= 3
        ]
        invariant_anchor = next(
            (
                word
                for word in invariant_words
                if word.startswith(
                    (
                        "account",
                        "asset",
                        "author",
                        "balance",
                        "invariant",
                        "state",
                        "storage",
                    )
                )
            ),
            invariant_words[0] if invariant_words else "invariant",
        )
        reviews.append(
            {
                "surface_id": request["surface_id"],
                "contract": request["contract"],
                "function_or_state_surface": request["function_or_state_surface"],
                "review_role": role,
                "status": resolved_status,
                "rationale": (
                    f"The synthetic reviewer traced {anchor} through deterministic graph evidence."
                ),
                "citation": citation,
                "invariant_considered": request["invariant_considered"],
                "evidence_observations": [
                    {
                        "citation": citation,
                        "observed_behavior": (
                            f"{anchor} calls, checks, or writes the cited deterministic source state."
                        ),
                        "security_relevance": (
                            f"{anchor} determines whether {invariant_anchor} integrity is preserved."
                        ),
                    }
                ]
                if path_evidence is not None
                else [],
                "reachability": (
                    {
                        "entry_point": path[0],
                        "path": path,
                        "actor_or_caller": "synthetic authorized caller",
                        "preconditions": [],
                    }
                    if path_evidence is not None
                    else None
                ),
                "assumptions": [],
                "confidence": 0.9,
            }
        )
    return reviews


@dataclass
class FakeOpenRouter:
    mode: str = "success"
    role: str | None = None
    reject_verifier: bool = False
    first_pass_canary: str | None = None
    requests: list[dict[str, Any]] = field(default_factory=list)
    extra_model_ids: list[str] = field(default_factory=list)
    context_length: int = 200_000
    max_prompt_tokens: int = 180_000
    max_completion_tokens: int = 20_000
    chat_calls: int = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "id": model,
                            "name": model,
                            "context_length": self.context_length,
                            "supported_parameters": ["response_format", "structured_outputs"],
                        }
                        for model in [*MODEL_IDS.values(), *self.extra_model_ids]
                    ]
                },
            )
        if "/models/" in request.url.path and request.url.path.endswith("/endpoints"):
            model = request.url.path.split("/models/", 1)[1].removesuffix("/endpoints")
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": model,
                        "endpoints": [self._endpoint_record(model)],
                    }
                },
            )
        if request.url.path.endswith("/endpoints/zdr"):
            data = (
                []
                if self.mode == "zdr_failure"
                else [
                    self._endpoint_record(model)
                    for model in [*MODEL_IDS.values(), *self.extra_model_ids]
                ]
            )
            return httpx.Response(200, json={"data": data})
        if not request.url.path.endswith("/chat/completions"):
            return httpx.Response(404)

        self.chat_calls += 1
        body = json.loads(request.content)
        self.requests.append(body)
        schema_name = _request_schema_name(body)
        role = schema_name.removeprefix("mmaudit_").removesuffix("_findings")

        if self.mode == "authentication_failure":
            return httpx.Response(401, json={"error": {"message": "synthetic auth failure"}})
        if self.mode == "timeout" and role == self.role:
            raise httpx.ReadTimeout("synthetic timeout", request=request)
        if self.mode == "invalid_json" and role == self.role:
            return self._completion(body, "not valid json")

        if schema_name == "mmaudit_threat_model":
            content: Any = _threat_model()
            if self.mode == "solidity_reproduction":
                content["assets"] = ["Vault native assets"]
                content["attack_surfaces"] = ["Vault.withdraw"]
                content["review_targets"] = ["src/Vault.sol"]
            if self.mode == "invalid_threat_location":
                content["trust_boundaries"][0]["locations"] = [
                    {
                        "path": "missing.py",
                        "start_line": 1,
                        "end_line": 1,
                        "symbol": None,
                        "content_hash": None,
                    }
                ]
        elif schema_name.startswith("mmaudit_whole_protocol_review_"):
            user = body["messages"][1]["content"]
            metadata = body.get("metadata") or {}
            request_role = metadata.get("mmaudit_role")
            if not isinstance(request_role, str) or not request_role.startswith(
                "whole_protocol_review:"
            ):
                raise AssertionError("synthetic whole-protocol request omitted its indexed role")
            content = {
                "findings": [],
                "surface_reviews": _surface_reviews(user, role=request_role),
            }
        elif schema_name == "mmaudit_source_audit_findings":
            user = body["messages"][1]["content"]
            if self.mode in {
                "execution_origin_post_judge",
                "maximum_assurance",
                "semantic_accounting",
            }:
                content = {
                    "findings": [],
                    "surface_reviews": _surface_reviews(
                        user,
                        role="source_audit",
                    ),
                }
                return self._completion(body, json.dumps(content, sort_keys=True))
            reviews_vault = self.mode == "solidity_reproduction" and (
                _requested_surface_covers_path(user, "src/Vault.sol")
            )
            path = "missing.py" if self.mode == "invalid_location" else "app.py"
            if self.mode == "solidity_reproduction":
                findings = (
                    [_solidity_candidate("raw-source", "source_audit")] if reviews_vault else []
                )
            else:
                findings = [
                    _candidate(
                        candidate_id="raw-source",
                        role="source_audit",
                        path=path,
                    )
                ]
            content = {
                "findings": findings,
                "surface_reviews": _surface_reviews(user, role="source_audit"),
            }
            if self.first_pass_canary is not None and content["findings"]:
                content["findings"][0]["summary"] += f" {self.first_pass_canary}"
        elif schema_name == "mmaudit_business_logic_findings":
            user = body["messages"][1]["content"]
            if self.mode == "semantic_accounting":
                requests = _extract_json(user, "TRUSTED_MODEL_SURFACE_REQUESTS_JSON")
                cross_shard_review = any(
                    str(request.get("invariant_considered", "")).startswith("Cross-shard")
                    for request in requests
                )
                unsafe_accounting = (
                    "totalRecorded += requested;" in user
                    and "ledger.record(requested);" in user
                    and "uint256 observed = ledger.record(requested);" not in user
                )
                findings: list[dict[str, Any]] = []
                if cross_shard_review and unsafe_accounting:
                    location = requests[0]["allowed_locations"][0]
                    findings.append(
                        _candidate(
                            candidate_id="raw-cross-shard-accounting",
                            role="business_logic",
                            title="Observed and assumed cross-shard accounting diverge",
                            path=str(location["path"]),
                            start_line=int(location["start_line"]),
                            end_line=int(location["end_line"]),
                            cwe="CWE-682",
                            symbol=(
                                location.get("symbol")
                                or (requests[0].get("allowed_symbols") or [None])[0]
                            ),
                        )
                    )
                content = {
                    "findings": findings,
                    "surface_reviews": _surface_reviews(
                        user,
                        role="business_logic",
                        status=(
                            "CANDIDATE"
                            if cross_shard_review and unsafe_accounting
                            else "REVIEWED_NO_ISSUE"
                        ),
                    ),
                }
                return self._completion(body, json.dumps(content, sort_keys=True))
            if self.mode in {"execution_origin_post_judge", "maximum_assurance"}:
                content = {
                    "findings": [],
                    "surface_reviews": _surface_reviews(
                        user,
                        role="business_logic",
                        force_inconclusive=self.mode == "execution_origin_post_judge",
                    ),
                }
                return self._completion(body, json.dumps(content, sort_keys=True))
            reviews_vault = self.mode == "solidity_reproduction" and (
                _requested_surface_covers_path(user, "src/Vault.sol")
            )
            if self.mode == "solidity_reproduction":
                findings = (
                    [_solidity_candidate("raw-business", "business_logic")] if reviews_vault else []
                )
            else:
                findings = [
                    _candidate(
                        candidate_id="raw-business",
                        role="business_logic",
                        title="User search permits SQL query manipulation",
                    )
                ]
            content = {
                "findings": findings,
                "surface_reviews": _surface_reviews(user, role="business_logic"),
            }
        elif schema_name == "mmaudit_configuration_findings":
            user = body["messages"][1]["content"]
            content = (
                {
                    "findings": [],
                    "surface_reviews": _surface_reviews(
                        user,
                        role="configuration",
                        force_inconclusive=self.mode == "execution_origin_post_judge",
                    ),
                }
                if self.mode
                in {
                    "execution_origin_post_judge",
                    "solidity_reproduction",
                    "maximum_assurance",
                    "semantic_accounting",
                }
                else {
                    "findings": [
                        _candidate(
                            candidate_id="raw-config",
                            role="configuration",
                            title="Debug mode enabled",
                            path="config.py",
                            start_line=3,
                            end_line=3,
                            cwe="CWE-489",
                        )
                    ],
                    "surface_reviews": _surface_reviews(user, role="configuration"),
                }
            )
        elif schema_name == "mmaudit_verification":
            user = body["messages"][1]["content"]
            candidates = _extract_json(user, "SUBMITTED_CANDIDATES_JSON")
            content = {
                "decisions": [
                    {
                        "candidate_id": candidate["candidate_id"],
                        "verdict": (
                            "rejected"
                            if self.reject_verifier
                            or self.mode == "verifier_rejection"
                            or (
                                self.mode == "maximum_assurance"
                                and candidate["locations"][0]["path"] == "src/SafeControls.sol"
                            )
                            else "verified"
                        ),
                        "rationale": (
                            "Nearby control disproves the claim"
                            if self.reject_verifier
                            or self.mode == "verifier_rejection"
                            or (
                                self.mode == "maximum_assurance"
                                and candidate["locations"][0]["path"] == "src/SafeControls.sol"
                            )
                            else "The source and sink are directly reachable"
                        ),
                        "source_to_sink": "Direct in supplied fixture",
                        "reachability": "Direct call",
                        "authentication": "Synthetic authenticated user",
                        "privilege_requirements": "Ordinary user",
                        "environmental_assumptions": [],
                        "guards_and_controls": (
                            ["Nearby authorization or reentrancy guard"]
                            if self.reject_verifier
                            or self.mode == "verifier_rejection"
                            or (
                                self.mode == "maximum_assurance"
                                and candidate["locations"][0]["path"] == "src/SafeControls.sol"
                            )
                            else []
                        ),
                        "false_positive_conditions": [
                            "An external runtime control blocks the operation"
                        ],
                        "safe_verification_test": {
                            "type": "local",
                            "description": "Use only the synthetic local fixture",
                            "safe": True,
                        },
                        "confidence": (
                            0.1
                            if self.reject_verifier
                            or self.mode == "verifier_rejection"
                            or (
                                self.mode == "maximum_assurance"
                                and candidate["locations"][0]["path"] == "src/SafeControls.sol"
                            )
                            else 0.94
                        ),
                    }
                    for candidate in candidates
                ]
            }
            if self.mode == "verifier_omission":
                content["decisions"] = content["decisions"][:-1]
        elif schema_name == "mmaudit_judgment":
            user = body["messages"][1]["content"]
            payload = _extract_json(user, "VERIFIED_GROUPS_JSON")
            content = {
                "decisions": [
                    {
                        "group_id": group["group_id"],
                        "status": group["consensus_status_cap"],
                        "severity": (
                            "high"
                            if self.mode == "execution_origin_post_judge"
                            and any(
                                candidate.get("origin_kind") == "deterministic_execution"
                                for candidate in group["candidates"]
                            )
                            else group["candidates"][0]["severity"]
                        ),
                        "confidence": 0.9,
                        "cwe": group["candidates"][0]["cwe"],
                        "owasp": group["candidates"][0]["owasp"],
                        "rationale": "Classification respects the deterministic cap",
                    }
                    for group in payload["candidate_groups"]
                ]
            }
            if self.mode == "judge_omission":
                content["decisions"] = content["decisions"][:-1]
        elif schema_name.startswith("mmaudit_candidate_cross_examination_"):
            user = body["messages"][1]["content"]
            candidates = _extract_json(user, "ANONYMIZED_CANDIDATES_JSON")
            reviewer_index = int(schema_name.rsplit("_", 1)[1])
            content = {
                "decisions": [
                    {
                        "candidate_ref": candidate["candidate_ref"],
                        "verdict": ("supported" if reviewer_index == 1 else "disputed"),
                        "rationale": (
                            "The supplied path remains supported after adversarial review."
                            if reviewer_index == 1
                            else "A material assumption remains unsupported in the supplied evidence."
                        ),
                        "contradictions": (
                            []
                            if reviewer_index == 1
                            else ["The claimed control bypass is not independently established."]
                        ),
                        "missing_evidence": (
                            []
                            if reviewer_index == 1
                            else ["Independent reachability evidence is incomplete."]
                        ),
                    }
                    for candidate in candidates
                ]
            }
            if self.mode == "cross_exam_unknown":
                content["decisions"].append(
                    {
                        "candidate_ref": "candidate-9999",
                        "verdict": "supported",
                        "rationale": "Unknown synthetic intake.",
                        "contradictions": [],
                        "missing_evidence": [],
                    }
                )
        elif schema_name in {
            "mmaudit_exploit_test",
            "mmaudit_test_generation",
            "mmaudit_exploit_reproduction_plan",
        }:
            content = _exploit_tests(body["messages"][1]["content"])
        elif schema_name == "mmaudit_falsification":
            content = _falsification(body["messages"][1]["content"])
        elif schema_name == "mmaudit_invariant_review":
            content = _invariant_review(body["messages"][1]["content"])
        elif schema_name.startswith("mmaudit_specialist_"):
            specialist = schema_name.removeprefix("mmaudit_specialist_")
            user = body["messages"][1]["content"]
            candidate_by_role = {
                "access_control": _candidate(
                    candidate_id="specialist-access",
                    role="specialist:access_control",
                    title="Anyone can drain the access vault",
                    path="src/AccessVault.sol",
                    start_line=12,
                    end_line=14,
                    cwe="CWE-862",
                    symbol="drain",
                ),
                "reentrancy_control_flow": _candidate(
                    candidate_id="specialist-reentrancy",
                    role="specialist:reentrancy_control_flow",
                    title="External callback precedes balance clearing",
                    path="src/ReentrantBank.sol",
                    start_line=12,
                    end_line=17,
                    cwe="CWE-841",
                    symbol="withdraw",
                    severity="critical",
                ),
                "oracle_price_manipulation": _candidate(
                    candidate_id="specialist-oracle",
                    role="specialist:oracle_price_manipulation",
                    title="Same-transaction spot price controls debt",
                    path="src/SpotOracleLender.sol",
                    start_line=17,
                    end_line=19,
                    cwe="CWE-20",
                    symbol="borrow",
                ),
                "upgradeability_storage": _candidate(
                    candidate_id="specialist-upgrade",
                    role="specialist:upgradeability_storage",
                    title="Unrestricted UUPS implementation change",
                    path="src/UnsafeUUPS.sol",
                    start_line=9,
                    end_line=14,
                    cwe="CWE-862",
                    symbol="upgradeTo",
                    severity="critical",
                ),
                "false_negative_hunter": _candidate(
                    candidate_id="specialist-safe-control",
                    role="specialist:false_negative_hunter",
                    title="Rescue may lack authorization",
                    path="src/SafeControls.sol",
                    start_line=26,
                    end_line=28,
                    cwe="CWE-862",
                    symbol="rescue",
                ),
            }
            specialist_candidate = candidate_by_role.get(specialist)
            specialist_findings: list[dict[str, Any]] = []
            if self.mode == "maximum_assurance" and specialist_candidate is not None:
                metadata = body.get("metadata")
                logical_request_id = (
                    metadata.get("mmaudit_request_id") if isinstance(metadata, dict) else None
                )
                if not isinstance(logical_request_id, str) or not logical_request_id:
                    raise AssertionError(
                        "maximum-assurance synthetic specialist omitted its logical request ID"
                    )
                candidate_path = specialist_candidate["locations"][0]["path"]
                candidate_start_line = specialist_candidate["locations"][0]["start_line"]
                candidate_end_line = specialist_candidate["locations"][0]["end_line"]
                candidate_id = _request_scoped_candidate_id(
                    specialist_candidate["candidate_id"],
                    user,
                    candidate_path,
                    candidate_start_line,
                    candidate_end_line,
                    logical_request_id=logical_request_id,
                )
                if candidate_id is not None:
                    specialist_candidate["candidate_id"] = candidate_id
                    specialist_findings.append(specialist_candidate)
            content = {
                "findings": specialist_findings,
                "surface_reviews": _surface_reviews(
                    user,
                    role=f"specialist:{specialist}",
                    force_inconclusive=self.mode == "execution_origin_post_judge",
                ),
            }
        elif schema_name == "mmaudit_report_quality_review":
            content = {
                "passed": True,
                "missing_sections": [],
                "unsupported_claims": [],
                "coverage_caveats": ["Maximum-assurance engines that did not run remain visible."],
                "contradictions": [],
                "rationale": "The synthetic report labels its incomplete engines and evidence caps.",
            }
        else:
            raise AssertionError(f"unexpected schema {schema_name}")
        return self._completion(body, json.dumps(content, sort_keys=True))

    def _endpoint_record(self, model: str) -> dict[str, Any]:
        return {
            "model_id": model,
            "tag": "synthetic-provider",
            "provider_name": "Synthetic Provider",
            "status": 0,
            "context_length": self.context_length,
            "max_prompt_tokens": self.max_prompt_tokens,
            "max_completion_tokens": self.max_completion_tokens,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.0000001",
                "completion": "0.000001",
                "request": "0",
            },
        }

    @staticmethod
    def _completion(body: dict[str, Any], content: str) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-Generation-Id": "synthetic-generation"},
            json={
                "id": "synthetic-generation",
                "model": body["model"],
                "provider": "Synthetic Provider",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "native_finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": content,
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 50,
                    "total_tokens": 150,
                    "cost": 0.001,
                },
                "openrouter_metadata": {
                    "requested": body["model"],
                    "strategy": "direct",
                    "attempt": 1,
                    "endpoints": {
                        "total": 1,
                        "available": [
                            {
                                "provider": "Synthetic Provider",
                                "model": body["model"],
                                "selected": True,
                            }
                        ],
                    },
                    "attempts": [
                        {
                            "provider": "Synthetic Provider",
                            "model": body["model"],
                            "status": 200,
                        }
                    ],
                    "pipeline": [],
                },
            },
        )
