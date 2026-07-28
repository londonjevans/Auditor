"""Deterministic local OpenRouter transport used by integration tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from tests.conftest import MODEL_IDS


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

    if request["kind"] in {"invariant", "template"}:
        reachable = [
            (
                entry_by_id[edge["source_id"]],
                entities_by_id[edge["target_id"]],
            )
            for edge in edges
            if edge["source_id"] in entry_by_id
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
    first_pass_canary: str | None = None
    requests: list[dict[str, Any]] = field(default_factory=list)
    extra_model_ids: list[str] = field(default_factory=list)
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
                            "context_length": 200_000,
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
        schema_name = body["response_format"]["json_schema"]["name"]
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
        elif schema_name == "mmaudit_source_audit_findings":
            user = body["messages"][1]["content"]
            if self.mode == "maximum_assurance":
                content = {
                    "findings": [],
                    "surface_reviews": _surface_reviews(user, role="source_audit"),
                }
                return self._completion(body, json.dumps(content, sort_keys=True))
            path = (
                "src/Vault.sol"
                if self.mode == "solidity_reproduction"
                else ("missing.py" if self.mode == "invalid_location" else "app.py")
            )
            content = {
                "findings": [
                    _solidity_candidate("raw-source", "source_audit")
                    if self.mode == "solidity_reproduction"
                    else _candidate(
                        candidate_id="raw-source",
                        role="source_audit",
                        path=path,
                    )
                ],
                "surface_reviews": _surface_reviews(user, role="source_audit"),
            }
            if self.first_pass_canary is not None:
                content["findings"][0]["summary"] += f" {self.first_pass_canary}"
        elif schema_name == "mmaudit_business_logic_findings":
            user = body["messages"][1]["content"]
            if self.mode == "maximum_assurance":
                content = {
                    "findings": [],
                    "surface_reviews": _surface_reviews(user, role="business_logic"),
                }
                return self._completion(body, json.dumps(content, sort_keys=True))
            content = {
                "findings": [
                    _solidity_candidate("raw-business", "business_logic")
                    if self.mode == "solidity_reproduction"
                    else _candidate(
                        candidate_id="raw-business",
                        role="business_logic",
                        title="User search permits SQL query manipulation",
                    )
                ],
                "surface_reviews": _surface_reviews(user, role="business_logic"),
            }
        elif schema_name == "mmaudit_configuration_findings":
            user = body["messages"][1]["content"]
            content = (
                {
                    "findings": [],
                    "surface_reviews": _surface_reviews(user, role="configuration"),
                }
                if self.mode in {"solidity_reproduction", "maximum_assurance"}
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
                            if self.mode == "verifier_rejection"
                            or (
                                self.mode == "maximum_assurance"
                                and candidate["locations"][0]["path"] == "src/SafeControls.sol"
                            )
                            else "verified"
                        ),
                        "rationale": (
                            "Nearby control disproves the claim"
                            if self.mode == "verifier_rejection"
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
                            if self.mode == "verifier_rejection"
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
                            if self.mode == "verifier_rejection"
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
                        "severity": group["candidates"][0]["severity"],
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
            content = {
                "findings": (
                    [candidate_by_role[specialist]]
                    if self.mode == "maximum_assurance" and specialist in candidate_by_role
                    else []
                ),
                "surface_reviews": _surface_reviews(
                    user,
                    role=f"specialist:{specialist}",
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

    @staticmethod
    def _endpoint_record(model: str) -> dict[str, Any]:
        return {
            "model_id": model,
            "tag": "synthetic-provider",
            "provider_name": "Synthetic Provider",
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
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
