"""Explicit synthetic property/mutation pairs; never target discovery or runtime authority."""

from __future__ import annotations

import hashlib
from pathlib import Path

from mmaudit.benchmark.mutation_portfolio import PortfolioSourceMutationSpec, SecurityMutationClass
from mmaudit.benchmark.mutations import (
    MutationApplicabilityBinding,
    MutationApplicabilityPlan,
    MutationKindAccounting,
    MutationKindInventoryStatus,
    MutationNonApplicabilityReason,
    MutationNonApplicabilityRecord,
    mutation_repository_sha256,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mutation_portfolio"
SOURCE_PATH = "src/PortfolioTargets.sol"
CASES: dict[SecurityMutationClass, tuple[tuple[str, ...], str, str | None, str | None]] = {
    SecurityMutationClass.AUTHORIZATION_REMOVAL: (
        ('        require(msg.sender == owner, "caller denied");',),
        "testCallerMustBeAuthorized",
        None,
        None,
    ),
    SecurityMutationClass.NONCE_UPDATE_REMOVAL: (
        ("        consumedIdentifiers[identifier] = true;",),
        "testIdentifierCannotBeConsumedTwice",
        None,
        None,
    ),
    SecurityMutationClass.ROUNDING_DIRECTION: (
        ("        return LocalMath.mulDiv(amount, 1, 3, LocalMath.Rounding.Ceil);",),
        "testRequiredRoundingIsUpward",
        "Ceil",
        "Floor",
    ),
    SecurityMutationClass.STALE_PRICE_VALIDATION_REMOVAL: (
        ('        require(block.timestamp - updatedAt <= maxAge, "stale price");',),
        "testStalePriceMustBeRefused",
        None,
        None,
    ),
    SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE: (
        ("        pendingValue = 0;", "        observer.observe(amount);"),
        "testStateIsFinalBeforeNotification",
        None,
        None,
    ),
    SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL: (
        ('        require(!initialized, "already initialized");',),
        "testInitializationCannotRepeat",
        None,
        None,
    ),
    SecurityMutationClass.TIMELOCK_WEAKENING: (
        ('        require(block.timestamp >= scheduledAt + 2 seconds, "too early");',),
        "testDelayCannotBeBypassedAtSchedulingTime",
        "2 seconds",
        "0 seconds",
    ),
    SecurityMutationClass.STORAGE_SLOT_CHANGE: (
        ("    bytes32 internal constant STORAGE_SLOT = 0x" + "a" * 64 + ";",),
        "testStorageSlotRetainsItsBoundValue",
        "0x" + "a" * 64,
        "0x" + "b" * 64,
    ),
    SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL: (
        ('        require(!paused, "paused");',),
        "testPauseMustStopProtectedOperation",
        None,
        None,
    ),
    SecurityMutationClass.UNCHECKED_RETURN_HANDLING: (
        ('        require(success, "result refused");',),
        "testFalseReturnMustBeChecked",
        None,
        None,
    ),
    SecurityMutationClass.INCORRECT_DECIMAL_SCALE: (
        ("        return amount * 1e18;",),
        "testScaleMustRetainEighteenDecimals",
        "1e18",
        "1e6",
    ),
}


def specification(kind: SecurityMutationClass) -> PortfolioSourceMutationSpec:
    content = (FIXTURE / SOURCE_PATH).read_bytes()
    lines = content.decode().splitlines()
    expected, _, original, replacement = CASES[kind]
    matches = [i for i in range(len(lines)) if tuple(lines[i : i + len(expected)]) == expected]
    assert len(matches) == 1
    return PortfolioSourceMutationSpec(
        id="mut-" + kind.value.replace("_", "-"),
        kind=kind,
        path=SOURCE_PATH,
        line=matches[0] + 1,
        expected_file_sha256=hashlib.sha256(content).hexdigest(),
        expected_lines=expected,
        original_token=original,
        replacement_token=replacement,
    )


def property_id(kind: SecurityMutationClass) -> str:
    return "prop-" + hashlib.sha256(kind.value.encode()).hexdigest()[:24]


def portfolio_plan(
    kinds: tuple[SecurityMutationClass, ...] = tuple(SecurityMutationClass),
) -> MutationApplicabilityPlan:
    specs = sorted((specification(kind) for kind in kinds), key=lambda s: s.id)
    properties = {property_id(kind): kind for kind in kinds}
    bindings = sorted(
        [
            MutationApplicabilityBinding(
                property_id=property_id(item.kind),
                mutation_id=item.id,
                test_ids=[CASES[item.kind][1]],
            )
            for item in specs
        ],
        key=lambda b: (b.property_id, b.mutation_id),
    )
    non_applicability = sorted(
        [
            MutationNonApplicabilityRecord(
                property_id=pid,
                mutation_id=item.id,
                reason=MutationNonApplicabilityReason.PROPERTY_SCOPE_MISMATCH,
                rationale="This named synthetic control asserts a different declared property.",
            )
            for pid, kind in properties.items()
            for item in specs
            if item.kind is not kind
        ],
        key=lambda b: (b.property_id, b.mutation_id),
    )
    accounting = []
    for kind in sorted(SecurityMutationClass, key=lambda c: c.value):
        ids = [item.id for item in specs if item.kind is kind]
        accounting.append(
            MutationKindAccounting(
                kind=kind,
                status=(
                    MutationKindInventoryStatus.CANDIDATES_DECLARED
                    if ids
                    else MutationKindInventoryStatus.NO_CANDIDATE_DECLARED
                ),
                candidate_count=len(ids),
                candidate_ids=ids,
                limitation=None if ids else "No synthetic candidate was selected for this class.",
            )
        )
    return MutationApplicabilityPlan.sealed(
        schema_version="2.0",
        portfolio_scope="required_eleven_class",
        property_corpus_hash="c" * 64,
        source_repository_sha256=mutation_repository_sha256(FIXTURE),
        approved_executor_sha256="e" * 64,
        approved_isolation_policy_sha256="9" * 64,
        property_repositories={pid: "synthetic-portfolio" for pid in sorted(properties)},
        specifications=specs,
        bindings=bindings,
        non_applicability=non_applicability,
        kind_accounting=accounting,
    )
