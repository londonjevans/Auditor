from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryRecord,
    SolidityProjectMetadata,
    SolidityProjectType,
)
from mmaudit.scanners.repository_suite import (
    RepositorySuiteSelectionError,
    select_foundry_repository_suite,
    select_foundry_repository_suite_from_inventory,
)


def _write(root: Path, relative_path: str, content: str) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _project(
    *,
    project_root: str = ".",
    test_directories: list[str] | None = None,
) -> SolidityProjectMetadata:
    return SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=project_root,
        test_directories=test_directories
        if test_directories is not None
        else ["test" if project_root == "." else f"{project_root}/test"],
    )


def _explicit_config(
    *,
    include_paths: tuple[str, ...] = ("test/**/*.t.sol",),
    exclude_paths: tuple[str, ...] = (),
    include_tests: tuple[str, ...] = ("*",),
    exclude_tests: tuple[str, ...] = (),
    **limits: int,
) -> SmartContractsConfig:
    return SmartContractsConfig(
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=include_paths,
            foundry_exclude_paths=exclude_paths,
            foundry_include_tests=include_tests,
            foundry_exclude_tests=exclude_tests,
            hardhat_include_paths=(),
            hardhat_include_tests=(),
            **limits,
        )
    )


def _contract(suite: str, *functions: str) -> str:
    body = "\n\n".join(f"    {function}" for function in functions)
    return f"pragma solidity ^0.8.20;\n\ncontract {suite} {{\n{body}\n}}\n"


def _compiler_inventory(
    *,
    project_root: str = "packages/core",
    tests: tuple[tuple[str, str, str, str], ...] = (
        (
            "test/audit/Concrete.t.sol",
            "ConcreteSuite",
            "testInherited",
            "test/base/SharedBase.t.sol",
        ),
    ),
) -> tuple[RepositorySuiteInventoryRecord, ...]:
    source_paths = sorted(
        {
            path
            for execution_path, _suite, _test, declaration_path in tests
            for path in (execution_path, declaration_path)
        }
    )
    source_hashes = {
        path: hashlib.sha256(f"source:{path}".encode()).hexdigest() for path in source_paths
    }
    return tuple(
        RepositorySuiteInventoryRecord.sealed(
            project_root=project_root,
            execution_path=(
                execution_path if project_root == "." else f"{project_root}/{execution_path}"
            ),
            execution_suite_name=suite,
            test_name=test_name,
            execution_signature=test_name,
            execution_source_sha256=source_hashes[execution_path],
            execution_start_line=3,
            execution_end_line=20,
            execution_contract_ast_id=100 + index,
            declaration_path=(
                declaration_path if project_root == "." else f"{project_root}/{declaration_path}"
            ),
            declaration_suite_name="SharedBase",
            declaration_signature=f"{test_name}()",
            declaration_source_sha256=source_hashes[declaration_path],
            declaration_start_line=7,
            declaration_end_line=9,
            declaration_contract_ast_id=200 + index,
            declaration_function_ast_id=300 + index,
            build_info_sha256="b" * 64,
        )
        for index, (execution_path, suite, test_name, declaration_path) in enumerate(tests)
    )


def test_compiler_inventory_selects_inherited_test_and_binds_declaration() -> None:
    inventory = _compiler_inventory()
    config = SmartContractsConfig()

    selection = select_foundry_repository_suite_from_inventory(
        inventory,
        config,
        repository_sha256="d" * 64,
        repository_exclusion_path=".mmaudit",
        inventory_sha256="e" * 64,
    )

    assert selection.inventory_kind is RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
    assert selection.inventory_sha256 == "e" * 64
    assert selection.candidate_file_count == 1
    assert selection.candidate_test_count == 1
    descriptor = selection.tests[0]
    assert descriptor.path == "packages/core/test/audit/Concrete.t.sol"
    assert descriptor.suite_name == "ConcreteSuite"
    assert descriptor.declaration_path == "packages/core/test/base/SharedBase.t.sol"
    assert descriptor.declaration_suite_name == "SharedBase"
    assert descriptor.declaration_signature == "testInherited()"
    assert descriptor.inventory_record_sha256 == inventory[0].record_sha256
    assert descriptor.finding_path == descriptor.declaration_path
    assert descriptor.finding_start_line == 7
    assert descriptor.finding_end_line == 9


def test_compiler_inventory_preserves_full_denominators_and_bounded_filters() -> None:
    inventory = _compiler_inventory(
        tests=(
            (
                "test/audit/Concrete.t.sol",
                "ConcreteSuite",
                "testIncluded",
                "test/base/SharedBase.t.sol",
            ),
            (
                "test/unit/Other.t.sol",
                "OtherSuite",
                "testOmitted",
                "test/unit/Other.t.sol",
            ),
        )
    )

    selection = select_foundry_repository_suite_from_inventory(
        inventory,
        SmartContractsConfig(),
        repository_sha256="d" * 64,
        repository_exclusion_path=".mmaudit",
        inventory_sha256="e" * 64,
    )

    assert [descriptor.test_name for descriptor in selection.tests] == ["testIncluded"]
    assert selection.candidate_file_count == 2
    assert selection.candidate_test_count == 2
    assert selection.selected_file_count == 1
    assert selection.selected_test_count == 1
    assert selection.omitted_file_count == 1
    assert selection.omitted_test_count == 1


def test_legacy_profile_selects_only_project_relative_audit_tests(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "packages/core/test/audit/Legacy.t.sol",
        _contract(
            "LegacyTest",
            "function testLegacy() public {\n        assert(true);\n    }",
        ),
    )
    _write(
        tmp_path,
        "packages/core/test/unit/Ordinary.t.sol",
        _contract("OrdinaryTest", "function testOrdinary() public {}"),
    )

    selection = select_foundry_repository_suite(
        tmp_path,
        [_project(project_root="packages/core")],
        SmartContractsConfig(),
    )

    assert selection.profile == "legacy_audit"
    assert selection.selected_file_count == 1
    assert selection.selected_test_count == 1
    assert selection.candidate_file_count == 2
    assert selection.candidate_test_count == 2
    assert selection.omitted_file_count == 1
    assert selection.omitted_test_count == 1
    assert selection.limit_reached is False
    descriptor = selection.tests[0]
    assert descriptor.project_root == "packages/core"
    assert descriptor.path == "packages/core/test/audit/Legacy.t.sol"
    assert descriptor.suite_name == "LegacyTest"
    assert descriptor.test_name == "testLegacy"
    assert descriptor.start_line == 4
    assert descriptor.end_line == 6
    assert descriptor.descriptor_sha256 == descriptor.expected_descriptor_sha256()
    assert selection.selection_sha256 == selection.expected_selection_sha256()


def test_explicit_selection_matches_stable_ids_and_excludes_win(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/unit/Suite.t.sol",
        """pragma solidity ^0.8.20;
// function testCommented() public {}
contract SuiteTest {
    string internal constant FAKE = "function testString() public {}";
    function testChosen() public {}
    function testSkipped() public {}
    function invariant_state() external view {}
    function invariant_skipThis() external view {}
    function testInternal() internal {}
    function testInternalReturn() internal returns (function() external) { revert(); }
    function helper() public {}
}
""",
    )
    _write(
        tmp_path,
        "test/excluded/Excluded.t.sol",
        _contract("ExcludedTest", "function testExcluded() public {}"),
    )
    _write(
        tmp_path,
        "src/Outside.t.sol",
        _contract("OutsideTest", "function testOutside() public {}"),
    )
    config = _explicit_config(
        include_paths=("test/**/*.t.sol",),
        exclude_paths=("test/excluded/*.t.sol",),
        include_tests=(
            "invariant_*",
            "test/unit/Suite.t.sol:SuiteTest:testChosen",
        ),
        exclude_tests=("invariant_skip*",),
    )

    selection = select_foundry_repository_suite(tmp_path, [_project()], config)

    assert [(test.suite_name, test.test_name) for test in selection.tests] == [
        ("SuiteTest", "invariant_state"),
        ("SuiteTest", "testChosen"),
    ]
    assert selection.repository_sha256
    assert selection.configuration_sha256 == config.repository_suite.stable_hash()
    assert selection.candidate_file_count == 2
    assert selection.candidate_test_count == 5
    assert selection.omitted_file_count == 1
    assert selection.omitted_test_count == 3
    assert selection.limit_reached is False


def test_selection_is_canonical_across_project_and_filesystem_order(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "packages/z/test/Z.t.sol",
        _contract("ZTest", "function testZ() public {}"),
    )
    _write(
        tmp_path,
        "packages/a/test/A.t.sol",
        _contract("ATest", "function testA() public {}"),
    )
    config = _explicit_config(include_paths=("packages/*/test/*.t.sol",))
    projects = [
        _project(project_root="packages/z"),
        _project(project_root="packages/a"),
    ]

    first = select_foundry_repository_suite(tmp_path, projects, config)
    second = select_foundry_repository_suite(tmp_path, list(reversed(projects)), config)

    assert [test.test_name for test in first.tests] == ["testA", "testZ"]
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_selection_hash_binds_non_test_source_changes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/Vault.t.sol",
        _contract("VaultTest", "function testDeposit() public {}"),
    )
    source = _write(
        tmp_path,
        "src/Vault.sol",
        "pragma solidity ^0.8.20; contract Vault { uint256 public totalAssets; }\n",
    )
    config = _explicit_config(include_paths=("test/*.t.sol",))

    before = select_foundry_repository_suite(tmp_path, [_project()], config)
    source.write_text(
        "pragma solidity ^0.8.20; contract Vault { uint256 public totalSupply; }\n",
        encoding="utf-8",
    )
    after = select_foundry_repository_suite(tmp_path, [_project()], config)

    assert before.tests[0].descriptor_sha256 == after.tests[0].descriptor_sha256
    assert before.repository_sha256 != after.repository_sha256
    assert before.selection_sha256 != after.selection_sha256


def test_selection_excludes_custom_output_nested_under_test_directory(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "test/Selected.t.sol",
        _contract("SelectedTest", "function testSelected() public {}"),
    )
    output = tmp_path / "test" / "custom-audit-output"
    _write(
        tmp_path,
        "test/custom-audit-output/Rogue.t.sol",
        _contract("RogueTest", "function testRogue() public {}"),
    )

    selection = select_foundry_repository_suite(
        tmp_path,
        [_project()],
        _explicit_config(include_paths=("test/**/*.t.sol",)),
        private_dir=output,
    )

    assert selection.candidate_file_count == 1
    assert selection.candidate_test_count == 1
    assert selection.repository_exclusion_path == "test/custom-audit-output"
    assert [test.path for test in selection.tests] == ["test/Selected.t.sol"]


def test_exact_bare_name_is_rejected_when_multiple_tests_match(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/A.t.sol",
        _contract("ATest", "function testSame() public {}"),
    )
    _write(
        tmp_path,
        "test/B.t.sol",
        _contract("BTest", "function testSame() public {}"),
    )
    config = _explicit_config(
        include_paths=("test/*.t.sol",),
        include_tests=("testSame",),
    )

    with pytest.raises(RepositorySuiteSelectionError, match="bare test selector is ambiguous"):
        select_foundry_repository_suite(tmp_path, [_project()], config)


def test_stable_test_id_disambiguates_an_exact_name(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/A.t.sol",
        _contract("ATest", "function testSame() public {}"),
    )
    _write(
        tmp_path,
        "test/B.t.sol",
        _contract("BTest", "function testSame() public {}"),
    )
    config = _explicit_config(
        include_paths=("test/*.t.sol",),
        include_tests=("test/A.t.sol:ATest:testSame",),
    )

    selection = select_foundry_repository_suite(tmp_path, [_project()], config)

    assert [(test.path, test.test_name) for test in selection.tests] == [
        ("test/A.t.sol", "testSame")
    ]
    assert selection.candidate_file_count == 2
    assert selection.candidate_test_count == 2
    assert selection.omitted_file_count == 1
    assert selection.omitted_test_count == 1


def test_duplicate_test_identity_in_one_suite_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/Duplicate.t.sol",
        _contract(
            "DuplicateTest",
            "function testDuplicate() public {}",
            "function testDuplicate(uint256 value) public { assert(value >= 0); }",
        ),
    )

    with pytest.raises(RepositorySuiteSelectionError, match="ambiguous duplicate"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


def test_inherited_foundry_tests_fail_closed_until_inventory_is_reconciled(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "test/Inherited.t.sol",
        """pragma solidity ^0.8.20;
abstract contract SharedTests {
    function testInheritedInvariant() public {}
}
contract ConcreteSuite is SharedTests {}
""",
    )

    with pytest.raises(
        RepositorySuiteSelectionError,
        match="inheritance requires isolated inventory reconciliation",
    ):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


@pytest.mark.parametrize(
    ("limits", "files", "message"),
    [
        (
            {"max_selected_files": 1},
            {
                "test/A.t.sol": _contract("ATest", "function testA() public {}"),
                "test/B.t.sol": _contract("BTest", "function testB() public {}"),
            },
            "files exceed",
        ),
        (
            {"max_tests_per_file": 1},
            {
                "test/A.t.sol": _contract(
                    "ATest",
                    "function testA() public {}",
                    "function testB() public {}",
                ),
            },
            "per-file ceiling",
        ),
        (
            {"max_total_tests": 1},
            {
                "test/A.t.sol": _contract("ATest", "function testA() public {}"),
                "test/B.t.sol": _contract("BTest", "function testB() public {}"),
            },
            "total ceiling",
        ),
    ],
)
def test_selection_fails_instead_of_truncating_at_ceilings(
    tmp_path: Path,
    limits: dict[str, int],
    files: dict[str, str],
    message: str,
) -> None:
    for path, content in files.items():
        _write(tmp_path, path, content)

    with pytest.raises(RepositorySuiteSelectionError, match=message):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",), **limits),
        )


def test_zero_selected_tests_fails_closed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/OnlyHelper.t.sol",
        _contract("OnlyHelper", "function helper() public {}"),
    )

    with pytest.raises(RepositorySuiteSelectionError, match="matched zero tests"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


def test_symlink_in_test_tree_fails_before_selection(tmp_path: Path) -> None:
    target = _write(
        tmp_path,
        "outside/Linked.t.sol",
        _contract("LinkedTest", "function testLinked() public {}"),
    )
    test_directory = tmp_path / "test"
    test_directory.mkdir()
    try:
        (test_directory / "Linked.t.sol").symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(RepositorySuiteSelectionError, match="contains a link"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


def test_test_directory_must_remain_within_its_project(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "other/test/Outside.t.sol",
        _contract("OutsideTest", "function testOutside() public {}"),
    )
    (tmp_path / "packages/core").mkdir(parents=True)

    with pytest.raises(RepositorySuiteSelectionError, match="escapes its project root"):
        select_foundry_repository_suite(
            tmp_path,
            [
                _project(
                    project_root="packages/core",
                    test_directories=["other/test"],
                )
            ],
            _explicit_config(include_paths=("other/test/*.t.sol",)),
        )


def test_parameterized_invariant_is_rejected_as_non_exact_execution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "test/Invariant.t.sol",
        _contract(
            "InvariantTest",
            "function invariant_state(uint256 value) public view { assert(value >= 0); }",
        ),
    )

    with pytest.raises(RepositorySuiteSelectionError, match="must not accept parameters"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


def test_non_regular_test_candidate_is_rejected(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable on this platform")
    test_directory = tmp_path / "test"
    test_directory.mkdir()
    fifo = test_directory / "Pipe.t.sol"
    try:
        os.mkfifo(fifo)
    except OSError:
        pytest.skip("FIFO creation is unavailable on this platform")

    with pytest.raises(RepositorySuiteSelectionError, match="not a regular file"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )


def test_hard_linked_test_candidate_is_rejected(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "outside/Source.t.sol",
        _contract("LinkedTest", "function testLinked() public {}"),
    )
    linked = tmp_path / "test/Linked.t.sol"
    linked.parent.mkdir()
    try:
        os.link(source, linked)
    except OSError:
        pytest.skip("hard links are unavailable on this platform")

    with pytest.raises(RepositorySuiteSelectionError, match="cannot be hard-linked"):
        select_foundry_repository_suite(
            tmp_path,
            [_project()],
            _explicit_config(include_paths=("test/*.t.sol",)),
        )
