from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.config import RepositoryForkSuiteConfig, SmartContractsConfig
from mmaudit.models.schemas import HardhatReporterInventory, HardhatReporterObservedTest
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SHA256, HARDHAT_REPORTER_VERSION
from mmaudit.scanners.hardhat_source import (
    HardhatSourceBindingError,
    bind_hardhat_inventory_to_source,
    hardhat_selection_from_source_authority,
    verify_hardhat_source_inventory_authority,
)

_REQUEST_SHA256 = "9" * 64


def _config(
    *,
    include_paths: tuple[str, ...] = ("test/audit/*.ts",),
    include_tests: tuple[str, ...] = ("preserves*",),
) -> SmartContractsConfig:
    return SmartContractsConfig(
        repository_suite=RepositoryForkSuiteConfig(
            profile="explicit",
            foundry_include_paths=(),
            foundry_include_tests=(),
            hardhat_include_paths=include_paths,
            hardhat_include_tests=include_tests,
        )
    )


def _observation(
    *,
    path: str = "test/audit/Vault.ts",
    suite_name: str = "Vault",
    test_name: str,
) -> HardhatReporterObservedTest:
    return HardhatReporterObservedTest.sealed(
        project_root=".",
        path=path,
        suite_name=suite_name,
        test_name=test_name,
    )


def _inventory(
    root: Path,
    *observations: HardhatReporterObservedTest,
) -> HardhatReporterInventory:
    repository_sha256 = scanner_workspace_sha256(root)
    return HardhatReporterInventory.sealed(
        reporter_version=HARDHAT_REPORTER_VERSION,
        reporter_sha256=HARDHAT_REPORTER_SHA256,
        request_sha256=_REQUEST_SHA256,
        repository_sha256=repository_sha256,
        tests=tuple(sorted(observations, key=lambda item: item.canonical_key)),
    )


def _write_source(root: Path, source: str) -> None:
    path = root / "test" / "audit" / "Vault.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def test_source_authority_requires_exact_complete_static_inventory_and_policy(
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path,
        """
const inert = /ordinary-pattern/;
const helper = {};
helper.describe(\"not mocha\", () => helper.it(\"not a test\", () => {}));
describe.only("Vault", () => {
  it("preserves accounting", async () => {});
  it.skip("documents safe branch", function () {});
});
""".lstrip(),
    )
    inventory = _inventory(
        tmp_path,
        _observation(test_name="preserves accounting"),
        _observation(test_name="documents safe branch"),
    )
    config = _config()

    authority = bind_hardhat_inventory_to_source(
        tmp_path,
        inventory,
        config,
        expected_repository_sha256=inventory.repository_sha256,
    )
    selection = hardhat_selection_from_source_authority(
        inventory,
        config,
        repository_exclusion_path=".mmaudit",
        authority=authority,
    )

    assert verify_hardhat_source_inventory_authority(authority, inventory=inventory)
    assert authority.candidate_file_count == 1
    assert authority.candidate_test_count == 2
    assert authority.selected_file_count == 1
    assert authority.selected_test_count == 1
    assert authority.omitted_test_count == 1
    assert [descriptor.test_name for descriptor in selection.tests] == ["preserves accounting"]
    assert selection.safety_claim is False


def test_source_authority_rejects_reporter_omission_and_dead_branch_claim(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
describe("Vault", () => {
  it("preserves accounting", () => {});
  it("second registered test", () => {});
});
if (false) {
  describe("Dead", () => { it("never registered", () => {}); });
}
""".lstrip(),
    )
    omitted = _inventory(tmp_path, _observation(test_name="preserves accounting"))

    with pytest.raises(HardhatSourceBindingError, match="exactly cover"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            omitted,
            _config(include_tests=("*",)),
            expected_repository_sha256=omitted.repository_sha256,
        )


def test_source_authority_rejects_dynamic_title_and_excluded_tree(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
describe("Vault", () => {
  const title = "preserves accounting";
  it(title, () => {});
});
""".lstrip(),
    )
    dynamic = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    with pytest.raises(HardhatSourceBindingError, match="literal strings"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            dynamic,
            _config(),
            expected_repository_sha256=dynamic.repository_sha256,
        )

    excluded_root = tmp_path / "excluded"
    path = excluded_root / "artifacts" / "test" / "audit" / "Forged.ts"
    path.parent.mkdir(parents=True)
    path.write_text('describe("Forged", () => { it("claim", () => {}); });\n')
    excluded = _inventory(
        excluded_root,
        _observation(
            path="artifacts/test/audit/Forged.ts",
            suite_name="Forged",
            test_name="claim",
        ),
    )
    with pytest.raises(HardhatSourceBindingError, match="zero candidate files"):
        bind_hardhat_inventory_to_source(
            excluded_root,
            excluded,
            _config(include_paths=("artifacts/**/*.ts",), include_tests=("*",)),
            expected_repository_sha256=excluded.repository_sha256,
        )

    jsx_path = tmp_path / "jsx" / "test" / "audit" / "Vault.tsx"
    jsx_path.parent.mkdir(parents=True)
    jsx_path.write_text(
        'describe("Vault",()=>{ const x = <div>it("inert",()=>0)</div>; '
        'it("preserves accounting",()=>{}); });\n',
        encoding="utf-8",
    )
    jsx_inventory = _inventory(
        tmp_path / "jsx",
        _observation(path="test/audit/Vault.tsx", test_name="preserves accounting"),
    )
    with pytest.raises(HardhatSourceBindingError, match="zero candidate files"):
        bind_hardhat_inventory_to_source(
            tmp_path / "jsx",
            jsx_inventory,
            _config(include_paths=("test/audit/*.tsx",)),
            expected_repository_sha256=jsx_inventory.repository_sha256,
        )


def test_source_authority_rejects_alias_registration_and_stale_inventory(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        """
const register = it;
describe("Vault", () => {
  it("preserves accounting", () => {});
  register("hidden alias", () => {});
});
""".lstrip(),
    )
    inventory = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    with pytest.raises(HardhatSourceBindingError, match="unsupported direct Mocha"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            inventory,
            _config(),
            expected_repository_sha256=inventory.repository_sha256,
        )

    _write_source(
        tmp_path,
        """
const {it: register} = globalThis;
describe("Vault", () => {
  it("preserves accounting", () => {});
  register("hidden destructured alias", () => {});
});
""".lstrip(),
    )
    destructured = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    with pytest.raises(HardhatSourceBindingError, match="unsupported direct Mocha"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            destructured,
            _config(),
            expected_repository_sha256=destructured.repository_sha256,
        )

    _write_source(
        tmp_path,
        'describe("Vault", () => { it("preserves accounting", () => {}); });\n',
    )
    stale = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    stale.tests[0].test_name = "mutated after sealing"
    with pytest.raises(HardhatSourceBindingError, match="hash is stale"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            stale,
            _config(),
            expected_repository_sha256=stale.repository_sha256,
        )


@pytest.mark.parametrize(
    "unsupported_source",
    [
        'describe("Vault",()=>{ const x = 1 / it("hidden",()=>{}); '
        'it("preserves accounting",()=>{}); });\n',
        'describe("Vault",()=>{ `${it("hidden",()=>{})}`; it("preserves accounting",()=>{}); });\n',
        'describe("Vault",()=>{ \\u0069\\u0074("hidden",()=>{}); '
        'it("preserves accounting",()=>{}); });\n',
        '#!/usr/bin/env node describe("Ghost",()=>{it("fake",()=>{})})\n'
        'describe("Vault",()=>{it("preserves accounting",()=>{});});\n',
        '<!-- describe("Ghost",()=>{it("fake",()=>{})});\n'
        'describe("Vault",()=>{it("preserves accounting",()=>{});});\n',
    ],
)
def test_source_authority_rejects_lexically_ambiguous_registration(
    tmp_path: Path,
    unsupported_source: str,
) -> None:
    _write_source(tmp_path, unsupported_source)
    inventory = _inventory(tmp_path, _observation(test_name="preserves accounting"))

    with pytest.raises(HardhatSourceBindingError):
        bind_hardhat_inventory_to_source(
            tmp_path,
            inventory,
            _config(),
            expected_repository_sha256=inventory.repository_sha256,
        )


@pytest.mark.parametrize("line_terminator", ["\r", "\u2028", "\u2029"])
def test_source_authority_counts_all_javascript_line_terminators(
    tmp_path: Path,
    line_terminator: str,
) -> None:
    _write_source(
        tmp_path,
        line_terminator.join(
            [
                'describe("Visible",()=>{it("first",()=>{});});',
                "// inert line comment",
                'describe("Vault",()=>{it("preserves accounting",()=>{});});',
                "",
            ]
        ),
    )
    inventory = _inventory(
        tmp_path,
        _observation(suite_name="Vault", test_name="preserves accounting"),
        _observation(suite_name="Visible", test_name="first"),
    )

    authority = bind_hardhat_inventory_to_source(
        tmp_path,
        inventory,
        _config(),
        expected_repository_sha256=inventory.repository_sha256,
    )

    assert authority.candidate_test_count == 2
    assert authority.descriptors[0].start_line == 3


@pytest.mark.parametrize(
    "prefix",
    [
        "const hidden = ready && ",
        "if (ready) ",
    ],
)
def test_source_authority_rejects_ambiguous_regex_test_tokens(
    tmp_path: Path,
    prefix: str,
) -> None:
    _write_source(
        tmp_path,
        prefix
        + '/x describe("Ghost", () => { it("phantom", () => {}) })/;\n'
        + 'describe("Vault", () => { it("preserves accounting", () => {}); });\n',
    )
    inventory = _inventory(tmp_path, _observation(test_name="preserves accounting"))

    with pytest.raises(HardhatSourceBindingError, match="ambiguous regular-expression"):
        bind_hardhat_inventory_to_source(
            tmp_path,
            inventory,
            _config(),
            expected_repository_sha256=inventory.repository_sha256,
        )


def test_source_authority_is_process_local_and_revalidates_nested_descriptors(
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path,
        'describe("Vault", () => { it("preserves accounting", () => {}); });\n',
    )
    inventory = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    authority = bind_hardhat_inventory_to_source(
        tmp_path,
        inventory,
        _config(),
        expected_repository_sha256=inventory.repository_sha256,
    )

    assert not verify_hardhat_source_inventory_authority(replace(authority), inventory=inventory)
    authority.descriptors[0].path = "test/audit/Changed.ts"
    assert not verify_hardhat_source_inventory_authority(authority, inventory=inventory)


def test_source_descriptor_lines_count_escaped_newline_continuations(tmp_path: Path) -> None:
    _write_source(
        tmp_path,
        'const continued = "first\\\nsecond";\n'
        'describe("Vault", () => {\n'
        '  it("preserves accounting", () => {});\n'
        "});\n",
    )
    inventory = _inventory(tmp_path, _observation(test_name="preserves accounting"))
    authority = bind_hardhat_inventory_to_source(
        tmp_path,
        inventory,
        _config(),
        expected_repository_sha256=inventory.repository_sha256,
    )

    assert authority.descriptors[0].start_line == 4
