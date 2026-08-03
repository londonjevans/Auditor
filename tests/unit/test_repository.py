from __future__ import annotations

import os
from pathlib import Path

import pytest

from mmaudit.models.schemas import Location, ScannerFinding, Severity
from mmaudit.orchestration.context import ContextBuilder, context_hash_index, render_context
from mmaudit.repository.chunking import chunk_text, line_range_hash
from mmaudit.repository.discovery import (
    RepositorySafetyError,
    discover_repository,
    is_binary,
    safe_repository_root,
)
from mmaudit.repository.ignore import (
    IgnoreMatcher,
    normalize_relative_path,
    safe_ignore_file,
)
from mmaudit.repository.locations import validate_location
from mmaudit.repository.mapping import build_repository_map
from mmaudit.repository.redaction import SecretSafetyError, detect_secrets, redact_text


def test_default_ignore_rules_cover_dependencies_and_keys() -> None:
    matcher = IgnoreMatcher()
    assert matcher.ignored("node_modules/pkg/index.js")
    assert matcher.ignored("nested/private.key")
    assert matcher.ignored(".git/config")
    assert not matcher.ignored("src/app.py")


def test_user_negation_can_reinclude_appropriate_default() -> None:
    matcher = IgnoreMatcher(["!vendor/first_party/"])
    assert not matcher.ignored("vendor/first_party/module.py")
    assert matcher.ignored("vendor/third_party/module.py")


def test_negation_can_descend_into_default_excluded_directory(
    tmp_path: Path, config_factory
) -> None:
    (tmp_path / "vendor" / "first_party").mkdir(parents=True)
    (tmp_path / "vendor" / "third_party").mkdir()
    (tmp_path / "vendor" / "first_party" / "owned.py").write_text(
        "owned = True\n",
        encoding="utf-8",
    )
    (tmp_path / "vendor" / "third_party" / "dependency.py").write_text(
        "dependency = True\n",
        encoding="utf-8",
    )
    result = discover_repository(
        tmp_path,
        config_factory().repository,
        IgnoreMatcher(["!vendor/first_party/"]),
    )
    assert [item.relative_path for item in result.files] == ["vendor/first_party/owned.py"]


def test_permanent_git_and_key_exclusions_cannot_be_negated() -> None:
    matcher = IgnoreMatcher(
        [
            "!.git/",
            "!private.pem",
            "!.ssh/id_ed25519",
            "!.aws/credentials",
            "!.config/gcloud/application_default_credentials.json",
        ]
    )
    assert matcher.ignored(".git/config")
    assert matcher.ignored("private.pem")
    assert matcher.ignored(".ssh/id_ed25519")
    assert matcher.ignored(".aws/credentials")
    assert matcher.ignored(".config/gcloud/application_default_credentials.json")


@pytest.mark.parametrize(
    "path",
    [
        ".ENV",
        ".Env.Local",
        "nested/Credentials.json",
        "nested/KEYS.json",
        "nested/Wallet.json",
        "nested/Mnemonic.txt",
        "nested/Seed.toml",
        "nested/.env.sol",
        "operator-secrets.example",
        "nested/operator-secrets.example",
    ],
)
def test_control_plane_and_wallet_artifacts_are_case_insensitively_excluded(
    path: str,
) -> None:
    matcher = IgnoreMatcher([f"!{path}"])
    assert matcher.ignored(path)


@pytest.mark.parametrize(
    "path",
    [
        "contracts/Wallet.sol",
        "contracts/Seed.sol",
        "contracts/KeyStore.sol",
        "src/Credentials.py",
        "src/public_key.py",
        "audit/wallet-audit.json",
    ],
)
def test_sensitive_name_near_misses_do_not_hide_auditable_source(path: str) -> None:
    assert not IgnoreMatcher().ignored(path)


@pytest.mark.parametrize("directory", ["wallet", "keys", "credentials", "seed"])
def test_generic_security_named_source_directories_remain_auditable(
    tmp_path: Path,
    config_factory,
    directory: str,
) -> None:
    source = tmp_path / "contracts" / directory / "Vault.sol"
    source.parent.mkdir(parents=True)
    source.write_text("contract Vault {}\n", encoding="utf-8")

    discovery = discover_repository(tmp_path, config_factory().repository, IgnoreMatcher())
    relative = f"contracts/{directory}/Vault.sol"

    assert relative in {item.relative_path for item in discovery.files}
    validation = validate_location(
        tmp_path,
        Location(path=relative, start_line=1, end_line=1),
    )
    assert validation.valid


def test_permanent_directory_negation_never_enables_traversal(
    tmp_path: Path, config_factory
) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("synthetic\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("safe = True\n", encoding="utf-8")
    result = discover_repository(
        tmp_path,
        config_factory().repository,
        IgnoreMatcher(["!.git/config"]),
    )
    assert [item.relative_path for item in result.files] == ["app.py"]


def test_ignore_file_cannot_escape_repository(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        safe_ignore_file(tmp_path, "../outside-ignore")


def test_ignore_file_cannot_be_sensitive_or_linked(tmp_path: Path) -> None:
    secret = tmp_path / ".env"
    secret.write_text("synthetic", encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive"):
        safe_ignore_file(tmp_path, ".env")

    target = tmp_path / "rules"
    target.write_text("*.tmp\n", encoding="utf-8")
    link = tmp_path / "linked-rules"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="link"):
        safe_ignore_file(tmp_path, "linked-rules")


@pytest.mark.parametrize(
    "value",
    ["../etc/passwd", "/etc/passwd", "C:\\Windows\\secret.txt", "safe/\nname.py"],
)
def test_unsafe_relative_paths_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_relative_path(value)


def test_filesystem_and_home_roots_are_rejected() -> None:
    with pytest.raises(RepositorySafetyError, match="filesystem root"):
        safe_repository_root(Path(Path.cwd().anchor))
    with pytest.raises(RepositorySafetyError, match="home directory"):
        safe_repository_root(Path.home())


def test_secret_detection_and_redaction() -> None:
    synthetic = "AKIA" + ("A" * 16)
    matches = detect_secrets(f"value = '{synthetic}'")
    assert len(matches) == 1
    redacted, redaction_matches = redact_text(
        f"value = '{synthetic}'",
        fail_on_detected_secret=False,
    )
    assert synthetic not in redacted
    assert "[REDACTED:aws_access_key]" in redacted
    assert redaction_matches[0].fingerprint not in redacted


def test_high_confidence_secret_blocks_egress() -> None:
    synthetic = "ghp_" + ("a" * 36)
    with pytest.raises(SecretSafetyError, match="egress blocked"):
        redact_text(synthetic, fail_on_detected_secret=True)


def test_low_entropy_placeholder_does_not_block() -> None:
    text = 'password = "test-only-placeholder-value"'
    redacted, matches = redact_text(text, fail_on_detected_secret=True)
    assert matches[0].confidence == "low"
    assert "test-only-placeholder-value" not in redacted


def test_unquoted_high_entropy_credential_assignment_blocks() -> None:
    synthetic = "Ab9_Xy7-" + "Qp2/Zm8+" + "Vk4.Nr6=Ts1"
    with pytest.raises(SecretSafetyError, match="egress blocked"):
        redact_text(
            f"api_key: {synthetic}",
            fail_on_detected_secret=True,
        )


def test_multiline_secret_redaction_preserves_line_numbers() -> None:
    begin_marker = "-----BEGIN " + "PRIVATE KEY-----"
    end_marker = "-----END " + "PRIVATE KEY-----"
    text = f"before\n{begin_marker}\nsynthetic fixture material\n{end_marker}\nafter\n"
    redacted, matches = redact_text(text, fail_on_detected_secret=False)
    assert matches[0].kind == "private_key"
    assert len(redacted.splitlines()) == len(text.splitlines())
    assert redacted.splitlines().index("after") == text.splitlines().index("after")
    assert "synthetic fixture material" not in redacted


def test_binary_detection() -> None:
    assert is_binary(b"abc\x00def")
    assert not is_binary(b"print('hello')\n")


def test_discovery_excludes_binary_and_oversized(tmp_path: Path, config_factory) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00\x01")
    (tmp_path / "large.py").write_text("x" * 100, encoding="utf-8")
    config = config_factory(repository={"max_file_bytes": 50})
    result = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    assert [item.relative_path for item in result.files] == ["app.py"]
    assert any("binary" in item for item in result.omitted)
    assert any("max_file_bytes" in item for item in result.omitted)


def test_discovery_walk_entry_limit_is_bounded(tmp_path: Path, config_factory) -> None:
    for index in range(5):
        (tmp_path / f"directory-{index}").mkdir()
    result = discover_repository(
        tmp_path,
        config_factory(repository={"max_walk_entries": 3}).repository,
        IgnoreMatcher(),
    )
    assert result.files == ()
    assert "repository: max_walk_entries reached" in result.omitted


def test_symlink_escape_is_excluded(tmp_path: Path, config_factory) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    result = discover_repository(
        tmp_path,
        config_factory().repository,
        IgnoreMatcher(),
    )
    assert not result.files
    assert any("symlink excluded" in item for item in result.omitted)


def test_safe_named_symlink_to_sensitive_file_is_excluded(
    tmp_path: Path,
    config_factory,
) -> None:
    secret = tmp_path / ".env"
    secret.write_text("OPENROUTER_API_KEY=synthetic-canary\n", encoding="utf-8")
    alias = tmp_path / "apparently-safe.py"
    try:
        alias.symlink_to(secret)
    except OSError:
        pytest.skip("symlinks unavailable")

    result = discover_repository(
        tmp_path,
        config_factory(repository={"follow_symlinks": True}).repository,
        IgnoreMatcher(),
    )

    assert result.files == ()
    assert any("sensitive symlink target excluded" in item for item in result.omitted)


def test_location_validation_rejects_sensitive_paths_and_link_aliases(tmp_path: Path) -> None:
    secret = tmp_path / ".env"
    secret.write_text("OPENROUTER_API_KEY=synthetic-canary\n", encoding="utf-8")
    direct = validate_location(
        tmp_path,
        Location(path=".env", start_line=1, end_line=1),
    )
    assert not direct.valid
    assert "sensitive repository path rejected" in direct.errors

    alias = tmp_path / "apparently-safe.sol"
    try:
        alias.symlink_to(secret)
    except OSError:
        pytest.skip("symlinks unavailable")
    linked = validate_location(
        tmp_path,
        Location(path=alias.name, start_line=1, end_line=1),
    )
    assert not linked.valid
    assert "linked repository path rejected" in linked.errors


def test_hardlink_is_excluded_from_repository_content(tmp_path: Path, config_factory) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-hardlink.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "alias.py").hardlink_to(outside)
    except OSError:
        pytest.skip("hardlinks unavailable")
    result = discover_repository(
        tmp_path,
        config_factory().repository,
        IgnoreMatcher(),
    )
    assert result.files == ()
    assert any("hardlink excluded" in item for item in result.omitted)


def test_changed_since_rejects_git_option_injection(vulnerable_repo: Path, config_factory) -> None:
    with pytest.raises(RepositorySafetyError, match="safe git ref"):
        discover_repository(
            vulnerable_repo,
            config_factory().repository,
            IgnoreMatcher(),
            changed_since="--output=/tmp/unsafe",
        )


def test_repository_local_git_executable_is_never_run(
    tmp_path: Path, config_factory, monkeypatch
) -> None:
    if os.name == "nt":
        pytest.skip("PATH executable resolution differs on Windows")
    fake_git = tmp_path / "git"
    marker = tmp_path / "executed"
    fake_git.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(RepositorySafetyError, match="inside the repository"):
        discover_repository(
            tmp_path,
            config_factory().repository,
            IgnoreMatcher(),
            changed_since="HEAD",
        )
    assert not marker.exists()


def test_repository_mapping_detects_categories(vulnerable_repo: Path, config_factory) -> None:
    config = config_factory(repository={"include_docs": True})
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    assert repository_map.languages["Python"] >= 2
    assert "requirements.txt" in repository_map.manifests
    assert "app.py" in repository_map.network_clients
    assert "config.py" in repository_map.configuration_files


def test_python_chunking_preserves_complete_symbols() -> None:
    content = "import os\n\n" + "\n".join(
        [
            "def first():",
            "    return 1",
            "",
            "def second():",
            "    return 2",
            "",
        ]
    )
    result = chunk_text(path="app.py", content=content, max_chunk_bytes=35)
    assert result.excerpts
    assert all(
        "def " not in excerpt.content or "return" in excerpt.content for excerpt in result.excerpts
    )
    assert line_range_hash(content, 1, 1)


def test_empty_source_chunk_is_explicit_provider_visible_whole_file() -> None:
    result = chunk_text(path="empty.py", content="")

    assert len(result.excerpts) == 1
    excerpt = result.excerpts[0]
    assert (excerpt.start_line, excerpt.end_line, excerpt.content) == (1, 1, "")
    assert not excerpt.omitted_before
    assert not excerpt.omitted_after
    assert result.omissions == ()


def test_oversized_logical_symbol_is_reported_not_split() -> None:
    content = "def giant():\n" + "\n".join(f"    value_{i} = {i}" for i in range(100))
    result = chunk_text(path="giant.py", content=content, max_chunk_bytes=100)
    assert result.excerpts == ()
    assert len(result.omissions) == 1
    assert "logical construct" in result.omissions[0]


def test_location_validation_checks_range_symbol_and_snapshot(
    vulnerable_repo: Path,
) -> None:
    content = (vulnerable_repo / "app.py").read_text(encoding="utf-8")
    location = Location(
        path="app.py",
        start_line=11,
        end_line=14,
        symbol="search_users",
    )
    hashes = {
        ("app.py", 0, 0): __import__("hashlib").sha256(content.encode()).hexdigest(),
        ("app.py", 1, len(content.splitlines())): __import__("hashlib")
        .sha256(content.encode())
        .hexdigest(),
    }
    result = validate_location(vulnerable_repo, location, context_hashes=hashes)
    assert result.valid
    invalid = validate_location(
        vulnerable_repo,
        Location(path="app.py", start_line=999, end_line=999),
        context_hashes=hashes,
    )
    assert not invalid.valid


def test_context_builder_enforces_total_allocation(vulnerable_repo: Path, config_factory) -> None:
    config = config_factory(
        repository={"max_total_context_bytes": 60_000},
        privacy={"fail_on_detected_secret": False},
    )
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )
    packages = [builder.build(role) for role in ("threat_model", "source_audit", "judge")]
    assert sum(package.bytes_used for package in packages) <= 60_000
    index = context_hash_index(packages)
    assert ("app.py", 0, 0) in index


def test_context_builder_blocks_or_omits_credential_shaped_filename(
    tmp_path: Path, config_factory
) -> None:
    synthetic = "AKIA" + ("Q" * 16)
    (tmp_path / f"{synthetic}.py").write_text("safe = True\n", encoding="utf-8")
    strict = config_factory()
    discovery = discover_repository(
        tmp_path,
        strict.repository,
        IgnoreMatcher(),
    )
    repository_map = build_repository_map(discovery)
    with pytest.raises(SecretSafetyError, match="egress blocked"):
        ContextBuilder(
            discovery=discovery,
            repository_map=repository_map,
            repository_config=strict.repository,
            privacy=strict.privacy,
            scanner_findings=[],
        )

    permissive = config_factory(privacy={"fail_on_detected_secret": False})
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=repository_map,
        repository_config=permissive.repository,
        privacy=permissive.privacy,
        scanner_findings=[],
    )
    rendered = render_context(builder.build("threat_model"))
    assert synthetic not in rendered
    assert "withheld by local secret safeguards" in rendered


def test_secret_scanner_hit_blocks_context_even_when_pattern_is_unknown(
    vulnerable_repo: Path, config_factory
) -> None:
    config = config_factory()
    discovery = discover_repository(vulnerable_repo, config.repository, IgnoreMatcher())
    repository_map = build_repository_map(discovery)
    scanner_finding = ScannerFinding(
        scanner="gitleaks",
        rule_id="synthetic-provider-token",
        title="Potential provider token",
        severity=Severity.HIGH,
        message="Potential credential detected; value omitted",
        locations=[Location(path="app.py", start_line=1, end_line=1)],
        fingerprint="synthetic-fingerprint",
    )
    with pytest.raises(SecretSafetyError, match="scanner detected"):
        ContextBuilder(
            discovery=discovery,
            repository_map=repository_map,
            repository_config=config.repository,
            privacy=config.privacy,
            scanner_findings=[scanner_finding],
        )
