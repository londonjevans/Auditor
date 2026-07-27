from __future__ import annotations

import json
import pickle
import traceback
from pathlib import Path

import pytest

from mmaudit.operator_secrets import (
    MAX_OPERATOR_SECRET_FILE_BYTES,
    OPENROUTER_API_KEY_NAME,
    SECRETS_ENV_FILE_VARIABLE,
    OperatorSecretError,
    load_operator_secrets,
    select_operator_secret_file,
)

CANARY = "sk-or-v1-synthetic-secret-boundary-canary"


def _write_secret_file(path: Path, value: str = CANARY) -> Path:
    path.write_text(f"{OPENROUTER_API_KEY_NAME}={value}\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def test_explicit_dotenv_load_is_allowlisted_and_non_interpolating(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    literal = "sk-${IGNORED}-$(id)"
    path = tmp_path / "operator.env"
    path.write_text(
        "\n".join(
            (
                "IGNORED=synthetic-unrelated-value",
                f"{OPENROUTER_API_KEY_NAME}='{literal}'",
                f"COMMAND='touch {marker}'",
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    with load_operator_secrets(path, environ={}) as secrets:
        assert secrets.openrouter_api_key == literal
        assert secrets.get("IGNORED") == ""

    assert not marker.exists()


def test_only_selector_environment_is_consulted(tmp_path: Path) -> None:
    path = _write_secret_file(tmp_path / "operator.env")
    environment = {
        OPENROUTER_API_KEY_NAME: "ambient-value-must-be-ignored",
        SECRETS_ENV_FILE_VARIABLE: str(path),
    }

    with load_operator_secrets(None, environ=environment, required=True) as secrets:
        assert secrets.openrouter_api_key == CANARY

    without_selector = load_operator_secrets(
        None,
        environ={OPENROUTER_API_KEY_NAME: CANARY},
        required=False,
    )
    assert not without_selector.openrouter_api_key_present


def test_conflicting_secret_file_selectors_are_rejected(tmp_path: Path) -> None:
    left = _write_secret_file(tmp_path / "left.env")
    right = _write_secret_file(tmp_path / "right.env")

    with pytest.raises(OperatorSecretError, match="ambiguous"):
        select_operator_secret_file(
            left,
            environ={SECRETS_ENV_FILE_VARIABLE: str(right)},
        )


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
def test_group_or_world_writable_secret_file_is_rejected(tmp_path: Path, mode: int) -> None:
    path = _write_secret_file(tmp_path / "operator.env")
    path.chmod(mode)

    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(path, environ={}, required=True)


def test_secret_file_links_and_non_files_are_rejected(tmp_path: Path) -> None:
    target = _write_secret_file(tmp_path / "real.env")
    link = tmp_path / "linked.env"
    link.symlink_to(target)
    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(link, environ={}, required=True)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    nested = _write_secret_file(real_parent / "operator.env")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(linked_parent / nested.name, environ={}, required=True)

    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(real_parent, environ={}, required=True)


def test_secret_file_size_encoding_and_nul_are_bounded(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.env"
    oversized.write_bytes(b"x" * (MAX_OPERATOR_SECRET_FILE_BYTES + 1))
    oversized.chmod(0o600)
    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(oversized, environ={}, required=True)

    invalid_utf8 = tmp_path / "invalid-utf8.env"
    invalid_utf8.write_bytes(b"OPENROUTER_API_KEY=valid-prefix\xff")
    invalid_utf8.chmod(0o600)
    with pytest.raises(OperatorSecretError, match="UTF-8"):
        load_operator_secrets(invalid_utf8, environ={}, required=True)

    nul = tmp_path / "nul.env"
    nul.write_bytes(b"OPENROUTER_API_KEY=prefix\x00suffix")
    nul.chmod(0o600)
    with pytest.raises(OperatorSecretError, match="rejected"):
        load_operator_secrets(nul, environ={}, required=True)


@pytest.mark.parametrize(
    "value",
    [
        "contains tab",
        "contains\ttab",
        "sk-é",
        "x" * 4_097,
    ],
)
def test_approved_secret_value_must_be_bounded_printable_ascii(
    tmp_path: Path,
    value: str,
) -> None:
    path = _write_secret_file(tmp_path / "invalid-value.env", value)

    with pytest.raises(OperatorSecretError, match="invalid approved value"):
        load_operator_secrets(path, environ={}, required=True)


def test_secret_holder_is_redacted_nonserializable_and_clearable(tmp_path: Path) -> None:
    secrets = load_operator_secrets(
        _write_secret_file(tmp_path / "operator.env"),
        environ={},
        required=True,
    )

    assert CANARY not in repr(secrets)
    assert CANARY not in str(secrets)
    with pytest.raises(TypeError):
        pickle.dumps(secrets)
    with pytest.raises(TypeError):
        json.dumps(secrets)

    secrets.clear()
    secrets.clear()
    assert secrets.cleared
    assert not secrets.openrouter_api_key_present
    assert secrets.openrouter_api_key == ""


def test_validation_error_diagnostics_do_not_retain_secret_value(tmp_path: Path) -> None:
    path = tmp_path / "operator.env"
    path.write_text(
        f'{OPENROUTER_API_KEY_NAME}="{CANARY}\ncontinued"\n',
        encoding="utf-8",
    )
    path.chmod(0o600)

    with pytest.raises(OperatorSecretError) as captured:
        load_operator_secrets(path, environ={}, required=True)

    rendered = "".join(traceback.format_exception(captured.value))
    assert CANARY not in rendered
    assert CANARY not in repr(captured.value)
