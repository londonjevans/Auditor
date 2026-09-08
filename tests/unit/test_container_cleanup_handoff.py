"""Retained launch-to-cleanup inputs, using synthetic files and MOCK CLI replies only."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.isolation import container_cleanup as cleanup
from mmaudit.scanners.base import _observe_scanner_executable
from tests.unit.test_container_cleanup import CID, mock_controls
from tests.unit.test_container_cleanup import selected as selected


@pytest.fixture
def handoff(selected, monkeypatch):
    backend, private, cidfile = selected
    observation = _observe_scanner_executable(Path(backend.executable))
    monkeypatch.setattr(cleanup, "_runtime_identity", lambda *_: observation)
    environment = backend.host_environment(private)
    environment["PATH"] = str(Path(backend.executable).parent) + os.pathsep + "/usr/bin:/bin"
    return backend, private, cidfile, observation, environment


def test_exact_retained_environment_is_used_without_ambient_reread(handoff, monkeypatch):
    backend, private, cidfile, identity, environment = handoff
    environment["DOCKER_HOST"] = "unix:///synthetic/owned-launch.sock"
    monkeypatch.setenv("DOCKER_HOST", "unix:///synthetic/other.sock")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: retained cleanup must not rebuild runtime routing")

    monkeypatch.setattr(cleanup, "rootless_runtime_environment", forbidden)
    calls = mock_controls(monkeypatch, [CID.encode(), b"", b""])
    result = cleanup.cleanup_rootless_container(
        backend,
        private,
        environment=environment,
        expected_runtime_identity=identity,
        expected_container_id=CID,
    )
    assert result.absence_verified and not cidfile.exists()
    assert all(kwargs["environment"] == environment for _, kwargs in calls)
    assert all(kwargs["environment"] is not environment for _, kwargs in calls)
    assert result.execution_credit is result.runtime_authority is False


@pytest.mark.parametrize("change", ["digest", "file_identity", "cid"])
def test_changed_expected_executable_or_identifier_refuses_before_control(handoff, change):
    backend, private, cidfile, identity, environment = handoff
    expected = replace(identity, sha256="b" * 64) if change == "digest" else identity
    if change == "file_identity":
        expected = replace(identity, identity=(0,))
    with pytest.raises(cleanup.ContainerCleanupError, match="retained"):
        cleanup.cleanup_rootless_container(
            backend,
            private,
            environment=environment,
            expected_runtime_identity=expected,
            expected_container_id="b" * 64 if change == "cid" else CID,
        )
    assert cidfile.read_text() == CID


@pytest.mark.parametrize(
    "key,value",
    [
        ("PATH", ".:/synthetic"),
        ("HOME", "/synthetic/other"),
        ("DOCKER_HOST", "tcp://127.0.0.1:1234"),
        ("CONTAINER_HOST", "ssh://synthetic"),
        ("XDG_RUNTIME_DIR", "relative"),
        ("PYTHONPATH", "/synthetic"),
        ("OPENROUTER_API_KEY", "synthetic-not-a-secret"),
        ("HOME", None),
        ("LANG", "nul\x00value"),
    ],
)
def test_supplied_environment_cannot_expand_cleanup_scope(handoff, key, value):
    backend, private, cidfile, identity, environment = handoff
    environment[key] = value
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(
            backend,
            private,
            environment=environment,
            expected_runtime_identity=identity,
            expected_container_id=CID,
        )
    assert cidfile.exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("environment", []),
        ("expected_runtime_identity", {}),
        ("expected_container_id", True),
        ("expected_container_id", "a" * 12),
        ("expected_container_id", "A" * 64),
    ],
)
def test_expected_handoff_inputs_require_exact_types(handoff, key, value):
    backend, private, cidfile, _, _ = handoff
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(backend, private, **{key: value})
    assert cidfile.exists()


def test_retained_client_home_link_is_refused(handoff):
    backend, private, cidfile, identity, environment = handoff
    client_home = Path(environment["HOME"])
    retained = client_home.with_name("retained-home")
    client_home.rename(retained)
    client_home.symlink_to(retained, target_is_directory=True)
    with pytest.raises(cleanup.ContainerCleanupError):
        cleanup.cleanup_rootless_container(
            backend,
            private,
            environment=environment,
            expected_runtime_identity=identity,
            expected_container_id=CID,
        )
    assert cidfile.exists()
