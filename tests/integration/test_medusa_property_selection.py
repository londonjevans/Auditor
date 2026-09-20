"""Generated native configuration must select the intended local boolean properties."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess

import pytest

from mmaudit.config import FormalConfig
from mmaudit.solidity.formal import MedusaAdapter
from tests.unit.test_echidna import FIXTURE, _inputs


@pytest.mark.parametrize("timeout", [1, 12, 3600])
def test_retained_medusa_configuration_selects_every_boolean_property(
    tmp_path, monkeypatch, config_factory, timeout
):
    """Exercise real preparation/file I/O, not native compilation or qualification."""

    def forbidden(*_args, **_kwargs):
        pytest.fail("configuration preparation attempted external execution")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE, workspace)
    _, index, _, corpus = _inputs(workspace, config_factory())
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    config = FormalConfig(enabled=True, timeout_seconds=timeout)
    prepared = MedusaAdapter().prepare_workspace(
        workspace=workspace, index=index, property_corpus=corpus, config=config
    )
    assert prepared is not None and prepared.property_map
    generated = workspace / "mmaudit-medusa"
    retained = json.loads((generated / "medusa.json").read_bytes())
    assert retained == json.loads(prepared.configuration)
    assert (generated / "MMAuditMedusa.sol").read_text() == prepared.source
    properties = retained["fuzzing"]["testing"]["propertyTesting"]
    assert properties == {"enabled": True, "testPrefixes": ["echidna_"]}
    prefixes = tuple(properties["testPrefixes"])
    assert all(name.startswith(prefixes) for name in prepared.property_map)
    mapping = json.loads((generated / "property-map.json").read_bytes())
    assert mapping["corpus_hash"] == corpus.corpus_hash
    assert mapping["properties"] == {name: spec.id for name, spec in prepared.property_map.items()}
    assert retained["fuzzing"]["timeout"] == timeout
    assert retained["fuzzing"]["testLimit"] == prepared.runs == 100
    assert retained["fuzzing"]["workers"] == 1
    assert retained["fuzzing"]["testing"]["testAllContracts"] is False
    assert retained["fuzzing"]["testing"]["stopOnNoTests"] is True
    assert not (workspace / "out").exists()
    assert not (workspace / "cache").exists()
