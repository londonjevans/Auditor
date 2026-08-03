from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[2]
PACKAGED_RESOURCES = (
    "mmaudit/scanners/rules/security.yml",
    "mmaudit/scanners/rules/gitleaks.toml",
)


def test_built_wheel_contains_importable_exact_scanner_rule_resources(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hatchling",
            "build",
            "--target",
            "wheel",
            "--directory",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]

    expected_hashes: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for packaged_path in PACKAGED_RESOURCES:
            assert packaged_path in names
            source_path = ROOT / "src" / packaged_path
            packaged_bytes = archive.read(packaged_path)
            assert packaged_bytes == source_path.read_bytes()
            expected_hashes[packaged_path] = hashlib.sha256(packaged_bytes).hexdigest()

    probe = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            "\n".join(
                (
                    "import hashlib, json, sys",
                    "from importlib.resources import files",
                    "sys.path.insert(0, sys.argv[1])",
                    "observed = {}",
                    "for path in sys.argv[2:]:",
                    "    resource = files('mmaudit.scanners').joinpath(*path.split('/')[2:])",
                    "    assert resource.is_file()",
                    "    observed[path] = hashlib.sha256(resource.read_bytes()).hexdigest()",
                    "print(json.dumps(observed, sort_keys=True))",
                )
            ),
            str(wheel),
            *PACKAGED_RESOURCES,
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert probe.returncode == 0, probe.stderr
    assert json.loads(probe.stdout) == expected_hashes
