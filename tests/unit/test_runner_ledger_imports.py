"""Fresh local interpreter imports; no credential, provider, or subprocess use inside the child."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "first",
    (
        "mmaudit.models.authenticated_runner",
        "mmaudit.models.authenticated_runner_ledger",
        "mmaudit.orchestration.authenticated_calibration_accounting",
    ),
)
def test_import_order_does_not_create_an_initialization_cycle(first: str) -> None:
    source = (
        "import sys, os, importlib\n"
        "def guard(event, args):\n"
        "    if event.startswith('socket.') or event in {'subprocess.Popen', 'os.system', 'os.posix_spawn'}:\n"
        "        raise AssertionError('import must not contact providers or launch processes')\n"
        "    if event == 'open' and isinstance(args[0], (str, bytes)):\n"
        "        name = os.path.basename(os.fsdecode(args[0]))\n"
        "        if name == '.env' or name.startswith('.env.'):\n"
        "            raise AssertionError('import must not read secrets')\n"
        "sys.addaudithook(guard)\n"
        f"importlib.import_module({first!r})\n"
        "from mmaudit.models import authenticated_runner as r, authenticated_runner_ledger as l\n"
        "from mmaudit.orchestration import authenticated_calibration_accounting as a\n"
        "assert r.ClosedCrossLineageLedgerInterval is l.ClosedCrossLineageLedgerInterval\n"
        "assert a.ClosedCrossLineageLedgerInterval is l.ClosedCrossLineageLedgerInterval\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MMAUDIT_RUN_REAL_PROVIDER_TESTS": "0",
            "MMAUDIT_SECRETS_ENV_FILE": "",
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
