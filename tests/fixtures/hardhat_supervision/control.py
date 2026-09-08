"""Synthetic finite process controls only; no Hardhat, contracts, network or credentials."""

import os
import sys
import time
from pathlib import Path

mode, output = sys.argv[1:]
root = Path(output)
report = root / "hardhat-report.json"
if mode == "timeout":
    time.sleep(2)
elif mode == "stream_limit":
    os.write(1, b"a" * 700)
    os.write(2, b"b" * 700)
elif mode == "report_limit":
    report.write_bytes(b"x" * 2048)
    time.sleep(2)
elif mode == "missing":
    os.write(1, b"fixed missing-report control")
elif mode in {"symlink", "hardlink"}:
    target = root / "synthetic-target.json"
    target.write_bytes(b"{}")
    if mode == "symlink":
        report.symlink_to(target.name)
    else:
        os.link(target, report)
elif mode == "descendant":
    report.write_bytes(b'{"synthetic":true}\n')
    if os.fork() == 0:
        for descriptor in (0, 1, 2):
            os.close(descriptor)
        time.sleep(2)
        os._exit(0)
elif mode == "bytes":
    report.write_bytes(b'{"synthetic":true}\n')
    os.write(1, b"\xff\x00")
    os.write(2, b"\xfe")
elif mode in {"success", "exit"}:
    report.write_bytes(b'{"synthetic":true}\n')
    os.write(1, b"fixed stdout\n")
    os.write(2, b"fixed stderr\n")
    if mode == "exit":
        sys.exit(7)
else:
    sys.exit(23)
