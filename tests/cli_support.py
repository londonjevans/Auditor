"""Run synchronous CLI entry points without displacing pytest's event loop."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from typer.testing import CliRunner, Result


class IsolatedLoopCliRunner(CliRunner):
    """Give the real CLI's asyncio.run its own thread-local loop policy state."""

    def invoke(self, *args: Any, **kwargs: Any) -> Result:
        invoke = super().invoke
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(invoke, *args, **kwargs).result(timeout=30)
