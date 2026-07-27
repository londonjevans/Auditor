"""Documents the intended nearby-control behavior without importing a web app."""

from pathlib import Path


def locally_safe_avatar(root: Path, filename: str) -> Path:
    if not filename.isascii() or not filename.replace(".", "").isalnum():
        raise ValueError("invalid")
    result = (root / filename).resolve()
    if result.parent != root.resolve():
        raise ValueError("escaped")
    return result
