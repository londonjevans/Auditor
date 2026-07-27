"""Intentionally vulnerable, non-deployable test fixture."""

from pathlib import Path
from urllib.request import urlopen

UPLOAD_ROOT = Path("/tmp/mmaudit-synthetic-uploads")
DEMO_SIGNING_SECRET = "test-only-placeholder-value"
used_credit_events: set[str] = set()


def search_users(connection: object, query: str) -> object:
    """SQL injection: attacker text is interpolated into a query."""
    sql = f"SELECT id, email FROM users WHERE email LIKE '%{query}%'"
    return connection.execute(sql)  # type: ignore[attr-defined]


def download_upload(filename: str) -> str:
    """Path traversal: filename is not constrained to UPLOAD_ROOT."""
    target = UPLOAD_ROOT / filename
    return target.read_text(encoding="utf-8")


def get_project(connection: object, project_id: str, tenant_id: str) -> object:
    """Tenant ID is accepted but omitted from the lookup."""
    del tenant_id
    return connection.execute(  # type: ignore[attr-defined]
        "SELECT * FROM projects WHERE id = ?", (project_id,)
    ).fetchone()


def preview_url(user_url: str) -> bytes:
    """SSRF: arbitrary schemes and destinations are accepted."""
    return urlopen(user_url, timeout=2).read()


def apply_credit(account: dict[str, int], event_id: str, amount: int) -> None:
    """Replay issue: event_id is never checked or recorded."""
    del event_id
    account["balance"] += amount


def safe_avatar_path(filename: str) -> Path:
    """Intentional false positive: a nearby allowlist blocks traversal."""
    if not filename.isascii() or not filename.replace(".", "").isalnum():
        raise ValueError("invalid avatar name")
    target = (UPLOAD_ROOT / filename).resolve()
    if target.parent != UPLOAD_ROOT.resolve():
        raise ValueError("path escaped upload directory")
    return target
