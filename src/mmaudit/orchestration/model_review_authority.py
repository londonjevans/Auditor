"""Opaque types for scheduler-owned model-review dispatch authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Never, SupportsIndex


@dataclass(frozen=True, slots=True)
class ModelReviewPreDispatchBinding:
    """Exact provider-visible request state bound before transport dispatch."""

    request_id: str
    task_id: str
    review_role: str
    requested_model: str
    root_lineage: str
    requested_surface_manifest_sha256: str
    rendered_context_sha256: str
    provider_prompt_sha256: str
    response_schema_sha256: str
    task_plan_sha256: str
    activation_sha256: str
    dispatched_event_sha256: str


class ModelReviewPreDispatchAuthorization:
    """Opaque process-local proof issued by exact scheduler custody."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> ModelReviewPreDispatchAuthorization:
        del cls
        raise TypeError("model-review pre-dispatch authorization cannot be constructed directly")

    def __copy__(self) -> Never:
        raise TypeError("model-review pre-dispatch authorization cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("model-review pre-dispatch authorization cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("model-review pre-dispatch authorization cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("model-review pre-dispatch authorization cannot be serialized")
