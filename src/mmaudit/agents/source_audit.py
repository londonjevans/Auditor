"""Concrete source-to-sink vulnerability role."""

from mmaudit.agents.base import FindingAgent


class SourceAuditAgent(FindingAgent):
    role = "source_audit"
    prompt_file = "source_audit.md"
