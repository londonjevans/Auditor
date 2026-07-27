"""Abusive-authorized-user workflow review role."""

from mmaudit.agents.base import FindingAgent


class BusinessLogicAgent(FindingAgent):
    role = "business_logic"
    prompt_file = "business_logic.md"
