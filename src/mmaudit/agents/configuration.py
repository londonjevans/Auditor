"""Configuration and supply-chain role."""

from mmaudit.agents.base import FindingAgent


class ConfigurationAgent(FindingAgent):
    role = "configuration"
    prompt_file = "configuration.md"
