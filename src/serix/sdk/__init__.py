"""Serix SDK - Clean integration for Python agents.

Usage:
    import serix

    @serix.scan(scenarios=["injection", "pii_leak"])
    def my_agent(user_input: str) -> str:
        response = client.chat.completions.create(...)
        return response.choices[0].message.content

    # Run: serix test my_agent.py:my_agent
"""

from serix.sdk.decorator import Agent, scan

__all__ = ["scan", "Agent"]
