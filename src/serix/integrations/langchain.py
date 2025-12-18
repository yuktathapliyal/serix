"""LangChain integration - wraps AgentExecutor for Serix testing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    pass


def test_langchain(
    agent: Any,
    system_prompt: str | None = None,
    input_key: str = "input",
    output_key: str = "output",
    scenarios: list[str] | None = None,
) -> Callable[[str], str]:
    """Wrap a LangChain AgentExecutor for Serix testing.

    Args:
        agent: AgentExecutor or similar with invoke()
        system_prompt: For self-healing suggestions
        input_key: Key for invoke input dict
        output_key: Key for result dict
        scenarios: Attack types to test

    Returns:
        Wrapped callable for Serix testing
    """
    import serix

    scenarios = scenarios or ["jailbreak"]

    @serix.scan(scenarios=scenarios, system_prompt=system_prompt)
    def wrapped_agent(user_input: str) -> str:
        result = agent.invoke({input_key: user_input})
        if isinstance(result, dict):
            return result.get(output_key, str(result))
        return str(result)

    return wrapped_agent
