"""CrewAI integration - wraps Crew for Serix testing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    pass


def test_crewai(
    crew: Any,
    system_prompt: str | None = None,
    input_key: str = "input",
    scenarios: list[str] | None = None,
) -> Callable[[str], str]:
    """Wrap a CrewAI Crew for Serix testing.

    Args:
        crew: Crew instance with kickoff()
        system_prompt: For self-healing suggestions
        input_key: Key for kickoff input dict
        scenarios: Attack types to test

    Returns:
        Wrapped callable for Serix testing
    """
    import serix

    scenarios = scenarios or ["jailbreak"]

    @serix.scan(scenarios=scenarios, system_prompt=system_prompt)
    def wrapped_crew(user_input: str) -> str:
        result = crew.kickoff(inputs={input_key: user_input})
        return str(result)

    return wrapped_crew
