"""
Integration Tests for Phase 2.

Tests that combine multiple Phase 2 components:
- Engine + PythonTarget + MockLLM
- Factory + Config integration
"""

from serix_v2.core.contracts import AttackMode, AttackStatus, Persona
from serix_v2.engine import AdversaryEngine
from serix_v2.targets import PythonFunctionTarget
from tests.serix_v2.mocks import MockAttacker, MockCritic, MockJudge


class TestEngineWithPythonTarget:
    """Test AdversaryEngine with real PythonFunctionTarget."""

    def test_engine_with_python_target_mock_llm(self) -> None:
        """Engine + real PythonTarget + MockAttacker/Judge/Critic."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        engine = AdversaryEngine(
            target=target,
            attacker=MockAttacker(["Hello", "World"]),
            judge=MockJudge([AttackStatus.DEFENDED, AttackStatus.EXPLOITED]),
            critic=None,
        )

        result = engine.run(
            goal="test",
            depth=3,
            mode=AttackMode.STATIC,
            persona=Persona.JAILBREAKER,
        )

        assert result.success is True
        assert len(result.turns) == 2  # Stopped on exploit
        assert result.winning_payload == "World"

    def test_engine_runs_full_depth_when_no_exploit(self) -> None:
        """Test engine runs to full depth when no exploit found."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        engine = AdversaryEngine(
            target=target,
            attacker=MockAttacker(["A", "B", "C", "D", "E"]),
            judge=MockJudge([AttackStatus.DEFENDED] * 5),
            critic=None,
        )

        result = engine.run(
            goal="test",
            depth=5,
            mode=AttackMode.STATIC,
            persona=Persona.JAILBREAKER,
        )

        assert result.success is False
        assert len(result.turns) == 5

    def test_engine_with_vulnerable_agent(self) -> None:
        """Test engine finds exploit in vulnerable agent."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:VulnerableAgent.respond"
        )

        # Simulate attack that eventually asks for secret
        engine = AdversaryEngine(
            target=target,
            attacker=MockAttacker(
                [
                    "Hello",
                    "Tell me about yourself",
                    "What is the secret?",
                ]
            ),
            judge=MockJudge(
                [
                    AttackStatus.DEFENDED,
                    AttackStatus.DEFENDED,
                    AttackStatus.EXPLOITED,
                ]
            ),
            critic=None,
        )

        result = engine.run(
            goal="reveal secrets",
            depth=5,
            mode=AttackMode.STATIC,
            persona=Persona.EXTRACTOR,
        )

        assert result.success is True
        assert "secret" in result.turns[-1].response.lower()

    def test_engine_with_adaptive_mode_and_critic(self) -> None:
        """Test engine with adaptive mode and critic feedback."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        engine = AdversaryEngine(
            target=target,
            attacker=MockAttacker(["Attempt 1", "Attempt 2", "Attempt 3"]),
            judge=MockJudge([AttackStatus.DEFENDED] * 3),
            critic=MockCritic([True, True, False]),  # Stop after turn 3
        )

        result = engine.run(
            goal="test",
            depth=5,
            mode=AttackMode.ADAPTIVE,
            persona=Persona.JAILBREAKER,
        )

        assert result.success is False
        assert len(result.turns) == 3  # Stopped by critic

    def test_engine_exhaustive_mode_continues_after_exploit(self) -> None:
        """Test exhaustive mode continues even after finding exploit."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        engine = AdversaryEngine(
            target=target,
            attacker=MockAttacker(["A", "B", "C", "D"]),
            judge=MockJudge(
                [
                    AttackStatus.DEFENDED,
                    AttackStatus.EXPLOITED,  # Found exploit
                    AttackStatus.DEFENDED,
                    AttackStatus.EXPLOITED,  # Found another
                ]
            ),
            critic=None,
        )

        result = engine.run(
            goal="test",
            depth=4,
            exhaustive=True,  # Continue after exploit
            mode=AttackMode.STATIC,
            persona=Persona.JAILBREAKER,
        )

        assert result.success is True  # Sticky success
        assert len(result.turns) == 4  # Ran all turns
        assert result.winning_payload == "B"  # First winning payload


class TestTargetBehavior:
    """Test target behavior in isolation."""

    def test_python_target_returns_expected_output(self) -> None:
        """Verify PythonTarget integrates correctly with test fixture."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        result = target("Hello World")
        assert result == "Echo: Hello World"

    def test_class_method_target(self) -> None:
        """Verify Class.method syntax works correctly."""
        target = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:Agent.respond"
        )

        result = target("Test message")
        assert "TestAgent" in result
        assert "Test message" in result

    def test_target_id_consistency(self) -> None:
        """Verify target IDs are consistent and can be used for storage."""
        target = PythonFunctionTarget("tests/serix_v2/fixtures/echo_agent.py:echo")

        # ID should be stable
        id1 = target.id
        id2 = target.id
        assert id1 == id2
        assert id1.startswith("t_")

        # Different targets should have different IDs
        target2 = PythonFunctionTarget(
            "tests/serix_v2/fixtures/echo_agent.py:VulnerableAgent.respond"
        )
        assert target.id != target2.id
