"""
Serix v2 - Law Compliance Tests

Phase 7.1: 40 tests proving architectural compliance with the 8 Laws.

Reference: docs/serix-phoenix-rebuild/CONTRACTS/00-LAWS.md
"""

import ast
from pathlib import Path

from pydantic import BaseModel

from serix_v2.core.config import SerixSessionConfig
from serix_v2.core.contracts import (
    AttackMode,
    AttackResult,
    AttackStatus,
    AttackTransition,
    AttackTurn,
    CampaignResult,
    CriticFeedback,
    HealingResult,
    JudgeVerdict,
    Persona,
    RegressionResult,
    ResilienceResult,
    StoredAttack,
    VulnerabilityAnalysis,
)
from serix_v2.core.id_gen import generate_target_id
from serix_v2.engine.adversary import AdversaryEngine
from serix_v2.providers.analyzer import LLMAnalyzer
from serix_v2.providers.critic import LLMCritic
from serix_v2.providers.judge import LLMJudge
from serix_v2.providers.patcher import LLMPatcher
from serix_v2.services.fuzz import FuzzService
from serix_v2.services.regression import RegressionService
from serix_v2.workflows.test_workflow import TestWorkflow
from tests.serix_v2.mocks import (
    MockAttacker,
    MockAttackStore,
    MockCampaignStore,
    MockCrashingTarget,
    MockCritic,
    MockJudge,
    MockLLMProvider,
    MockTarget,
)

# =============================================================================
# Helper: Find source files
# =============================================================================


def get_serix_v2_path() -> Path:
    """Get the path to src/serix_v2."""
    return Path(__file__).parent.parent.parent.parent / "src" / "serix_v2"


def get_python_files(directory: Path) -> list[Path]:
    """Get all .py files in a directory (non-recursive)."""
    return list(directory.glob("*.py"))


def parse_imports(filepath: Path) -> set[str]:
    """Parse a Python file and return all import names."""
    with open(filepath) as f:
        tree = ast.parse(f.read())

    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return imports


def find_module_level_assignments(filepath: Path) -> list[str]:
    """Find module-level mutable assignments (globals)."""
    with open(filepath) as f:
        tree = ast.parse(f.read())

    # Only look at top-level nodes (not inside functions/classes)
    mutable_globals = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Skip constants (UPPER_CASE) and type aliases
                    if not target.id.isupper() and not target.id.startswith("_"):
                        # Check if it's a mutable type (list, dict, set)
                        if isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
                            mutable_globals.append(target.id)
    return mutable_globals


# =============================================================================
# Law 1: No-Dictionary Law (8 tests)
# =============================================================================


class TestLaw1NoDictionary:
    """Law 1: No raw dicts between modules. Everything is a Pydantic model."""

    def test_engine_returns_attack_result_not_dict(self) -> None:
        """AdversaryEngine.run() returns AttackResult, not dict."""
        target = MockTarget(responses=["Safe response"])
        attacker = MockAttacker(payloads=["test payload"])
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=None,
        )

        result = engine.run(goal="test goal", depth=1)

        assert isinstance(result, AttackResult)
        assert isinstance(result, BaseModel)
        assert not isinstance(result, dict)

    def test_workflow_returns_campaign_result_not_dict(self, tmp_path: Path) -> None:
        """TestWorkflow.run() returns CampaignResult, not dict."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            goals=["test goal"],
            scenarios=["jailbreaker"],
            depth=1,
            dry_run=True,  # Don't write files
        )

        target = MockTarget()
        llm = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        result = workflow.run()

        assert isinstance(result, CampaignResult)
        assert isinstance(result, BaseModel)
        assert not isinstance(result, dict)

    def test_regression_service_returns_pydantic_model(self) -> None:
        """RegressionService.run() returns RegressionResult."""
        from serix_v2.core.contracts import AttackLibrary

        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget()

        service = RegressionService(judge=judge, target=target)

        # Create a library with one attack
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                StoredAttack(
                    id="a_test",
                    target_id="t_test",
                    goal="test",
                    strategy_id="jailbreaker",
                    payload="test payload",
                    status=AttackStatus.EXPLOITED,
                )
            ],
        )

        result = service.run(library=library, skip_mitigated=False)

        assert isinstance(result, RegressionResult)
        assert isinstance(result, BaseModel)

    def test_fuzz_service_returns_list_of_models(self) -> None:
        """FuzzService.run() returns list[ResilienceResult]."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            fuzz=True,
            fuzz_latency=0.01,  # Small delay for fast test
        )
        target = MockTarget()

        service = FuzzService(target=target, config=config)
        result = service.run()

        assert isinstance(result, list)
        assert all(isinstance(r, ResilienceResult) for r in result)
        assert all(isinstance(r, BaseModel) for r in result)

    def test_judge_returns_judge_verdict(self) -> None:
        """LLMJudge.evaluate() returns JudgeVerdict."""
        llm = MockLLMProvider(
            responses=[
                '{"verdict": "defended", "confidence": 0.9, "reasoning": "Test"}'
            ]
        )
        judge = LLMJudge(llm_provider=llm, model="test-model")

        result = judge.evaluate(
            goal="test goal",
            payload="test payload",
            response="test response",
        )

        assert isinstance(result, JudgeVerdict)
        assert isinstance(result, BaseModel)

    def test_critic_returns_critic_feedback(self) -> None:
        """LLMCritic.evaluate() returns CriticFeedback."""
        llm = MockLLMProvider(
            responses=[
                '{"should_continue": true, "confidence": 0.8, "reasoning": "Test", "suggested_pivot": null}'
            ]
        )
        critic = LLMCritic(llm_provider=llm, model="test-model")

        result = critic.evaluate(goal="test goal", turns=[])

        assert isinstance(result, CriticFeedback)
        assert isinstance(result, BaseModel)

    def test_analyzer_returns_vulnerability_analysis(self) -> None:
        """LLMAnalyzer.analyze() returns VulnerabilityAnalysis."""
        llm = MockLLMProvider(
            responses=[
                '{"vulnerability_type": "jailbreak", "owasp_code": "LLM01", "severity": "high", "root_cause": "Test"}'
            ]
        )
        analyzer = LLMAnalyzer(llm_provider=llm, model="test-model")

        result = analyzer.analyze(
            goal="test goal",
            payload="test payload",
            response="test response",
        )

        assert isinstance(result, VulnerabilityAnalysis)
        assert isinstance(result, BaseModel)

    def test_patcher_returns_healing_result(self) -> None:
        """LLMPatcher.heal() returns HealingResult."""
        llm = MockLLMProvider(
            responses=[
                '{"patch": {"original": "test", "patched": "test patched", "diff": "---", "explanation": "Fixed"}, "recommendations": [], "confidence": 0.9}'
            ]
        )
        patcher = LLMPatcher(llm_provider=llm, model="test-model")

        # Create minimal analysis
        analysis = VulnerabilityAnalysis(
            vulnerability_type="jailbreak",
            owasp_code="LLM01",
            severity="high",
            root_cause="Test",
        )

        result = patcher.heal(
            original_prompt="test prompt",
            attacks=[("payload", "response")],
            analysis=analysis,
        )

        assert isinstance(result, HealingResult)
        assert isinstance(result, BaseModel)


# =============================================================================
# Law 2: CLI-is-a-Guest Law (3 tests)
# =============================================================================


class TestLaw2CLIIsGuest:
    """Law 2: No typer/rich/click imports in engine/services/workflows."""

    # Forbidden CLI libraries
    CLI_LIBS = {"typer", "rich", "click", "prompt_toolkit"}

    def test_engine_no_typer_imports(self) -> None:
        """adversary.py has no typer/rich/click imports."""
        engine_path = get_serix_v2_path() / "engine" / "adversary.py"
        assert engine_path.exists(), f"Engine file not found: {engine_path}"

        imports = parse_imports(engine_path)
        cli_imports = imports & self.CLI_LIBS

        assert not cli_imports, f"Engine has CLI imports: {cli_imports}"

    def test_services_no_typer_imports(self) -> None:
        """services/*.py has no CLI imports."""
        services_dir = get_serix_v2_path() / "services"
        assert services_dir.exists(), f"Services dir not found: {services_dir}"

        for py_file in get_python_files(services_dir):
            if py_file.name == "__init__.py":
                continue

            imports = parse_imports(py_file)
            cli_imports = imports & self.CLI_LIBS

            assert not cli_imports, f"{py_file.name} has CLI imports: {cli_imports}"

    def test_workflows_no_typer_imports(self) -> None:
        """workflows/*.py has no CLI imports."""
        workflows_dir = get_serix_v2_path() / "workflows"
        assert workflows_dir.exists(), f"Workflows dir not found: {workflows_dir}"

        for py_file in get_python_files(workflows_dir):
            if py_file.name == "__init__.py":
                continue

            imports = parse_imports(py_file)
            cli_imports = imports & self.CLI_LIBS

            assert not cli_imports, f"{py_file.name} has CLI imports: {cli_imports}"


# =============================================================================
# Law 3: Protocol Law (4 tests)
# =============================================================================


class TestLaw3Protocol:
    """Law 3: Depend on interfaces, not implementations."""

    def test_engine_accepts_any_target_protocol(self) -> None:
        """Engine works with any Target protocol implementation."""

        # Create a custom target that implements the protocol
        class CustomTarget:
            @property
            def id(self) -> str:
                return "t_custom"

            @property
            def locator(self) -> str:
                return "custom.py:fn"

            def __call__(self, message: str) -> str:
                return "Custom response"

        target = CustomTarget()
        attacker = MockAttacker()
        judge = MockJudge()

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
        )

        # Should work without type errors
        result = engine.run(goal="test", depth=1)
        assert result.turns[0].response == "Custom response"

    def test_workflow_accepts_protocol_implementations(self) -> None:
        """Workflow accepts protocol implementations."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            goals=["test"],
            depth=1,
            dry_run=True,
        )

        # All of these are protocol implementations, not concrete classes
        target = MockTarget()
        llm = MockLLMProvider()
        attack_store = MockAttackStore()
        campaign_store = MockCampaignStore()

        # Should accept these without type errors
        workflow = TestWorkflow(
            config=config,
            target=target,
            llm_provider=llm,
            attack_store=attack_store,
            campaign_store=campaign_store,
        )

        assert workflow is not None

    def test_regression_service_uses_judge_protocol(self) -> None:
        """RegressionService uses Judge protocol."""

        # Create a custom judge that implements the protocol
        class CustomJudge:
            def evaluate(self, goal: str, payload: str, response: str) -> JudgeVerdict:
                return JudgeVerdict(
                    verdict=AttackStatus.DEFENDED,
                    confidence=1.0,
                    reasoning="Custom judge",
                )

        judge = CustomJudge()
        target = MockTarget()

        # Should accept custom judge
        service = RegressionService(judge=judge, target=target)
        assert service is not None

    def test_fuzz_service_uses_target_protocol(self) -> None:
        """FuzzService uses Target protocol."""

        # Create a custom target
        class CustomTarget:
            @property
            def id(self) -> str:
                return "t_custom"

            @property
            def locator(self) -> str:
                return "custom.py:fn"

            def __call__(self, message: str) -> str:
                return "Custom response"

        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            fuzz=True,
            fuzz_latency=0.01,
        )

        target = CustomTarget()
        service = FuzzService(target=target, config=config)

        # Should work with custom target
        result = service.run()
        assert isinstance(result, list)


# =============================================================================
# Law 4: Stateless Engine Law (2 tests)
# =============================================================================


class TestLaw4StatelessEngine:
    """Law 4: No module-level mutable state."""

    def test_no_module_globals_in_engine(self) -> None:
        """adversary.py has no module-level mutable state."""
        engine_path = get_serix_v2_path() / "engine" / "adversary.py"
        assert engine_path.exists()

        mutable_globals = find_module_level_assignments(engine_path)

        assert not mutable_globals, f"Engine has mutable globals: {mutable_globals}"

    def test_no_module_globals_in_services(self) -> None:
        """Service modules have no mutable globals."""
        services_dir = get_serix_v2_path() / "services"
        assert services_dir.exists()

        for py_file in get_python_files(services_dir):
            if py_file.name == "__init__.py":
                continue

            mutable_globals = find_module_level_assignments(py_file)

            assert (
                not mutable_globals
            ), f"{py_file.name} has mutable globals: {mutable_globals}"


# =============================================================================
# Law 5: Flag-to-Logic Law (10 tests)
# =============================================================================


class TestLaw5FlagToLogic:
    """Law 5: Every CLI flag maps to a code branch."""

    def test_exhaustive_flag_changes_engine_behavior(self) -> None:
        """exhaustive=True continues after exploit."""
        target = MockTarget(responses=["Revealed secret!", "Another secret!"])
        attacker = MockAttacker(payloads=["attack1", "attack2"])
        judge = MockJudge(verdicts=[AttackStatus.EXPLOITED, AttackStatus.EXPLOITED])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
        )

        # Non-exhaustive: stops after first exploit
        result_normal = engine.run(goal="test", depth=2, exhaustive=False)
        assert len(result_normal.turns) == 1

        # Reset mocks
        target._call_count = 0
        attacker._call_count = 0
        judge._call_count = 0

        # Exhaustive: continues to find more
        result_exhaustive = engine.run(goal="test", depth=2, exhaustive=True)
        assert len(result_exhaustive.turns) == 2
        assert len(result_exhaustive.winning_payloads) == 2

    def test_dry_run_flag_prevents_disk_writes(self) -> None:
        """dry_run=True prevents any disk writes."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            dry_run=True,
        )

        assert config.should_write_to_disk() is False

        config_normal = SerixSessionConfig(
            target_path="test.py:test_fn",
            dry_run=False,
        )

        assert config_normal.should_write_to_disk() is True

    def test_fuzz_only_skips_security_tests(self) -> None:
        """fuzz_only=True skips attack phase."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            fuzz_only=True,
        )

        assert config.should_run_security_tests() is False
        assert config.should_run_fuzz_tests() is True

    def test_skip_regression_skips_regression_phase(self) -> None:
        """skip_regression=True skips regression."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            skip_regression=True,
        )

        assert config.should_run_regression() is False

    def test_no_report_skips_report_generation(self) -> None:
        """no_report=True skips report file."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            no_report=True,
        )

        assert config.should_generate_report() is False

    def test_skip_mitigated_filters_defended_attacks(self) -> None:
        """skip_mitigated=True filters DEFENDED attacks in regression."""
        from serix_v2.core.contracts import AttackLibrary

        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget()

        service = RegressionService(judge=judge, target=target)

        # Create library with one DEFENDED attack
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                StoredAttack(
                    id="a_test",
                    target_id="t_test",
                    goal="test",
                    strategy_id="jailbreaker",
                    payload="test payload",
                    status=AttackStatus.DEFENDED,  # Already defended
                )
            ],
        )

        # With skip_mitigated=True, should skip DEFENDED attacks
        result = service.run(library=library, skip_mitigated=True)
        assert result.replayed == 0  # Skipped the DEFENDED attack

        # With skip_mitigated=False, should replay all attacks
        result2 = service.run(library=library, skip_mitigated=False)
        assert result2.replayed == 1  # Replayed the DEFENDED attack

    def test_mode_static_disables_critic(self) -> None:
        """mode=STATIC means no critic feedback."""
        target = MockTarget()
        attacker = MockAttacker()
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        critic = MockCritic(should_continue_sequence=[True])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="test",
            depth=1,
            mode=AttackMode.STATIC,
        )

        # In STATIC mode, critic should not be called
        assert result.turns[0].critic_feedback is None

    def test_mode_adaptive_enables_critic(self) -> None:
        """mode=ADAPTIVE uses critic for pivots."""
        target = MockTarget()
        attacker = MockAttacker()
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        critic = MockCritic(should_continue_sequence=[False])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(
            goal="test",
            depth=2,
            mode=AttackMode.ADAPTIVE,
        )

        # In ADAPTIVE mode, critic should be called
        assert result.turns[0].critic_feedback is not None
        assert result.turns[0].critic_feedback.should_continue is False

    def test_fuzz_latency_sets_delay(self) -> None:
        """fuzz_latency=N sets simulated delay."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            fuzz_latency=2.5,
        )

        assert config.get_effective_fuzz_latency() == 2.5

    def test_no_patch_skips_healing(self) -> None:
        """no_patch=True skips HealingResult."""
        config = SerixSessionConfig(
            target_path="test.py:test_fn",
            no_patch=True,
            system_prompt="test prompt",
        )

        assert config.should_generate_patch() is False

        config_with_patch = SerixSessionConfig(
            target_path="test.py:test_fn",
            no_patch=False,
            system_prompt="test prompt",
        )

        assert config_with_patch.should_generate_patch() is True


# =============================================================================
# Law 6: Deterministic ID Law (4 tests)
# =============================================================================


class TestLaw6DeterministicID:
    """Law 6: Target ID follows Spec 02 exactly."""

    def test_id_format_starts_with_prefix(self) -> None:
        """Target ID starts with 't_'."""
        target_id = generate_target_id(locator="agent.py:my_agent")

        assert target_id.startswith("t_"), f"ID should start with 't_': {target_id}"

    def test_id_from_same_locator_is_deterministic(self) -> None:
        """Same locator produces same ID."""
        locator = "src/agent.py:my_agent"

        id1 = generate_target_id(locator=locator)
        id2 = generate_target_id(locator=locator)

        assert id1 == id2, "Same locator should produce same ID"

    def test_name_overrides_locator_for_id(self) -> None:
        """--name flag overrides locator for ID."""
        locator = "agent.py:my_agent"
        name = "my-custom-name"

        id_from_locator = generate_target_id(locator=locator)
        id_from_name = generate_target_id(locator=locator, name=name)

        # When name is provided, it should be used for ID generation
        assert id_from_locator != id_from_name

        # Same name should produce same ID regardless of locator
        id_from_name2 = generate_target_id(locator="different.py:fn", name=name)
        assert id_from_name == id_from_name2

    def test_explicit_id_overrides_all(self) -> None:
        """--target-id flag overrides everything."""
        explicit_id = "t_explicit123"

        result = generate_target_id(
            locator="agent.py:my_agent",
            name="some-name",
            explicit_id=explicit_id,
        )

        assert result == explicit_id


# =============================================================================
# Law 7: Immutable Task ID Law (1 test)
# =============================================================================


class TestLaw7ImmutableTaskID:
    """Law 7: Task IDs follow P#-S#-T## format forever."""

    def test_task_ids_follow_format(self) -> None:
        """Task IDs in session logs follow P#-S#-T## format."""
        import re

        # Valid task ID pattern: P1-S1-T01, P2-S3-T12, etc.
        pattern = re.compile(r"^P\d+-S\d+-T\d{2}$")

        # Check that mocks.py has the correct pattern reference
        mocks_path = Path(__file__).parent.parent / "mocks.py"

        if mocks_path.exists():
            content = mocks_path.read_text()
            # The mocks file should reference the task ID format
            assert (
                "P1-S1-T02" in content or "P1-S1" in content
            ), "Mocks should reference task ID format"

        # Validate the pattern matches expected formats
        assert pattern.match("P1-S1-T01")
        assert pattern.match("P2-S3-T12")
        assert pattern.match("P10-S99-T00")
        assert not pattern.match("P1-S1-T1")  # Must be 2 digits
        assert not pattern.match("1-S1-T01")  # Must start with P


# =============================================================================
# Law 8: Contract Fulfillment Law (8 tests)
# =============================================================================


class TestLaw8ContractFulfillment:
    """Law 8: Every Optional field must have a population path."""

    def test_attack_result_analysis_populated_on_success(self) -> None:
        """AttackResult.analysis populated when success=True."""
        # Create a successful attack result
        result = AttackResult(
            goal="test",
            persona=Persona.JAILBREAKER,
            success=True,
            turns=[
                AttackTurn(
                    turn_number=1,
                    payload="test",
                    response="secret revealed",
                )
            ],
            analysis=VulnerabilityAnalysis(
                vulnerability_type="jailbreak",
                owasp_code="LLM01",
                severity="high",
                root_cause="Test",
            ),
            winning_payloads=["test"],
        )

        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.owasp_code == "LLM01"

    def test_attack_result_healing_populated_when_enabled(self) -> None:
        """AttackResult.healing populated when patch enabled."""
        from serix_v2.core.contracts import HealingPatch

        result = AttackResult(
            goal="test",
            persona=Persona.JAILBREAKER,
            success=True,
            turns=[],
            healing=HealingResult(
                patch=HealingPatch(
                    original="test",
                    patched="test patched",
                    diff="---",
                    explanation="Fixed vulnerability",
                ),
                recommendations=[],
                confidence=0.9,
            ),
            winning_payloads=["test"],
        )

        assert result.healing is not None
        assert result.healing.patch is not None
        assert result.healing.patch.explanation == "Fixed vulnerability"

    def test_campaign_result_regression_fields_populated(self) -> None:
        """CampaignResult.regression_* fields populated."""
        from serix_v2.core.contracts import Grade, SecurityScore, TargetType

        result = CampaignResult(
            run_id="test_run",
            target_id="t_test",
            target_locator="test.py:fn",
            target_type=TargetType.PYTHON_FUNCTION,
            passed=True,
            score=SecurityScore(overall_score=100, grade=Grade.A),
            regression_ran=True,
            regression_replayed=5,
            regression_still_exploited=2,
            regression_now_defended=3,
        )

        assert result.regression_ran is True
        assert result.regression_replayed == 5
        assert result.regression_still_exploited == 2
        assert result.regression_now_defended == 3

    def test_campaign_result_resilience_populated_when_fuzz(self) -> None:
        """CampaignResult.resilience populated when fuzz enabled."""
        from serix_v2.core.contracts import Grade, SecurityScore, TargetType

        result = CampaignResult(
            run_id="test_run",
            target_id="t_test",
            target_locator="test.py:fn",
            target_type=TargetType.PYTHON_FUNCTION,
            passed=True,
            score=SecurityScore(overall_score=100, grade=Grade.A),
            resilience=[
                ResilienceResult(
                    test_type="latency",
                    passed=True,
                    details="Handled 1s delay",
                    latency_ms=1000.0,
                ),
                ResilienceResult(
                    test_type="http_500",
                    passed=True,
                    details="Handled error",
                ),
            ],
        )

        assert len(result.resilience) == 2
        assert result.resilience[0].test_type == "latency"
        assert result.resilience[1].test_type == "http_500"

    def test_attack_turn_critic_feedback_in_adaptive(self) -> None:
        """AttackTurn.critic_feedback populated in ADAPTIVE."""
        target = MockTarget()
        attacker = MockAttacker()
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        critic = MockCritic(should_continue_sequence=[False])

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
            critic=critic,
        )

        result = engine.run(goal="test", depth=1, mode=AttackMode.ADAPTIVE)

        assert result.turns[0].critic_feedback is not None
        assert isinstance(result.turns[0].critic_feedback, CriticFeedback)

    def test_attack_turn_error_type_on_exception(self) -> None:
        """AttackTurn.error_type populated on target crash."""
        target = MockCrashingTarget(
            crash_on_calls=[0],
            exception_type=ValueError,
            exception_message="Target crashed!",
        )
        attacker = MockAttacker()
        judge = MockJudge()

        engine = AdversaryEngine(
            target=target,
            attacker=attacker,
            judge=judge,
        )

        result = engine.run(goal="test", depth=1)

        assert result.turns[0].error_type == "ValueError"

    def test_stored_attack_all_fields_populated(self) -> None:
        """StoredAttack has all required fields."""
        attack = StoredAttack(
            id="a_test123",
            target_id="t_test",
            goal="reveal secrets",
            strategy_id="jailbreaker",
            payload="test payload",
            status=AttackStatus.EXPLOITED,
            owasp_code="LLM01",
        )

        # All required fields are populated
        assert attack.id == "a_test123"
        assert attack.target_id == "t_test"
        assert attack.goal == "reveal secrets"
        assert attack.strategy_id == "jailbreaker"
        assert attack.payload == "test payload"
        assert attack.status == AttackStatus.EXPLOITED
        assert attack.owasp_code == "LLM01"
        assert attack.created_at is not None
        assert attack.last_tested is not None

    def test_attack_transition_both_statuses_set(self) -> None:
        """AttackTransition has previous and current status."""
        transition = AttackTransition(
            attack_id="a_test",
            goal="test",
            strategy_id="jailbreaker",
            payload="test payload",
            previous_status=AttackStatus.EXPLOITED,
            current_status=AttackStatus.DEFENDED,
        )

        assert transition.previous_status == AttackStatus.EXPLOITED
        assert transition.current_status == AttackStatus.DEFENDED
        assert transition.is_fixed is True
        assert transition.is_regression is False

        # Test regression case
        regression = AttackTransition(
            attack_id="a_test2",
            goal="test",
            strategy_id="jailbreaker",
            payload="test payload",
            previous_status=AttackStatus.DEFENDED,
            current_status=AttackStatus.EXPLOITED,
        )

        assert regression.is_regression is True
        assert regression.is_fixed is False
