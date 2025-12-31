"""
Serix v2 - Mock Implementations for Testing

P1-S1-T02: Mock implementations of all protocols for testing the engine
without real LLM calls.

These mocks are controllable via constructor parameters, allowing tests
to script exact behavior sequences.
"""

from serix_v2.core.contracts import (
    AttackLibrary,
    AttackStatus,
    AttackTurn,
    CampaignResult,
    CriticFeedback,
    HealingPatch,
    HealingResult,
    JudgeVerdict,
    Severity,
    StoredAttack,
    ToolRecommendation,
    VulnerabilityAnalysis,
)


class MockTarget:
    """
    Mock implementation of the Target protocol.

    Returns configurable responses in sequence.
    """

    def __init__(
        self,
        target_id: str = "t_mock1234",
        locator: str = "mock_target.py:mock_fn",
        responses: list[str] | None = None,
    ):
        self._id = target_id
        self._locator = locator
        self._responses = responses or ["Mock response"]
        self._call_count = 0

    @property
    def id(self) -> str:
        return self._id

    @property
    def locator(self) -> str:
        return self._locator

    def __call__(self, message: str) -> str:
        """Return the next response in sequence, cycling if needed."""
        response = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1
        return response


class MockAttacker:
    """
    Mock implementation of the Attacker protocol.

    Returns configurable payloads in sequence.
    """

    def __init__(self, payloads: list[str] | None = None):
        self._payloads = payloads or ["Mock attack payload"]
        self._call_count = 0

    def generate(self, goal: str, history: list[AttackTurn]) -> str:
        """Return the next payload in sequence, cycling if needed."""
        payload = self._payloads[self._call_count % len(self._payloads)]
        self._call_count += 1
        return payload


class MockJudge:
    """
    Mock implementation of the Judge protocol.

    Returns configurable verdicts (EXPLOITED/DEFENDED) in sequence.
    This is what determines if an attack succeeded - NOT the Critic.
    """

    def __init__(self, verdicts: list[AttackStatus] | None = None):
        self._verdicts = verdicts or [AttackStatus.DEFENDED]
        self._call_count = 0

    def evaluate(self, goal: str, payload: str, response: str) -> JudgeVerdict:
        """Return the next verdict in sequence, cycling if needed."""
        verdict = self._verdicts[self._call_count % len(self._verdicts)]
        self._call_count += 1
        return JudgeVerdict(
            verdict=verdict,
            confidence=1.0,
            reasoning=f"Mock verdict: {verdict.value}",
        )


class MockCritic:
    """
    Mock implementation of the Critic protocol.

    Returns configurable should_continue values in sequence.
    The Critic advises on strategy, NOT on whether an attack succeeded.
    """

    def __init__(self, should_continue_sequence: list[bool] | None = None):
        self._should_continue = should_continue_sequence or [True]
        self._call_count = 0

    def evaluate(self, goal: str, turns: list[AttackTurn]) -> CriticFeedback:
        """Return the next feedback in sequence, cycling if needed."""
        should_continue = self._should_continue[
            self._call_count % len(self._should_continue)
        ]
        self._call_count += 1
        return CriticFeedback(
            should_continue=should_continue,
            confidence=0.8,
            reasoning=f"Mock critic: should_continue={should_continue}",
            suggested_pivot="Try a different approach" if should_continue else None,
        )


class MockCrashingTarget:
    """
    Mock target that throws exceptions on specified calls.

    FH-01: Used to test engine error handling.
    """

    def __init__(
        self,
        target_id: str = "t_crash1234",
        locator: str = "crash_target.py:crash_fn",
        crash_on_calls: list[int] | None = None,
        exception_type: type[Exception] = ValueError,
        exception_message: str = "Target crashed!",
        fallback_response: str = "Normal response",
    ):
        self._id = target_id
        self._locator = locator
        self._crash_on_calls = crash_on_calls or [0]  # Crash on first call by default
        self._exception_type = exception_type
        self._exception_message = exception_message
        self._fallback_response = fallback_response
        self._call_count = 0

    @property
    def id(self) -> str:
        return self._id

    @property
    def locator(self) -> str:
        return self._locator

    def __call__(self, message: str) -> str:
        """Throw exception on specified calls, return fallback otherwise."""
        current_call = self._call_count
        self._call_count += 1

        if current_call in self._crash_on_calls:
            raise self._exception_type(self._exception_message)

        return self._fallback_response


class MockLLMProvider:
    """
    Mock implementation of the LLMProvider protocol.

    Returns configurable responses in sequence.
    """

    def __init__(self, responses: list[str] | None = None):
        self._responses = responses or [
            '{"verdict": "defended", "confidence": 0.9, "reasoning": "Mock"}'
        ]
        self._call_count = 0

    def complete(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float = 0.7,
    ) -> str:
        """Return the next response in sequence, cycling if needed."""
        response = self._responses[self._call_count % len(self._responses)]
        self._call_count += 1
        return response


class MockAttackStore:
    """
    Mock implementation of the AttackStore protocol.

    Stores attacks in memory for testing.
    """

    def __init__(self) -> None:
        self._libraries: dict[str, AttackLibrary] = {}
        self._add_attack_calls: list[StoredAttack] = []

    def load(self, target_id: str) -> AttackLibrary:
        """Load attack library for a target."""
        if target_id not in self._libraries:
            self._libraries[target_id] = AttackLibrary(target_id=target_id, attacks=[])
        return self._libraries[target_id]

    def save(self, library: AttackLibrary) -> None:
        """Save attack library."""
        self._libraries[library.target_id] = library

    def add_attack(self, attack: StoredAttack) -> None:
        """Add attack to library."""
        self._add_attack_calls.append(attack)
        library = self.load(attack.target_id)
        library.attacks.append(attack)
        self.save(library)


class MockCampaignStore:
    """
    Mock implementation of the CampaignStore protocol.

    Stores campaign results in memory for testing.
    """

    def __init__(self) -> None:
        self._results: dict[str, CampaignResult] = {}
        self._save_calls: list[CampaignResult] = []

    def save(self, result: CampaignResult) -> str:
        """Save campaign result."""
        self._save_calls.append(result)
        key = f"{result.target_id}:{result.run_id}"
        self._results[key] = result
        return result.run_id

    def load(self, target_id: str, run_id: str) -> CampaignResult:
        """Load campaign result."""
        key = f"{target_id}:{run_id}"
        if key not in self._results:
            raise FileNotFoundError(f"Campaign result not found: {target_id}/{run_id}")
        return self._results[key]


class MockAnalyzer:
    """
    Mock implementation of the Analyzer protocol.

    Returns configurable vulnerability analysis.
    """

    def __init__(
        self,
        vulnerability_type: str = "jailbreak",
        owasp_code: str = "LLM01",
        severity: Severity = Severity.HIGH,
        root_cause: str = "Mock root cause",
    ):
        self._vulnerability_type = vulnerability_type
        self._owasp_code = owasp_code
        self._severity = severity
        self._root_cause = root_cause
        self._call_count = 0

    def analyze(self, goal: str, payload: str, response: str) -> VulnerabilityAnalysis:
        """Return configured vulnerability analysis."""
        self._call_count += 1
        return VulnerabilityAnalysis(
            vulnerability_type=self._vulnerability_type,
            owasp_code=self._owasp_code,
            severity=self._severity,
            root_cause=self._root_cause,
        )


class MockPatcher:
    """
    Mock implementation of the Patcher protocol.

    Returns configurable healing results.
    """

    def __init__(
        self,
        patched_prompt: str | None = None,
        explanation: str = "Mock patch applied",
        confidence: float = 0.85,
        recommendations: list[ToolRecommendation] | None = None,
    ):
        self._patched_prompt = patched_prompt
        self._explanation = explanation
        self._confidence = confidence
        self._recommendations = recommendations or [
            ToolRecommendation(
                recommendation="Mock recommendation",
                severity="recommended",
                owasp_code="LLM01",
            )
        ]
        self._call_count = 0

    def heal(
        self,
        original_prompt: str,
        attacks: list[tuple[str, str]],
        analysis: VulnerabilityAnalysis,
    ) -> HealingResult:
        """Return configured healing result."""
        self._call_count += 1

        # If patched_prompt is provided, create a patch
        patch = None
        if self._patched_prompt is not None or original_prompt:
            patched = (
                self._patched_prompt or f"{original_prompt}\n\n[Security clause added]"
            )
            patch = HealingPatch(
                original=original_prompt,
                patched=patched,
                diff=f"--- original\n+++ patched\n-{original_prompt[:50]}...\n+{patched[:50]}...",
                explanation=self._explanation,
            )

        return HealingResult(
            patch=patch,
            recommendations=self._recommendations,
            confidence=self._confidence,
        )
