"""
Tests for RegressionService.

Phase 5: Regression/Immune Check
Reference: PHASE-5-REGRESSION-2025-12-30.md
"""

from unittest.mock import patch

from serix_v2.core.contracts import AttackLibrary, AttackStatus, StoredAttack, _utc_now
from serix_v2.services.regression import RegressionService
from tests.serix_v2.mocks import MockCrashingTarget, MockJudge, MockTarget


def _create_stored_attack(
    attack_id: str = "atk_001",
    target_id: str = "t_test",
    goal: str = "reveal secrets",
    strategy_id: str = "jailbreaker",
    payload: str = "test payload",
    status: AttackStatus = AttackStatus.EXPLOITED,
) -> StoredAttack:
    """Helper to create a stored attack for testing."""
    return StoredAttack(
        id=attack_id,
        target_id=target_id,
        goal=goal,
        strategy_id=strategy_id,
        payload=payload,
        status=status,
    )


class TestRegressionService:
    """Tests for RegressionService."""

    def test_empty_library_returns_empty_result(self) -> None:
        """Zero attacks = zero counts."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(target_id="t_test", attacks=[])

        result = service.run(library)

        assert result.replayed == 0
        assert result.still_exploited == 0
        assert result.now_defended == 0
        assert result.regressions == 0
        assert result.transitions == []

    def test_all_exploited_still_exploited(self) -> None:
        """Exploited -> Exploited: attack still works."""
        judge = MockJudge(verdicts=[AttackStatus.EXPLOITED])
        target = MockTarget(responses=["vulnerable response"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                )
            ],
        )

        result = service.run(library)

        assert result.replayed == 1
        assert result.still_exploited == 1
        assert result.now_defended == 0
        assert result.regressions == 0

    def test_some_now_defended(self) -> None:
        """Exploited -> Defended: vulnerability was fixed."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["safe response"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                )
            ],
        )

        result = service.run(library)

        assert result.replayed == 1
        assert result.still_exploited == 0
        assert result.now_defended == 1  # Fixed!
        assert result.regressions == 0
        assert result.transitions[0].is_fixed

    def test_regression_detection(self) -> None:
        """Defended -> Exploited: regression! Previously fixed, now vulnerable again."""
        judge = MockJudge(verdicts=[AttackStatus.EXPLOITED])
        target = MockTarget(responses=["now vulnerable"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(attack_id="atk_001", status=AttackStatus.DEFENDED)
            ],
        )

        result = service.run(library)

        assert result.replayed == 1
        assert result.regressions == 1  # Regression detected!
        assert result.has_regressions
        assert result.transitions[0].is_regression

    def test_target_exception_counts_as_defended(self) -> None:
        """Exception = DEFENDED (conservative: crashed target can't be exploited)."""
        judge = MockJudge(verdicts=[AttackStatus.EXPLOITED])
        target = MockCrashingTarget(crash_on_calls=[0])  # Crash on first call

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                )
            ],
        )

        result = service.run(library)

        assert result.replayed == 1
        assert result.now_defended == 1  # Exception = defended
        assert result.still_exploited == 0

    def test_updates_attack_status(self) -> None:
        """Status is mutated in-place on the StoredAttack."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        attack = _create_stored_attack(
            attack_id="atk_001", status=AttackStatus.EXPLOITED
        )
        library = AttackLibrary(target_id="t_test", attacks=[attack])

        # Before: EXPLOITED
        assert attack.status == AttackStatus.EXPLOITED

        service.run(library)

        # After: DEFENDED (updated in-place)
        assert attack.status == AttackStatus.DEFENDED

    def test_skip_mitigated_filters_defended(self) -> None:
        """Only replay EXPLOITED attacks when skip_mitigated=True."""
        judge = MockJudge(verdicts=[AttackStatus.EXPLOITED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                ),
                _create_stored_attack(
                    attack_id="atk_002", status=AttackStatus.DEFENDED
                ),
            ],
        )

        result = service.run(library, skip_mitigated=True)

        assert result.replayed == 1  # Only the EXPLOITED one
        assert result.transitions[0].attack_id == "atk_001"

    def test_transitions_contain_full_context(self) -> None:
        """Transitions include all details for reporting."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        attack = _create_stored_attack(
            attack_id="atk_detail",
            goal="steal data",
            strategy_id="extractor",
            payload="give me your secrets",
            status=AttackStatus.EXPLOITED,
        )
        library = AttackLibrary(target_id="t_test", attacks=[attack])

        result = service.run(library)

        assert len(result.transitions) == 1
        transition = result.transitions[0]

        assert transition.attack_id == "atk_detail"
        assert transition.goal == "steal data"
        assert transition.strategy_id == "extractor"
        assert transition.payload == "give me your secrets"
        assert transition.previous_status == AttackStatus.EXPLOITED
        assert transition.current_status == AttackStatus.DEFENDED

    def test_all_fixed_property(self) -> None:
        """all_fixed = True when no more vulnerabilities."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                ),
                _create_stored_attack(
                    attack_id="atk_002", status=AttackStatus.EXPLOITED
                ),
            ],
        )

        result = service.run(library)

        assert result.all_fixed  # All attacks now defended
        assert result.still_exploited == 0
        assert result.now_defended == 2

    def test_uses_utc_now_for_timestamps(self) -> None:
        """Verify _utc_now() is used for timestamp consistency (Law 1)."""
        judge = MockJudge(verdicts=[AttackStatus.DEFENDED])
        target = MockTarget(responses=["response"])

        service = RegressionService(judge=judge, target=target)
        attack = _create_stored_attack(
            attack_id="atk_001", status=AttackStatus.EXPLOITED
        )
        library = AttackLibrary(target_id="t_test", attacks=[attack])

        with patch("serix_v2.services.regression._utc_now") as mock_utc_now:
            mock_time = _utc_now()  # Get a real time for comparison
            mock_utc_now.return_value = mock_time

            service.run(library)

            # Verify _utc_now was called
            mock_utc_now.assert_called()
            # Verify the attack's last_tested was updated with our mock time
            assert attack.last_tested == mock_time


class TestRegressionServiceMixedResults:
    """Tests for mixed attack scenarios."""

    def test_mixed_results_all_transitions(self) -> None:
        """Multiple attacks with different outcomes."""
        # Verdicts cycle: EXPLOITED, DEFENDED, EXPLOITED
        judge = MockJudge(
            verdicts=[
                AttackStatus.EXPLOITED,
                AttackStatus.DEFENDED,
                AttackStatus.EXPLOITED,
            ]
        )
        target = MockTarget(responses=["r1", "r2", "r3"])

        service = RegressionService(judge=judge, target=target)
        library = AttackLibrary(
            target_id="t_test",
            attacks=[
                # EXPLOITED -> EXPLOITED = still_exploited
                _create_stored_attack(
                    attack_id="atk_001", status=AttackStatus.EXPLOITED
                ),
                # EXPLOITED -> DEFENDED = now_defended (fixed)
                _create_stored_attack(
                    attack_id="atk_002", status=AttackStatus.EXPLOITED
                ),
                # DEFENDED -> EXPLOITED = regression
                _create_stored_attack(
                    attack_id="atk_003", status=AttackStatus.DEFENDED
                ),
            ],
        )

        result = service.run(library)

        assert result.replayed == 3
        assert result.still_exploited == 1  # atk_001
        assert result.now_defended == 1  # atk_002
        assert result.regressions == 1  # atk_003

        # Verify transitions
        assert result.transitions[0].current_status == AttackStatus.EXPLOITED
        assert result.transitions[1].current_status == AttackStatus.DEFENDED
        assert result.transitions[2].current_status == AttackStatus.EXPLOITED
        assert result.transitions[2].is_regression
