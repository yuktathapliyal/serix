"""Shared fixtures for behavioral contract tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from serix.core.run_config import TestRunConfig

if TYPE_CHECKING:
    pass


@pytest.fixture
def default_config() -> TestRunConfig:
    """TestRunConfig with all defaults."""
    return TestRunConfig()


@pytest.fixture
def dry_run_config() -> TestRunConfig:
    """TestRunConfig with dry_run=True."""
    return TestRunConfig(dry_run=True)


@pytest.fixture
def fuzz_only_config() -> TestRunConfig:
    """TestRunConfig with fuzz_only=True."""
    return TestRunConfig(fuzz_only=True, fuzz_enabled=True)


@pytest.fixture
def no_report_config() -> TestRunConfig:
    """TestRunConfig with no_report=True."""
    return TestRunConfig(no_report=True, report_path=Path("report.html"))


@pytest.fixture
def no_patch_config() -> TestRunConfig:
    """TestRunConfig with no_patch=True."""
    return TestRunConfig(no_patch=True)


@pytest.fixture
def skip_regression_config() -> TestRunConfig:
    """TestRunConfig with skip_regression=True."""
    return TestRunConfig(skip_regression=True)


@pytest.fixture
def mock_target() -> MagicMock:
    """Mock target for workflow tests."""
    target = MagicMock()
    target.invoke.return_value = "I cannot help with that."
    return target
