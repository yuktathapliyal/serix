#!/usr/bin/env python3
"""
E2E Verification Script for Phase 9B: Config File Loading

Run with: uv run python tests/serix_v2/config/e2e_verify.py
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path for direct execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src"))

from serix_v2.config import (
    CLIOverrides,
    find_config_file,
    load_toml_config,
    resolve_config,
)
from serix_v2.core import constants


def test_1_find_serix_toml():
    """Test 1: find_config_file() finds serix.toml"""
    print("\n" + "=" * 60)
    print("TEST 1: find_config_file() finds serix.toml")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create nested directory structure
        project = Path(tmpdir) / "my-project"
        src = project / "src" / "module"
        src.mkdir(parents=True)

        # Create serix.toml at project root
        config_file = project / "serix.toml"
        config_file.write_text('[target]\npath = "agent.py:main"\n')

        # Search from nested directory
        found = find_config_file(src)

        print(f"  Created config at: {config_file}")
        print(f"  Searched from:     {src}")
        print(f"  Found:             {found}")

        # Use .resolve() to handle macOS /var -> /private/var symlinks
        assert (
            found.resolve() == config_file.resolve()
        ), f"Expected {config_file}, got {found}"
        print("  ✅ PASSED")


def test_2_load_serix_toml():
    """Test 2: load_toml_config() parses serix.toml correctly"""
    print("\n" + "=" * 60)
    print("TEST 2: load_toml_config() parses serix.toml")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
verbose = true
exhaustive = false

[target]
path = "my_agent.py:agent_fn"
name = "my-cool-agent"

[attack]
goal = "extract API keys"
depth = 10
scenarios = ["jailbreak", "extraction"]

[models]
attacker = "gpt-4o"
judge = "gpt-4o-mini"

[fuzz]
enabled = true
latency = 2.5
"""
        )

        config, config_dir = load_toml_config(config_file)

        print(f"  Config file: {config_file}")
        print(f"  Config dir:  {config_dir}")
        print("  Parsed values:")
        print(f"    target.path:      {config.target.path}")
        print(f"    target.name:      {config.target.name}")
        print(f"    attack.goal:      {config.attack.goal}")
        print(f"    attack.depth:     {config.attack.depth}")
        print(f"    attack.scenarios: {config.attack.scenarios}")
        print(f"    models.attacker:  {config.models.attacker}")
        print(f"    fuzz.latency:     {config.fuzz.latency}")
        print(f"    verbose:          {config.verbose}")

        assert config.target.path == "my_agent.py:agent_fn"
        assert config.target.name == "my-cool-agent"
        assert config.attack.goal == "extract API keys"
        assert config.attack.depth == 10
        assert config.models.attacker == "gpt-4o"
        assert config.fuzz.latency == 2.5
        assert config.verbose is True
        print("  ✅ PASSED")


def test_3_load_pyproject_toml():
    """Test 3: load_toml_config() extracts [tool.serix] from pyproject.toml"""
    print("\n" + "=" * 60)
    print("TEST 3: load_toml_config() extracts [tool.serix]")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "pyproject.toml"
        config_file.write_text(
            """
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-project"
version = "1.0.0"

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.serix]
verbose = true

[tool.serix.target]
path = "src/agent.py:run"

[tool.serix.attack]
depth = 15
"""
        )

        config, config_dir = load_toml_config(config_file)

        print(f"  Config file: {config_file}")
        print("  Extracted [tool.serix] section:")
        print(f"    target.path:  {config.target.path}")
        print(f"    attack.depth: {config.attack.depth}")
        print(f"    verbose:      {config.verbose}")

        assert config.target.path == "src/agent.py:run"
        assert config.attack.depth == 15
        assert config.verbose is True
        print("  ✅ PASSED")


def test_4_priority_cli_over_toml():
    """Test 4: CLI overrides TOML values"""
    print("\n" + "=" * 60)
    print("TEST 4: Priority: CLI > TOML")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
[target]
path = "toml-agent.py:fn"

[attack]
depth = 5
"""
        )

        toml_config, config_dir = load_toml_config(config_file)

        # CLI overrides
        cli = CLIOverrides(
            target_path="cli-agent.py:main",
            depth=20,
        )

        session = resolve_config(cli, toml_config, config_dir)

        print("  TOML target.path: toml-agent.py:fn")
        print("  CLI target_path:  cli-agent.py:main")
        print(f"  Result:           {session.target_path}")
        print()
        print("  TOML depth: 5")
        print("  CLI depth:  20")
        print(f"  Result:     {session.depth}")

        assert session.target_path == "cli-agent.py:main", "CLI should override TOML"
        assert session.depth == 20, "CLI should override TOML"
        print("  ✅ PASSED")


def test_5_priority_env_over_toml():
    """Test 5: Environment variables override TOML values"""
    print("\n" + "=" * 60)
    print("TEST 5: Priority: ENV > TOML")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[attack]
depth = 5
"""
        )

        # Set env var
        os.environ["SERIX_DEPTH"] = "15"

        try:
            toml_config, config_dir = load_toml_config(config_file)
            cli = CLIOverrides(target_path="agent.py:fn")  # Only provide required field
            session = resolve_config(cli, toml_config, config_dir)

            print("  TOML depth:        5")
            print("  SERIX_DEPTH env:   15")
            print(f"  Result:            {session.depth}")

            assert session.depth == 15, "ENV should override TOML"
            print("  ✅ PASSED")
        finally:
            del os.environ["SERIX_DEPTH"]


def test_6_goals_file_reading():
    """Test 6: Goals file with comments and blank lines"""
    print("\n" + "=" * 60)
    print("TEST 6: goals_file reading (comments, blanks stripped)")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create goals file
        goals_file = Path(tmpdir) / "goals.txt"
        goals_file.write_text(
            """# Security testing goals
reveal API keys

# Another comment
bypass authentication

extract user data
"""
        )

        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[attack]
goals_file = "goals.txt"
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        cli = CLIOverrides(target_path="agent.py:fn")
        session = resolve_config(cli, toml_config, config_dir)

        print("  Goals file content:")
        print("    # Security testing goals")
        print("    reveal API keys")
        print("    <blank line>")
        print("    # Another comment")
        print("    bypass authentication")
        print("    <blank line>")
        print("    extract user data")
        print()
        print(f"  Parsed goals: {session.goals}")

        assert session.goals == [
            "reveal API keys",
            "bypass authentication",
            "extract user data",
        ]
        assert len(session.goals) == 3, "Comments and blanks should be stripped"
        print("  ✅ PASSED")


def test_7_path_relativity():
    """Test 7: Relative paths resolve against config directory"""
    print("\n" + "=" * 60)
    print("TEST 7: Path relativity (relative to config dir)")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create config in subdirectory
        config_dir = Path(tmpdir) / "config"
        config_dir.mkdir()

        # Create goals file next to config
        goals_file = config_dir / "goals.txt"
        goals_file.write_text("test goal\n")

        config_file = config_dir / "serix.toml"
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[attack]
goals_file = "goals.txt"
"""
        )

        # Simulate running from project root (different from config dir)
        original_cwd = os.getcwd()
        os.chdir(tmpdir)  # CWD is now project root

        try:
            toml_config, cfg_dir = load_toml_config(config_file)
            cli = CLIOverrides(target_path="agent.py:fn")
            session = resolve_config(cli, toml_config, cfg_dir)

            print(f"  Config file at:    {config_file}")
            print("  goals_file value:  'goals.txt' (relative)")
            print(f"  CWD:               {tmpdir}")
            print(f"  Config dir:        {cfg_dir}")
            print(f"  Resolved to:       {cfg_dir / 'goals.txt'}")
            print(f"  Parsed goals:      {session.goals}")

            assert session.goals == ["test goal"]
            print("  ✅ PASSED (found file relative to config, not CWD)")
        finally:
            os.chdir(original_cwd)


def test_8_backward_compat():
    """Test 8: Backward compatibility fields work"""
    print("\n" + "=" * 60)
    print("TEST 8: Backward compatibility fields")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
[target]
script = "old_agent.py:fn"   # Deprecated, use 'path'

[attack]
max_attempts = 12            # Deprecated, use 'depth'
report = "old-report.html"   # Deprecated, moved to [output]

[fuzz]
mutation_probability = 0.5   # Deprecated, use 'probability'
json_corruption = true       # Deprecated, use 'json'
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        cli = CLIOverrides()  # No overrides - use all deprecated fields
        session = resolve_config(cli, toml_config, config_dir)

        print("  Deprecated field mappings:")
        print(f"    script -> target_path:            {session.target_path}")
        print(f"    max_attempts -> depth:            {session.depth}")
        print(f"    [attack].report -> report_path:   {session.report_path}")
        print(f"    mutation_probability -> fuzz_prob: {session.fuzz_probability}")
        print(f"    json_corruption -> fuzz_json:     {session.fuzz_json}")

        assert session.target_path == "old_agent.py:fn"
        assert session.depth == 12
        assert session.report_path == "old-report.html"
        assert session.fuzz_probability == 0.5
        assert session.fuzz_json is True
        print("  ✅ PASSED")


def test_9_regression_enabled_inversion():
    """Test 9: [regression].enabled inverts to skip_regression"""
    print("\n" + "=" * 60)
    print("TEST 9: [regression].enabled inversion")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Test enabled=true -> skip_regression=False
        config_file = Path(tmpdir) / "serix.toml"
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[regression]
enabled = true
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        cli = CLIOverrides(target_path="agent.py:fn")
        session = resolve_config(cli, toml_config, config_dir)

        print("  [regression].enabled = true")
        print(f"  skip_regression = {session.skip_regression}")
        assert session.skip_regression is False, "enabled=true should mean skip=False"

        # Test enabled=false -> skip_regression=True
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[regression]
enabled = false
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        session = resolve_config(cli, toml_config, config_dir)

        print("  [regression].enabled = false")
        print(f"  skip_regression = {session.skip_regression}")
        assert session.skip_regression is True, "enabled=false should mean skip=True"
        print("  ✅ PASSED")


def test_10_fuzz_latency_coercion():
    """Test 10: fuzz.latency bool/float coercion"""
    print("\n" + "=" * 60)
    print("TEST 10: fuzz.latency type coercion")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "serix.toml"

        # Test latency = true -> uses default
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[fuzz]
latency = true
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        cli = CLIOverrides(target_path="agent.py:fn")
        session = resolve_config(cli, toml_config, config_dir)

        print("  latency = true")
        print(
            f"  fuzz_latency = {session.fuzz_latency} (default: {constants.DEFAULT_FUZZ_LATENCY})"
        )
        assert session.fuzz_latency == constants.DEFAULT_FUZZ_LATENCY

        # Test latency = 3.5 -> uses value directly
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[fuzz]
latency = 3.5
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        session = resolve_config(cli, toml_config, config_dir)

        print("  latency = 3.5")
        print(f"  fuzz_latency = {session.fuzz_latency}")
        assert session.fuzz_latency == 3.5

        # Test latency = false -> None
        config_file.write_text(
            """
[target]
path = "agent.py:fn"

[fuzz]
latency = false
"""
        )

        toml_config, config_dir = load_toml_config(config_file)
        session = resolve_config(cli, toml_config, config_dir)

        print("  latency = false")
        print(f"  fuzz_latency = {session.fuzz_latency}")
        assert session.fuzz_latency is None
        print("  ✅ PASSED")


def main():
    """Run all E2E verification tests."""
    print("\n" + "=" * 60)
    print("PHASE 9B E2E VERIFICATION")
    print("Config File Loading")
    print("=" * 60)

    tests = [
        test_1_find_serix_toml,
        test_2_load_serix_toml,
        test_3_load_pyproject_toml,
        test_4_priority_cli_over_toml,
        test_5_priority_env_over_toml,
        test_6_goals_file_reading,
        test_7_path_relativity,
        test_8_backward_compat,
        test_9_regression_enabled_inversion,
        test_10_fuzz_latency_coercion,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ❌ FAILED: {e}")

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{len(tests)} tests passed")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)
    print("\n✅ ALL E2E TESTS PASSED!")


if __name__ == "__main__":
    main()
