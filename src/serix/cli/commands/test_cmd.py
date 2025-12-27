"""Test command implementation.

Provides the `serix test` command for security testing.
Wires together all services and runs the test workflow.

Features:
- Storage persistence to .serix/
- Regression check (immune check) before attacks
- Config cascade loading
- Healing generation for successful attacks
- HTML and JSON report generation
- GitHub Actions output
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ...adapters.openai import OpenAIAdapter
from ...core.constants import (
    DEFAULT_ATTACKER_MODEL,
    DEFAULT_DEPTH,
    DEFAULT_GOAL,
    DEFAULT_JUDGE_MODEL,
    DEFAULT_PATCHER_MODEL,
    EXIT_ERROR,
)
from ...core.errors import SerixError
from ...core.types import TargetMetadata
from ...services.attack import AttackService
from ...services.config import ConfigService
from ...services.healing import HealingService
from ...services.judge import JudgeService
from ...services.regression import RegressionService
from ...services.report import ReportService
from ...services.storage import StorageService
from ...services.target import TargetService
from ...workflows.test_workflow import TestWorkflow
from ..output.github import GithubRenderer, is_github_actions
from ..output.static import StaticRenderer

# Version for stored attacks
SERIX_VERSION = "0.3.0"


def test_command(
    target: Annotated[
        str,
        typer.Argument(help="Target to test (path/to/file.py:function or http://...)"),
    ],
    goal: Annotated[
        list[str],
        typer.Option(
            "--goal",
            "-g",
            help="Attack goal(s). Can be specified multiple times.",
        ),
    ] = [],
    scenarios: Annotated[
        list[str],
        typer.Option(
            "--scenarios",
            "-s",
            help="Attack scenarios (jailbreak, extraction, confusion, manipulation, all)",
        ),
    ] = ["all"],
    depth: Annotated[
        int,
        typer.Option(
            "--depth",
            "-d",
            help="Maximum attack turns per persona",
        ),
    ] = DEFAULT_DEPTH,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output",
        ),
    ] = False,
    # Sprint 2 additions
    name: Annotated[
        str | None,
        typer.Option(
            "--name",
            "-n",
            help="Target name for stable identity (e.g., 'my-agent')",
        ),
    ] = None,
    target_id_opt: Annotated[
        str | None,
        typer.Option(
            "--target-id",
            help="Explicit target ID (overrides --name)",
        ),
    ] = None,
    skip_regression: Annotated[
        bool,
        typer.Option(
            "--skip-regression",
            help="Skip immune check (regression testing)",
        ),
    ] = False,
    skip_mitigated: Annotated[
        bool,
        typer.Option(
            "--skip-mitigated",
            help="Skip attacks already marked as defended",
        ),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to config file",
        ),
    ] = None,
    # Sprint 3 additions
    report: Annotated[
        Path | None,
        typer.Option(
            "--report",
            "-r",
            help="Custom HTML report path (default: serix-report.html)",
        ),
    ] = None,
    no_report: Annotated[
        bool,
        typer.Option(
            "--no-report",
            help="Skip report generation",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Run without writing to disk (reports, storage)",
        ),
    ] = False,
    no_patch: Annotated[
        bool,
        typer.Option(
            "--no-patch",
            help="Skip patch generation",
        ),
    ] = False,
    github: Annotated[
        bool,
        typer.Option(
            "--github",
            help="Enable GitHub Actions output (implies non-interactive)",
        ),
    ] = False,
    # Phase 2 additions: Model flags
    attacker_model: Annotated[
        str,
        typer.Option(
            "--attacker-model",
            help="Model for attack personas (default: gpt-4o-mini)",
        ),
    ] = DEFAULT_ATTACKER_MODEL,
    judge_model: Annotated[
        str,
        typer.Option(
            "--judge-model",
            help="Model for impartial judge (default: gpt-4o)",
        ),
    ] = DEFAULT_JUDGE_MODEL,
    patcher_model: Annotated[
        str,
        typer.Option(
            "--patcher-model",
            help="Model for healing patches (default: gpt-4o)",
        ),
    ] = DEFAULT_PATCHER_MODEL,
    # Phase 2: Attack mode
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            "-m",
            help="Attack mode: 'static' (fixed prompts) or 'adaptive' (LLM-generated)",
        ),
    ] = "adaptive",
    # Phase 2: Goals file
    goals_file: Annotated[
        Path | None,
        typer.Option(
            "--goals-file",
            help="File containing goals (one per line, # for comments)",
        ),
    ] = None,
    # Phase 2: Fuzzing
    fuzz: Annotated[
        bool,
        typer.Option(
            "--fuzz",
            help="Enable fuzzing mutations (latency, errors, JSON corruption)",
        ),
    ] = False,
    # Phase 2: Exhaustive mode
    exhaustive: Annotated[
        bool,
        typer.Option(
            "--exhaustive",
            help="Run all attack variations (slower, more thorough)",
        ),
    ] = False,
    # Phase 2: HTTP target options
    input_field: Annotated[
        str,
        typer.Option(
            "--input-field",
            help="JSON field name for input in HTTP requests (default: message)",
        ),
    ] = "message",
    output_field: Annotated[
        str,
        typer.Option(
            "--output-field",
            help="JSON field name for output in HTTP responses (default: response)",
        ),
    ] = "response",
    headers: Annotated[
        list[str],
        typer.Option(
            "--headers",
            "-H",
            help="HTTP headers (format: 'Key: Value'). Can be specified multiple times.",
        ),
    ] = [],
) -> None:
    """Test an AI agent for security vulnerabilities.

    Examples:
        serix test my_agent.py:agent --goal "reveal secrets"
        serix test http://localhost:8000/chat -g "bypass safety" -s jailbreak
        serix test my_agent.py:agent --name my-agent  # Stable identity
        serix test my_agent.py:agent --skip-regression  # Skip immune check
        serix test my_agent.py:agent --report custom.html  # Custom report path
        serix test my_agent.py:agent --github  # GitHub Actions mode
        serix test my_agent.py:agent --dry-run  # No disk writes
    """
    from ...fuzz.personas import (
        ConfuserPersona,
        ExtractorPersona,
        JailbreakerPersona,
        ManipulatorPersona,
    )

    try:
        # Auto-detect GitHub Actions environment
        use_github = github or is_github_actions()

        # Load config with cascade (CLI > Env > File > Defaults)
        config_service = ConfigService(config_path=config)
        _ = config_service.load(
            cli_args={
                "goal": goal if goal else None,
                "depth": depth,
                "scenarios": scenarios,
                "name": name,
                "target_id": target_id_opt,
                "skip_regression": skip_regression,
                "skip_mitigated": skip_mitigated,
                "verbose": verbose,
                # Sprint 3 additions
                "report": str(report) if report else None,
                "no_report": no_report,
                "dry_run": dry_run,
                "no_patch": no_patch,
                "github": use_github,
            }
        )

        # Default goal if none provided
        goals = list(goal) if goal else []

        # Parse goals from file if provided
        if goals_file:
            try:
                with open(goals_file) as f:
                    for line in f:
                        line = line.strip()
                        # Skip empty lines and comments
                        if line and not line.startswith("#"):
                            goals.append(line)
            except FileNotFoundError:
                typer.echo(f"Error: Goals file not found: {goals_file}", err=True)
                raise typer.Exit(code=EXIT_ERROR)

        # Use default goal if none provided from CLI or file
        if not goals:
            goals = [DEFAULT_GOAL]

        # Generate target ID (explicit > name slug > hash)
        target_id = target_id_opt or TargetService.generate_target_id(target, name)

        # Initialize storage
        storage = StorageService()
        storage.initialize()

        # Save target metadata
        target_type = (
            "http" if target.startswith(("http://", "https://")) else "python:function"
        )
        metadata = TargetMetadata(
            target_id=target_id,
            target_type=target_type,
            locator=target,
            name=name,
        )
        storage.save_metadata(metadata)

        # Register alias if name provided
        if name:
            storage.register_alias(name, target_id)

        # Initialize OpenAI adapter with rate limiting
        adapter = OpenAIAdapter()
        raw_client = adapter.raw_client

        # Build personas based on scenarios
        all_personas = {
            "jailbreak": JailbreakerPersona(raw_client),
            "extraction": ExtractorPersona(raw_client),
            "confusion": ConfuserPersona(raw_client),
            "manipulation": ManipulatorPersona(raw_client),
        }

        if "all" in scenarios:
            personas = list(all_personas.values())
        else:
            personas = [all_personas[s] for s in scenarios if s in all_personas]

        if not personas:
            # Fallback to jailbreaker
            personas = [JailbreakerPersona(raw_client)]

        # Load target
        target_obj = TargetService.load(target, verbose=verbose)

        # Choose renderer based on --github flag
        # Use union type for mypy: both implement EventListener protocol
        renderer: GithubRenderer | StaticRenderer
        if use_github:
            renderer = GithubRenderer()
        else:
            renderer = StaticRenderer()

        # Create services
        judge_service = JudgeService(adapter, model=judge_model)
        attack_service = AttackService(
            judge_service=judge_service,
            max_turns=depth,
            event_listener=renderer,
            verbose=verbose,
        )

        # Create regression service (for immune check)
        regression_service = None
        if not skip_regression and not dry_run:
            regression_service = RegressionService(
                storage=storage,
                judge=judge_service,
                event_listener=renderer,
            )

        # Sprint 3: Create healing service
        healing_service = None
        if not no_patch and not dry_run:
            healing_service = HealingService(
                llm_client=raw_client,
                event_listener=renderer,
            )

        # Sprint 3: Create report service
        report_service = None
        if not no_report:
            report_service = ReportService(
                storage_service=storage,
                storage_base=storage.base_dir,
                dry_run=dry_run,
            )

        # Create and run workflow
        workflow = TestWorkflow(
            attack_service=attack_service,
            personas=personas,
            event_listener=renderer,
            storage_service=storage if not dry_run else None,
            regression_service=regression_service,
            healing_service=healing_service,
            report_service=report_service,
        )

        result = workflow.run(
            target_obj,
            goals,
            target_id=target_id,
            run_regression=not skip_regression and not dry_run,
            skip_mitigated=skip_mitigated,
            serix_version=SERIX_VERSION,
            # Sprint 3 additions
            generate_healing=not no_patch and not dry_run,
            generate_reports=not no_report and not dry_run,
            report_path=report,
            depth=depth,
            mode="adaptive",
        )

        # Exit with appropriate code
        raise typer.Exit(code=result.exit_code)

    except SerixError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=e.exit_code)
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"Unexpected error: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(code=EXIT_ERROR)
