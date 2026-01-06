"""
Serix v2 - Test Command

Run adversarial security campaigns against targets.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
Business logic is in TestWorkflow (no CLI deps).

Guardrails:
- 1: Alias First - _resolve_alias() before resolve_config()
- 2: Strict Signatures - resolve_target(session_config) single param
- 4: IO Delegation - Pass paths to CLIOverrides, resolver reads files
- 5: Display Isolation - All rich code in renderers/console.py
"""

import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from serix_v2.cli.renderers.console import (
    render_api_key_missing,
    render_campaign_header,
    render_campaign_result,
    render_healing_patch,
    render_no_goal_error,
)
from serix_v2.cli.renderers.github import write_github_annotations, write_step_summary
from serix_v2.config import CLIOverrides, load_toml_config, resolve_config
from serix_v2.core.contracts import TargetIndex
from serix_v2.providers import LiteLLMProvider
from serix_v2.report import HTMLReportGenerator, write_html_report
from serix_v2.storage import FileAttackStore, FileCampaignStore
from serix_v2.targets import resolve_target
from serix_v2.workflows import TestWorkflow

console = Console()


def _resolve_alias(target_arg: str | None) -> str | None:
    """
    Guardrail 1: Check if target is an alias, return locator if so.

    Called BEFORE resolve_config() to expand aliases to real paths.
    """
    if target_arg is None:
        return None

    index_path = Path(".serix/index.json")
    if index_path.exists():
        try:
            index = TargetIndex.model_validate_json(index_path.read_text())
            if target_arg in index.aliases:
                return index.aliases[target_arg]
        except Exception:
            pass

    return target_arg


def _check_api_key() -> bool:
    """Check if any LLM API key is configured."""
    return any(
        [
            os.environ.get("OPENAI_API_KEY"),
            os.environ.get("ANTHROPIC_API_KEY"),
            os.environ.get("LITELLM_API_KEY"),
        ]
    )


def _help_all_callback(ctx: typer.Context, value: bool) -> None:
    """Callback for --help-all flag to trigger extended help display."""
    if value:
        # Get help text via Click's help mechanism
        # The format_help method in TestHelpCommand will detect --help-all in sys.argv
        import click

        click.echo(ctx.get_help())
        raise typer.Exit()


def test(
    # Positional target argument
    target: Annotated[
        str | None,
        typer.Argument(help="Target to test (file.py:function or http://...)"),
    ] = None,
    # Attack goals
    goal: Annotated[
        list[str] | None,
        typer.Option("--goal", "-g", help="Objective of the security audit"),
    ] = None,
    goals_file: Annotated[
        Path | None,
        typer.Option("--goals-file", help="File with goals (one per line)"),
    ] = None,
    # Attack configuration
    mode: Annotated[
        str | None,
        typer.Option(
            "--mode", "-m", help="Attack mode: static or adaptive (default: adaptive)"
        ),
    ] = None,
    scenarios: Annotated[
        list[str] | None,
        typer.Option(
            "--scenarios", "-s", help="Threat personas to test (default: all)"
        ),
    ] = None,
    depth: Annotated[
        int | None,
        typer.Option(
            "--depth",
            "-d",
            help="Total audit depth (max turns or templates) (default: 5)",
        ),
    ] = None,
    exhaustive: Annotated[
        bool,
        typer.Option("--exhaustive", help="Continue after first exploit"),
    ] = False,
    # Model configuration
    attacker_model: Annotated[
        str | None,
        typer.Option(
            "--attacker-model",
            help="Model for attack generation (default: gpt-4o-mini)",
        ),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model", help="Model for attack evaluation (default: gpt-4o)"
        ),
    ] = None,
    critic_model: Annotated[
        str | None,
        typer.Option(
            "--critic-model", help="Model for per-turn feedback (default: gpt-4o-mini)"
        ),
    ] = None,
    patcher_model: Annotated[
        str | None,
        typer.Option(
            "--patcher-model", help="Model for patch generation (default: gpt-4o)"
        ),
    ] = None,
    analyzer_model: Annotated[
        str | None,
        typer.Option(
            "--analyzer-model",
            help="Model for vulnerability analysis (default: gpt-4o-mini)",
        ),
    ] = None,
    # HTTP target configuration
    input_field: Annotated[
        str | None,
        typer.Option("--input-field", help="JSON field name for agent input"),
    ] = None,
    output_field: Annotated[
        str | None,
        typer.Option("--output-field", help="JSON field name for agent response"),
    ] = None,
    headers: Annotated[
        str | None,
        typer.Option("--headers", help="Custom HTTP headers (JSON string)"),
    ] = None,
    headers_file: Annotated[
        Path | None,
        typer.Option("--headers-file", help="File with HTTP headers as JSON"),
    ] = None,
    # Target identification
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Target alias for reference"),
    ] = None,
    target_id: Annotated[
        str | None,
        typer.Option("--target-id", help="Explicit target ID"),
    ] = None,
    # Fuzz testing
    fuzz: Annotated[
        bool,
        typer.Option("--fuzz", help="Enable fuzz testing phase"),
    ] = False,
    fuzz_only: Annotated[
        bool,
        typer.Option("--fuzz-only", help="Only run fuzz tests"),
    ] = False,
    fuzz_latency: Annotated[
        float | None,
        typer.Option("--fuzz-latency", help="Inject latency (seconds)"),
    ] = None,
    fuzz_errors: Annotated[
        bool,
        typer.Option("--fuzz-errors", help="Inject HTTP errors"),
    ] = False,
    fuzz_json: Annotated[
        bool,
        typer.Option("--fuzz-json", help="Inject JSON corruption"),
    ] = False,
    fuzz_probability: Annotated[
        float | None,
        typer.Option(
            "--fuzz-probability", help="Mutation probability (0.0-1.0) (default: 0.3)"
        ),
    ] = None,
    # Regression
    skip_regression: Annotated[
        bool,
        typer.Option("--skip-regression", help="Skip regression check"),
    ] = False,
    skip_mitigated: Annotated[
        bool,
        typer.Option("--skip-mitigated", help="Skip already-defended attacks"),
    ] = False,
    # Output
    report: Annotated[
        Path | None,
        typer.Option(
            "--report", "-r", help="HTML report path (default: ./serix-report.html)"
        ),
    ] = None,
    no_report: Annotated[
        bool,
        typer.Option("--no-report", help="Skip report generation"),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Run without saving results"),
    ] = False,
    github: Annotated[
        bool,
        typer.Option("--github", help="Enable GitHub Actions CI annotations"),
    ] = False,
    # Behavior
    no_patch: Annotated[
        bool,
        typer.Option("--no-patch", help="Skip patch generation"),
    ] = False,
    live: Annotated[
        bool,
        typer.Option("--live", help="Monitor the audit in real-time"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "-v", "--verbose", help="Show all attack logs and model reasoning"
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("-y", "--yes", help="Bypass prompts (CI mode)"),
    ] = False,
    # Config
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Use a specific config file (default: serix.toml)"
        ),
    ] = None,
    # Hidden help-all flag for extended help (callback triggers help display)
    help_all: Annotated[
        bool,
        typer.Option(
            "--help-all",
            hidden=True,
            is_eager=True,
            callback=_help_all_callback,
            help="Show all options",
        ),
    ] = False,
) -> None:
    """Run adversarial attacks against your agent and get actionable fixes."""
    # Step 0: Check API key
    if not _check_api_key():
        render_api_key_missing()
        raise typer.Exit(1)

    # Step 1: Resolve alias FIRST (Guardrail 1)
    resolved_target = _resolve_alias(target)

    # Step 2: Load TOML config
    toml_config, config_dir = load_toml_config(config_path=config)

    # Step 3: Parse headers JSON if provided
    parsed_headers: dict[str, str] | None = None
    if headers:
        try:
            parsed_headers = json.loads(headers)
        except json.JSONDecodeError:
            console.print("[red]Error:[/red] --headers must be valid JSON")
            raise typer.Exit(1)

    # Step 4: Build CLIOverrides (Guardrail 4: pass paths, not contents)
    cli_overrides = CLIOverrides(
        # Target
        target_path=resolved_target,
        target_name=name,
        target_id=target_id,
        input_field=input_field,
        output_field=output_field,
        headers=parsed_headers,
        headers_file=str(headers_file) if headers_file else None,
        # Attack
        goals=list(goal) if goal else None,
        goals_file=str(goals_file) if goals_file else None,
        mode=mode,
        scenarios=list(scenarios) if scenarios else None,
        depth=depth,
        exhaustive=exhaustive if exhaustive else None,
        # Models
        attacker_model=attacker_model,
        judge_model=judge_model,
        critic_model=critic_model,
        patcher_model=patcher_model,
        analyzer_model=analyzer_model,
        # Fuzz
        fuzz=fuzz if fuzz else None,
        fuzz_only=fuzz_only if fuzz_only else None,
        fuzz_latency=fuzz_latency,
        fuzz_errors=fuzz_errors if fuzz_errors else None,
        fuzz_json=fuzz_json if fuzz_json else None,
        fuzz_probability=fuzz_probability,
        # Regression
        skip_regression=skip_regression if skip_regression else None,
        skip_mitigated=skip_mitigated if skip_mitigated else None,
        # Output
        report_path=str(report) if report else None,
        no_report=no_report if no_report else None,
        dry_run=dry_run if dry_run else None,
        github=github if github else None,
        # Behavior
        no_patch=no_patch if no_patch else None,
        live=live if live else None,
        verbose=verbose if verbose else None,
        yes=yes if yes else None,
    )

    # Step 5: Resolve config
    try:
        session_config = resolve_config(cli_overrides, toml_config, config_dir)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    # Step 6: Validate goals
    if not session_config.goals:
        render_no_goal_error()
        raise typer.Exit(1)

    # Step 7: Create LLM provider
    llm_provider = LiteLLMProvider()

    # Step 8: Resolve target (Guardrail 2: single param)
    try:
        target_obj = resolve_target(session_config)
    except Exception as e:
        console.print(f"[red]Target error:[/red] {e}")
        raise typer.Exit(1)

    # Step 9: Create stores
    attack_store = FileAttackStore(base_dir=Path(".serix"))
    campaign_store = FileCampaignStore(base_dir=Path(".serix"))

    # Step 10: Render header
    render_campaign_header(
        target_path=session_config.target_path,
        target_id=session_config.target_id or "auto",
        goals=session_config.goals,
        mode=session_config.mode.value,
        depth=session_config.depth,
    )

    # Step 11: Create and run workflow
    workflow = TestWorkflow(
        config=session_config,
        target=target_obj,
        llm_provider=llm_provider,
        attack_store=attack_store,
        campaign_store=campaign_store,
    )

    result = workflow.run()

    # Step 12: Display results (Guardrail 5: display logic in renderers)
    render_campaign_result(result, verbose=session_config.verbose)

    # Step 13: Show healing patch if available
    if result.attacks:
        for attack in result.attacks:
            if attack.healing and attack.healing.diff:
                render_healing_patch(attack.healing.diff)
                break  # Show only first patch

    # Step 14: Generate HTML report if enabled
    if not session_config.no_report and not session_config.dry_run:
        report_path = Path(session_config.report_path)
        generator = HTMLReportGenerator()
        write_html_report(generator, result, report_path)
        console.print(f"  Report     {report_path}")

    # Step 15: GitHub output if enabled
    if session_config.github:
        write_github_annotations(result)
        write_step_summary(result)

    # Step 16: Warning for resilience issues
    if result.passed and result.resilience:
        failed_resilience = [r for r in result.resilience if not r.passed]
        if failed_resilience:
            console.print("[yellow]⚠ Note: Some infrastructure tests failed[/yellow]")

    # Step 17: Exit code
    raise typer.Exit(0 if result.passed else 1)
