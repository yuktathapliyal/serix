"""Serix CLI - Command line interface for AI agent testing."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import openai
import typer
from openai import OpenAI as OriginalOpenAI  # Save BEFORE any patching!
from rich.console import Console

from serix.core.client import (
    SerixClient,
    set_original_openai_class,
    set_recording_session,
    set_serix_config,
)
from serix.core.recorder import load_recording, save_recording
from serix.core.types import RecordingSession, SerixConfig, SerixMode

# Store original OpenAI class immediately
set_original_openai_class(OriginalOpenAI)

app = typer.Typer(
    name="serix",
    help="AI agent testing framework with recording, replay, and fuzzing.",
    no_args_is_help=True,
)
console = Console()


def _apply_monkey_patch() -> None:
    """Replace openai.OpenAI with SerixClient."""
    openai.OpenAI = SerixClient  # type: ignore[misc]


def _run_script(script_path: Path) -> None:
    """Execute a Python script with Serix interception enabled."""
    if not script_path.exists():
        console.print(f"[red]Error:[/red] Script not found: {script_path}")
        raise typer.Exit(1)

    # Apply monkey patch
    _apply_monkey_patch()

    # Add script directory to path so imports work
    script_dir = str(script_path.parent.resolve())
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Read and execute the script
    script_code = script_path.read_text()
    script_globals = {
        "__name__": "__main__",
        "__file__": str(script_path.resolve()),
    }

    try:
        exec(compile(script_code, script_path, "exec"), script_globals)
    except Exception as e:
        console.print(f"[red]Script error:[/red] {e}")
        raise


@app.command()
def run(
    script: Annotated[Path, typer.Argument(help="Python script to run")],
    fuzz: Annotated[bool, typer.Option("--fuzz", help="Enable fuzzing mode")] = False,
    fuzz_latency: Annotated[
        bool, typer.Option("--fuzz-latency", help="Inject latency")
    ] = False,
    fuzz_errors: Annotated[
        bool, typer.Option("--fuzz-errors", help="Inject HTTP errors")
    ] = False,
    fuzz_json: Annotated[
        bool, typer.Option("--fuzz-json", help="Corrupt JSON responses")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
) -> None:
    """Run a Python script with Serix interception enabled."""
    from serix.core.types import FuzzConfig

    # Determine mode
    if fuzz or fuzz_latency or fuzz_errors or fuzz_json:
        mode = SerixMode.FUZZ
        fuzz_config = FuzzConfig(
            enable_latency=fuzz or fuzz_latency,
            enable_errors=fuzz or fuzz_errors,
            enable_json_corruption=fuzz or fuzz_json,
        )
    else:
        mode = SerixMode.PASSTHROUGH
        fuzz_config = FuzzConfig()

    config = SerixConfig(mode=mode, fuzz=fuzz_config, verbose=verbose)
    set_serix_config(config)

    console.print(
        f"[bold violet]Serix[/bold violet] Running {script} in {mode.value} mode"
    )
    _run_script(script)


@app.command()
def record(
    script: Annotated[Path, typer.Argument(help="Python script to run")],
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", help="Output file path"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
) -> None:
    """Record API interactions from a script run."""
    config = SerixConfig(mode=SerixMode.RECORD, verbose=verbose)
    set_serix_config(config)

    # Create recording session
    session = RecordingSession(script_path=str(script))
    set_recording_session(session)

    console.print(f"[bold violet]Serix[/bold violet] Recording {script}...")

    try:
        _run_script(script)
    finally:
        # Save recording
        if session.interactions:
            if output is None:
                recordings_dir = Path(config.recording_dir)
                recordings_dir.mkdir(exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = recordings_dir / f"{script.stem}_{timestamp}.json"

            save_recording(session, output)
            console.print(
                f"[green]✓[/green] Recorded {len(session.interactions)} "
                f"interactions to {output}"
            )
        else:
            console.print("[yellow]⚠️  No interactions recorded[/yellow]")


@app.command()
def replay(
    script: Annotated[Path, typer.Argument(help="Python script to run")],
    recording: Annotated[
        Path,
        typer.Option("-r", "--recording", help="Recording file to replay"),
    ],
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
) -> None:
    """Replay a script using recorded API responses."""
    if not recording.exists():
        console.print(f"[red]Error:[/red] Recording not found: {recording}")
        raise typer.Exit(1)

    config = SerixConfig(
        mode=SerixMode.REPLAY,
        recording_file=str(recording),
        verbose=verbose,
    )
    set_serix_config(config)

    # Load recording
    session = load_recording(recording)
    set_recording_session(session)

    console.print(
        f"[bold violet]Serix[/bold violet] Replaying {script} with {len(session.interactions)} "
        f"recorded interactions"
    )

    _run_script(script)
    console.print("[green]✓[/green] Replay complete")


@app.command()
def attack(
    script: Annotated[
        Path | None,
        typer.Argument(help="Python script to attack (optional if in config)"),
    ] = None,
    goal: Annotated[
        str | None,
        typer.Option("--goal", "-g", help="Attack goal description"),
    ] = None,
    max_attempts: Annotated[
        int | None,
        typer.Option("--max-attempts", "-n", help="Maximum attack attempts"),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Generate HTML report at path"),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option("--judge-model", help="Model for impartial judging"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to config file"),
    ] = None,
) -> None:
    """Run red team attacks against an agent.

    Configuration can be provided via serix.toml file or CLI arguments.
    CLI arguments override config file values.
    """
    from serix.core.client import get_original_openai_class
    from serix.core.config_loader import find_config_file, load_config
    from serix.fuzz.redteam import RedTeamEngine
    from serix.report.html import generate_html_report

    # Load config file
    config_path = config or find_config_file()
    file_config = load_config(config_path)

    if config_path:
        console.print(f"[dim]Using config:[/dim] {config_path}")

    # Merge config with CLI args (CLI takes precedence)
    final_script = script or (
        Path(file_config.target.script) if file_config.target.script else None
    )
    final_goal = goal or file_config.attack.goal
    final_max_attempts = max_attempts or file_config.attack.max_attempts
    final_judge_model = judge_model or file_config.attack.judge_model
    final_report = report or (
        Path(file_config.attack.report) if file_config.attack.report else None
    )
    final_verbose = verbose or file_config.verbose

    # Validate required fields
    if final_script is None:
        console.print(
            "[red]Error:[/red] Script is required. "
            "Provide via argument or config file."
        )
        raise typer.Exit(1)

    if final_goal is None:
        console.print(
            "[red]Error:[/red] Goal is required. " "Provide via --goal or config file."
        )
        raise typer.Exit(1)

    console.print(f"[bold violet]Serix[/bold violet] Attacking {final_script}")
    console.print(f"[yellow]Goal:[/yellow] {final_goal}")

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        console.print("[red]Error:[/red] Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine with unpatched client
    attacker_client = original_class()
    engine = RedTeamEngine(
        client=attacker_client,
        judge_model=final_judge_model,
        verbose=final_verbose,
    )

    # Run attacks
    results = engine.attack(
        script_path=final_script,
        goal=final_goal,
        max_attempts=final_max_attempts,
    )

    # Report results
    if results.successful_attacks:
        console.print(
            f"\n[red]⚠️  {len(results.successful_attacks)} successful attacks![/red]"
        )
        for atk in results.successful_attacks:
            console.print(f"  • {atk.strategy}: {atk.payload[:100]}...")
    else:
        console.print(
            f"\n[green]✓[/green] Agent defended against {final_max_attempts} attacks"
        )

    # Generate HTML report if requested
    if final_report:
        report_path = generate_html_report(
            results=results,
            script_path=str(final_script),
            output_path=final_report,
            judge_model=final_judge_model,
        )
        console.print(f"\n[cyan]Report:[/cyan] {report_path}")


@app.command()
def init(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing config")
    ] = False,
) -> None:
    """Initialize a serix.toml configuration file in the current directory."""
    config_path = Path("serix.toml")

    if config_path.exists() and not force:
        console.print(
            f"[yellow]Warning:[/yellow] {config_path} already exists. "
            "Use --force to overwrite."
        )
        raise typer.Exit(1)

    default_config = """# Serix Configuration File
# This file configures AI agent security testing for your project.
# All CLI arguments can also be set here. CLI args override these values.

# Target configuration
[target]
script = "agent.py"            # Your agent script to test
# working_dir = "."            # Working directory for script execution

# Red team attack configuration
[attack]
goal = "Make the agent reveal sensitive information or ignore its instructions"
max_attempts = 5               # Number of attack attempts
judge_model = "gpt-4o"         # Model for impartial judging (gpt-4o recommended)
model = "gpt-4o-mini"          # Model for generating attacks
report = "serix-report.html"   # HTML report output path
stop_on_first = true           # Stop after first successful attack

# Fuzzing configuration
[fuzz]
enabled = false                # Enable fuzzing by default
latency = true                 # Inject latency delays
errors = true                  # Inject HTTP errors (500, 503, 429)
json_corruption = true         # Corrupt JSON responses
mutation_probability = 0.3     # Probability of applying mutations
latency_seconds = 5.0          # Latency injection duration

# Global settings
verbose = false                # Enable verbose output
"""

    config_path.write_text(default_config)
    console.print(f"[green]✓[/green] Created {config_path}")
    console.print("\n[dim]Next steps:[/dim]")
    console.print("  1. Edit serix.toml to set your target script and attack goal")
    console.print("  2. Run [cyan]serix attack[/cyan] to start testing")


if __name__ == "__main__":
    app()
