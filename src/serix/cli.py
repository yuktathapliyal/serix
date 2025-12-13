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
    fuzz: Annotated[
        bool, typer.Option("--fuzz", help="Enable fuzzing mode")
    ] = False,
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

    console.print(f"[cyan]Serix[/cyan] Running {script} in {mode.value} mode")
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

    console.print(f"[cyan]Serix[/cyan] Recording {script}...")

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
        f"[cyan]Serix[/cyan] Replaying {script} with {len(session.interactions)} "
        f"recorded interactions"
    )

    _run_script(script)
    console.print("[green]✓[/green] Replay complete")


@app.command()
def attack(
    script: Annotated[Path, typer.Argument(help="Python script to attack")],
    goal: Annotated[
        str,
        typer.Option("--goal", "-g", help="Attack goal description"),
    ],
    max_attempts: Annotated[
        int,
        typer.Option("--max-attempts", "-n", help="Maximum attack attempts"),
    ] = 10,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
) -> None:
    """Run red team attacks against an agent."""
    from serix.fuzz.redteam import RedTeamEngine
    from serix.core.client import get_original_openai_class

    console.print(f"[cyan]Serix[/cyan] Attacking {script}")
    console.print(f"[yellow]Goal:[/yellow] {goal}")

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        console.print("[red]Error:[/red] Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine with unpatched client
    attacker_client = original_class()
    engine = RedTeamEngine(client=attacker_client, verbose=verbose)

    # Run attacks
    results = engine.attack(
        script_path=script,
        goal=goal,
        max_attempts=max_attempts,
    )

    # Report results
    if results.successful_attacks:
        console.print(
            f"\n[red]⚠️  {len(results.successful_attacks)} successful attacks![/red]"
        )
        for attack in results.successful_attacks:
            console.print(f"  • {attack.strategy}: {attack.payload[:100]}...")
    else:
        console.print(f"\n[green]✓[/green] Agent defended against {max_attempts} attacks")


if __name__ == "__main__":
    app()
