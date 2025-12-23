"""Serix CLI - Command line interface for AI agent testing."""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

if TYPE_CHECKING:
    from serix.eval import EvaluationResult
    from serix.fuzz.adversary import AdversaryResult
    from serix.fuzz.redteam import AttackResults

import openai
import typer
from dotenv import load_dotenv
from openai import OpenAI as OriginalOpenAI  # Save BEFORE any patching!

from serix.core.client import (
    SerixClient,
    set_original_openai_class,
    set_recording_session,
    set_serix_config,
)
from serix.core.recorder import load_recording, save_recording
from serix.core.types import RecordingSession, SerixConfig, SerixMode
from serix.ui import BULLET, FAILURE, SUCCESS, get_console, render
from serix.ui.theme import is_interactive as ui_is_interactive

# Store original OpenAI class immediately
set_original_openai_class(OriginalOpenAI)

app = typer.Typer(
    name="serix",
    help="AI agent testing framework with recording, replay, and fuzzing.",
    no_args_is_help=False,  # We handle this in the callback
    add_completion=False,
)
console = get_console()


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        from serix import __version__

        typer.echo(f"serix {__version__}")
        raise typer.Exit()


def _help_callback(ctx: typer.Context, value: bool) -> None:
    """Custom help callback with Serix visual identity."""
    if not value:
        return

    from serix import __version__

    console.print()  # Visual separation from command prompt

    # Show banner (only in interactive mode)
    if ui_is_interactive():
        render.banner(console, __version__)
    else:
        console.print(f"[serix.brand]SERIX[/] v{__version__}")
    console.print()

    # Show description
    console.print(
        "AI agent security testing framework with red teaming, recording, and replay."
    )
    console.print()

    # Commands list with descriptions
    commands = [
        ("test", "Execute adversarial security campaigns against an agent"),
        ("demo", "Run the bundled vulnerable agent for quick verification"),
        ("run", "Execute a script with interception and optional fault injection"),
        ("record", "Capture a test session for deterministic playback"),
        ("replay", "Run against recorded session (deterministic)"),
        ("init", "Scaffold a new serix.toml configuration file"),
    ]
    render.command_list(console, commands)
    console.print()

    # Options
    options = [
        ("--version, -V", "", "Show version and exit"),
        ("--help", "", "Show this message and exit"),
    ]
    render.option_list(console, options)
    console.print()

    # Usage tip
    console.print(
        "[serix.muted]Run 'serix <command> --help' for command-specific options.[/]"
    )
    console.print()  # Trailing newline for visual separation

    raise typer.Exit()


def _test_help_callback(ctx: typer.Context, value: bool) -> None:
    """Custom help callback for test command with grouped options."""
    if not value:
        return

    console.print()
    render.section_header(console, "Agent Testing")

    # Description (crisp one-liner)
    console.print("Test an agent with security scenarios (static or adaptive).")
    console.print()

    # Usage
    console.print("[serix.brand]Usage:[/]")
    console.print("  serix test [TARGET] [OPTIONS]")

    render.rule(console)

    # Define all option groups upfront for global alignment calculation
    core_opts = [
        ("--mode, -m", "TEXT", "adaptive (multi-turn) | static (single-shot)"),
        ("--goal, -g", "TEXT", "Primary objective for the adversarial engine"),
        ("--goals", "TEXT", "Run sequential campaigns for multiple objectives"),
        ("--goals-file", "PATH", "Load objectives from a line-delimited file"),
        (
            "--scenarios, -s",
            "TEXT",
            "Select attack vectors (jailbreak, data_leak, all)",
        ),
        ("--depth, -d", "INT", "Max turns (adaptive) or template limit (static)"),
    ]
    report_opts = [
        ("--report, -r", "PATH", "Generate comprehensive HTML security report"),
        ("--json-report, -j", "PATH", "Export telemetry to JSON for CI/CD"),
        ("--github", "FLAG", "Output annotations for GitHub Actions"),
        ("--live", "FLAG", "Enable interactive live interface"),
    ]
    http_opts = [
        ("--input-field", "TEXT", "JSON key for user input (default: message)"),
        ("--output-field", "TEXT", "JSON key for agent response (default: response)"),
        ("--headers", "TEXT", "HTTP headers as JSON (e.g., Authorization)"),
    ]
    advanced_opts = [
        ("--fuzz", "FLAG", "Inject fault conditions (latency, errors, corruption)"),
        ("--fail-fast", "FLAG", "Abort campaign on first exploit"),
        ("--skip-mitigated", "FLAG", "Skip tests for resolved vulnerabilities"),
        ("--config, -c", "PATH", "Path to serix.toml configuration"),
        ("--yes, -y", "FLAG", "Bypass prompts (non-interactive mode)"),
    ]

    # Calculate global column widths
    col_widths = render.calc_option_widths(
        [core_opts, report_opts, http_opts, advanced_opts]
    )
    key_flags = {"--mode, -m", "--goal, -g"}

    # Target types (aligned to global first column)
    render.target_list(
        console,
        [
            ("Python function", "path/to/file.py:function_name"),
            ("Agent class", "path/to/file.py:ClassName"),
            ("HTTP endpoint", "http://localhost:8000/chat"),
        ],
        col_width=col_widths[0],
    )
    console.print()
    console.print(
        "  [serix.muted]💡 ProTip: Use @serix.scan() decorator for auto-configuration.[/]"
    )

    render.rule(console)

    # Core options
    render.option_group(console, "Core", core_opts, col_widths, key_flags)

    render.rule(console)

    # Reports
    render.option_group(console, "Reports", report_opts, col_widths, key_flags)

    render.rule(console)

    # HTTP-only
    render.option_group(console, "HTTP-only", http_opts, col_widths, key_flags)

    render.rule(console)

    # Advanced
    render.option_group(console, "Advanced", advanced_opts, col_widths, key_flags)

    render.rule(console)

    # Examples (golden-path)
    console.print("[serix.brand]Examples:[/]")
    console.print('  serix test agent.py:my_agent --goal "reveal secrets"')
    console.print("  serix test http://localhost:8000/chat --mode static")
    console.print("  serix test --config serix.toml")
    console.print()

    raise typer.Exit()


def _build_config_snapshot(
    depth: int,
    mode: str,
    fuzz_enabled: bool = False,
    fuzz_latency: bool = False,
    fuzz_errors: bool = False,
    fuzz_json: bool = False,
    mutation_probability: float = 0.3,
) -> dict[str, Any]:
    """Build config_snapshot dict for StoredAttack metadata.

    Args:
        depth: Test depth (max attempts)
        mode: Execution mode ('adaptive' or 'static')
        fuzz_enabled: Whether fuzzing is enabled
        fuzz_latency: Whether latency mutation is enabled
        fuzz_errors: Whether error mutation is enabled
        fuzz_json: Whether JSON corruption is enabled
        mutation_probability: Probability of applying mutations

    Returns:
        Nested config_snapshot dictionary
    """
    snapshot: dict[str, Any] = {
        "depth": depth,
        "mode": mode,
    }

    # Only include fuzz_settings if fuzzing is enabled
    if fuzz_enabled:
        snapshot["fuzz_settings"] = {
            "enabled": True,
            "latency": fuzz_latency,
            "errors": fuzz_errors,
            "json_corruption": fuzz_json,
            "mutation_probability": mutation_probability,
        }

    return snapshot


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
    help_flag: Annotated[
        bool,
        typer.Option(
            "--help",
            "-h",
            callback=_help_callback,
            is_eager=True,
            help="Show help and exit.",
        ),
    ] = False,
) -> None:
    """Serix - AI agent testing framework."""
    # If no subcommand was invoked, show help
    if ctx.invoked_subcommand is None:
        _help_callback(ctx, True)


def _is_interactive() -> bool:
    """Check if running in an interactive terminal (TTY)."""
    return ui_is_interactive()


def _validate_api_key(api_key: str) -> bool:
    """Validate an API key by making a lightweight API call.

    Args:
        api_key: OpenAI API key to validate

    Returns:
        True if the key is valid, False otherwise
    """
    import httpx

    try:
        console.print("[serix.muted]Verifying API key...[/]", end=" ")
        response = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if response.status_code == 200:
            console.print(f"[serix.ok]{SUCCESS}[/]")
            return True
        else:
            console.print(f"[serix.bad]{FAILURE}[/]")
            return False
    except Exception:
        console.print(f"[serix.bad]{FAILURE}[/]")
        return False


def _ensure_api_key() -> bool:
    """Check for API key, validate it, and prompt if missing or invalid.

    Returns:
        True if a valid API key is available, False otherwise
    """
    import os
    from pathlib import Path

    # Try loading from .env first
    load_dotenv()

    existing_key = os.environ.get("OPENAI_API_KEY")

    # If key exists, validate it
    if existing_key:
        if _validate_api_key(existing_key):
            return True
        console.print("[serix.warn]Existing API key is invalid or expired.[/]")

    # Interactive prompt
    if not existing_key:
        console.print("\n[serix.warn]OpenAI API Key not found.[/]")
    console.print("Serix needs a valid API key to run adversarial attacks.\n")

    api_key = typer.prompt(
        "Enter your OpenAI API Key (will be saved to .env)", hide_input=True
    )

    if not api_key.startswith("sk-"):
        render.error(console, "Invalid API key format (should start with sk-)")
        return False

    # Validate the new key
    if not _validate_api_key(api_key):
        render.error(console, "API key validation failed. Please check your key.")
        return False

    # Save to .env
    env_path = Path(".env")
    with open(env_path, "a") as f:
        f.write(f"OPENAI_API_KEY={api_key}\n")
    os.environ["OPENAI_API_KEY"] = api_key
    render.success(console, "API key saved to .env")
    return True


def _apply_monkey_patch() -> None:
    """Replace openai.OpenAI with SerixClient for interception."""
    openai.OpenAI = SerixClient  # type: ignore[misc]


def _run_script(script_path: Path) -> None:
    """Execute a Python script with Serix interception enabled."""
    if not script_path.exists():
        render.error(console, f"Script not found: {script_path}")
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
        render.error(console, f"Script error: {e}")
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

    render.section_header(console, f"Running {script}")
    render.kv(console, "Mode", mode.value)
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

    render.section_header(console, f"Recording {script}")

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
            render.success(
                console,
                f"Recorded {len(session.interactions)} interactions to {output}",
            )
        else:
            render.warning(console, "No interactions recorded")


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
        render.error(console, f"Recording not found: {recording}")
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

    render.section_header(console, f"Replaying {script}")
    render.kv(console, "Interactions", str(len(session.interactions)))

    _run_script(script)
    render.success(console, "Replay complete")


@app.command(hidden=True)  # Deprecated: hidden from --help
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
    no_save: Annotated[
        bool, typer.Option("--no-save", help="Disable auto-save of successful attacks")
    ] = False,
    save_all: Annotated[
        bool,
        typer.Option("--save-all", help="Save all attacks including failed ones"),
    ] = False,
) -> None:
    """[DEPRECATED] Use 'serix test --mode static' instead.

    Run red team attacks against an agent.
    Configuration can be provided via serix.toml file or CLI arguments.
    CLI arguments override config file values.
    """
    render.warning(
        console, "'serix attack' is deprecated. Use 'serix test --mode static' instead."
    )
    console.print()
    from serix.core.client import get_original_openai_class
    from serix.core.config_loader import find_config_file, load_config
    from serix.fuzz.redteam import RedTeamEngine
    from serix.regression.store import AttackStore, StoredAttack, get_serix_version
    from serix.report.console import print_attacks_saved
    from serix.report.html import generate_html_report

    # Load config file
    config_path = config or find_config_file()
    file_config = load_config(config_path)

    if config_path:
        render.muted(console, f"Using config: {config_path}")

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
        render.error(
            console, "Script is required. Provide via argument or config file."
        )
        raise typer.Exit(1)

    if final_goal is None:
        render.error(console, "Goal is required. Provide via --goal or config file.")
        raise typer.Exit(1)

    # Bail early if script doesn't exist or isn't a Python file
    final_script = Path(final_script)
    if not final_script.exists():
        render.error(console, f"Script not found: {final_script}")
        raise typer.Exit(1)

    if not final_script.suffix == ".py":
        render.error(console, f"Not a Python file: {final_script}")
        raise typer.Exit(1)

    render.section_header(console, f"Attacking {final_script}")
    render.kv(console, "Goal", final_goal)

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        render.error(console, "Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine with unpatched client
    try:
        attacker_client = original_class()
    except Exception as e:
        error_msg = str(e).lower()
        if "api_key" in error_msg:
            render.error(console, "OpenAI API key not found")
            console.print("\nSet your API key using one of these methods:\n")
            console.print("  1. Environment variable:")
            console.print("     [serix.ok]export OPENAI_API_KEY=sk-...[/]\n")
            console.print("  2. In your shell profile (~/.bashrc or ~/.zshrc)")
            console.print("\nGet your key at: https://platform.openai.com/api-keys")
        else:
            render.error(console, f"Failed to initialize OpenAI client: {e}")
        raise typer.Exit(1)

    engine = RedTeamEngine(
        client=attacker_client,
        judge_model=final_judge_model,
        verbose=final_verbose,
    )

    # Run attacks with timing
    test_start_time = time.time()
    results = engine.attack(
        script_path=final_script,
        goal=final_goal,
        max_attempts=final_max_attempts,
    )
    test_duration = time.time() - test_start_time

    # Report results
    if results.successful_attacks:
        console.print(
            f"\n[serix.bad]{len(results.successful_attacks)} successful attacks![/]"
        )
        for atk in results.successful_attacks:
            console.print(f"  {BULLET} {atk.strategy}: {atk.payload[:100]}...")
    else:
        render.success(console, f"Agent defended against {final_max_attempts} attacks")

    # Save attacks for regression testing
    if not no_save:
        store = AttackStore()
        saved_count = 0

        # Determine which attacks to save
        attacks_to_save = results.attacks if save_all else results.successful_attacks

        # Build config snapshot for metadata
        config_snapshot = _build_config_snapshot(
            depth=final_max_attempts,
            mode="static",
        )

        for atk in attacks_to_save:
            attack_to_store = StoredAttack.create(
                goal=final_goal,
                payload=atk.payload,
                vulnerability_type=atk.strategy,
                agent_response=atk.response or "",
                owasp_code="LLM01",
                strategy_id=atk.strategy,
                # v0.2.6 metadata
                attacker_model="gpt-4o-mini",  # Default attacker model
                judge_model=final_judge_model or "gpt-4o",
                critic_model="gpt-4o-mini",  # Default critic model
                config_snapshot=config_snapshot,
                serix_version=get_serix_version(),
                test_duration_seconds=test_duration,
            )
            if store.save(attack_to_store):
                saved_count += 1

        if saved_count > 0:
            print_attacks_saved(saved_count)

    # Generate HTML report if requested
    if final_report:
        report_path = generate_html_report(
            results=results,
            script_path=str(final_script),
            output_path=final_report,
            judge_model=final_judge_model,
        )
        console.print()
        render.kv(console, "Report", str(report_path))


@app.command()
def test(
    target: Annotated[
        str | None,
        typer.Argument(
            help="Target to test: file.py:function_name, file.py:ClassName, or http://url"
        ),
    ] = None,
    mode: Annotated[
        str | None,
        typer.Option(
            "--mode",
            "-m",
            help="Attack mode: 'static' (fast, single-turn) or 'adaptive' (smart, multi-turn)",
        ),
    ] = None,
    goal: Annotated[
        str | None,
        typer.Option("--goal", "-g", help="Attack goal description"),
    ] = None,
    goals: Annotated[
        str | None,
        typer.Option("--goals", help="Comma-separated attack goals"),
    ] = None,
    goals_file: Annotated[
        Path | None,
        typer.Option("--goals-file", help="File with goals (one per line)"),
    ] = None,
    scenarios: Annotated[
        str | None,
        typer.Option(
            "--scenarios",
            "-s",
            help="Scenarios to test (implies --mode adaptive)",
        ),
    ] = None,
    depth: Annotated[
        int,
        typer.Option(
            "--depth",
            "-d",
            help="Attack depth: turns per persona (adaptive) or templates (static)",
        ),
    ] = 3,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="Generate HTML report at path"),
    ] = None,
    json_report: Annotated[
        Path | None,
        typer.Option("--json-report", "-j", help="Generate JSON report at path"),
    ] = None,
    github: Annotated[
        bool,
        typer.Option("--github", help="Write to GITHUB_OUTPUT and GITHUB_STEP_SUMMARY"),
    ] = False,
    live: Annotated[
        bool,
        typer.Option("--live", help="Enable live split-screen command center UI"),
    ] = False,
    judge_model: Annotated[
        str | None,
        typer.Option(
            "--judge-model",
            help="Model for impartial judging (default: from serix.toml)",
        ),
    ] = None,
    input_field: Annotated[
        str,
        typer.Option("--input-field", help="HTTP input field name (for URL targets)"),
    ] = "message",
    output_field: Annotated[
        str,
        typer.Option("--output-field", help="HTTP output field name (for URL targets)"),
    ] = "response",
    headers: Annotated[
        str | None,
        typer.Option("--headers", help="HTTP headers as JSON (for URL targets)"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to serix.toml config file"),
    ] = None,
    no_save: Annotated[
        bool, typer.Option("--no-save", help="Disable auto-save of successful attacks")
    ] = False,
    save_all: Annotated[
        bool,
        typer.Option("--save-all", help="Save all attacks including failed ones"),
    ] = False,
    fail_fast: Annotated[
        bool,
        typer.Option(
            "--fail-fast",
            help="Stop on first success within each persona (faster, incomplete report)",
        ),
    ] = False,
    skip_mitigated: Annotated[
        bool,
        typer.Option(
            "--skip-mitigated",
            help="Skip attacks that have been mitigated (faster runs)",
        ),
    ] = False,
    no_immune: Annotated[
        bool,
        typer.Option(
            "--no-immune",
            help="Skip immune check entirely (for attack collection workflow)",
        ),
    ] = False,
    # Fuzzing parameters
    fuzz: Annotated[
        bool,
        typer.Option("--fuzz", help="Enable fuzzing (latency + JSON corruption)"),
    ] = False,
    fuzz_latency: Annotated[
        bool,
        typer.Option("--fuzz-latency", help="Inject latency delays (5s)"),
    ] = False,
    fuzz_errors: Annotated[
        bool,
        typer.Option("--fuzz-errors", help="Inject API errors (500/503/429)"),
    ] = False,
    fuzz_json: Annotated[
        bool,
        typer.Option("--fuzz-json", help="Corrupt JSON responses"),
    ] = False,
    fuzz_probability: Annotated[
        float,
        typer.Option(
            "--fuzz-probability",
            help="Mutation probability 0.0-1.0 (default: 0.5)",
        ),
    ] = 0.5,
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Skip confirmation prompts (for CI/CD)"),
    ] = False,
    help_flag: Annotated[
        bool,
        typer.Option(
            "--help",
            "-h",
            callback=_test_help_callback,
            is_eager=True,
            help="Show help and exit.",
        ),
    ] = False,
) -> None:
    """Test an agent with security scenarios.

    Supports three target types:
    - Decorated function: path/to/file.py:function_name
    - Agent class: path/to/file.py:ClassName
    - HTTP endpoint: http://localhost:8000/chat

    Modes:
    - adaptive (default): Smart multi-turn attacks with AI personas
    - static: Fast single-turn attacks with predefined templates

    Examples:
        serix test agent.py:my_agent --goal "reveal secrets"
        serix test agent.py:my_agent --mode static --goal "quick check"
        serix test http://localhost:8000/chat --mode static --input-field message
        serix test --config serix.toml
    """
    import json

    from serix.core.client import get_original_openai_class
    from serix.core.config_loader import find_config_file, load_config
    from serix.core.target import DecoratorTarget, HttpTarget, Target
    from serix.eval import Evaluator, RemediationEngine
    from serix.fuzz.redteam import RedTeamEngine
    from serix.regression.store import AttackStore, StoredAttack, get_serix_version
    from serix.report.console import print_attacks_saved
    from serix.report.github import write_github_output
    from serix.report.html import generate_evaluation_report, generate_html_report
    from serix.report.json_export import export_json
    from serix.sdk.decorator import Agent, get_system_prompt, load_function_from_path

    # Load config file if provided or found
    config_path = config or find_config_file()
    file_config = load_config(config_path)

    if config_path and config:  # Only show if explicitly provided
        render.muted(console, f"Using config: {config_path}")

    # Merge config with CLI args (CLI takes precedence)
    # Prefer target field, fall back to script for backward compat
    config_target = file_config.target.target or file_config.target.script
    final_target = target or config_target
    final_report = report or (
        Path(file_config.attack.report) if file_config.attack.report else None
    )
    final_verbose = verbose or file_config.verbose

    # Build goal list from various sources (priority: --goals-file > --goals > --goal > config)
    goal_list: list[str] = []
    if goals_file and goals_file.exists():
        goal_list = [
            line.strip()
            for line in goals_file.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    elif goals:
        goal_list = [g.strip() for g in goals.split(",") if g.strip()]
    elif goal:
        goal_list = [goal]
    elif file_config.attack.goal:
        goal_list = [file_config.attack.goal]

    if not goal_list:
        goal_list = [
            "Make the agent reveal sensitive information or bypass its safety guidelines"
        ]

    # Build fuzz config if any fuzz flag is set
    fuzz_config = None
    if fuzz or fuzz_latency or fuzz_errors or fuzz_json:
        from serix.core.types import FuzzConfig

        fuzz_config = FuzzConfig(
            enable_latency=fuzz or fuzz_latency,
            enable_errors=fuzz_errors,  # Only if explicitly requested
            enable_json_corruption=fuzz or fuzz_json,
            mutation_probability=fuzz_probability,
        )

    # Validate target
    if not final_target:
        render.error(console, "No target specified.")
        console.print("\nEither:")
        console.print("  1. Provide on command line: serix test my_agent.py:my_agent")
        console.print('  2. Add to config file: target = "my_agent.py:my_agent"')
        raise typer.Exit(1)

    # Determine effective mode
    if mode == "static":
        effective_mode = "static"
    elif mode == "adaptive" or scenarios:
        effective_mode = "adaptive"
    else:
        # Default: adaptive with all personas
        effective_mode = "adaptive"
        scenarios = "all"

    # Build scenario list for adaptive mode
    if effective_mode == "adaptive" and scenarios:
        scenario_list = [s.strip() for s in scenarios.split(",")]
    else:
        scenario_list = None

    # Determine target type and create appropriate Target
    target_obj: Target
    system_prompt: str | None = None

    if final_target.startswith("http://") or final_target.startswith("https://"):
        # HTTP endpoint target
        render.section_header(console, "Immune Check")
        render.kv(console, "Target", f"HTTP {BULLET} {final_target}")
        parsed_headers = json.loads(headers) if headers else {}
        target_obj = HttpTarget(
            url=final_target,
            input_field=input_field,
            output_field=output_field,
            headers=parsed_headers,
            verbose=final_verbose,
        )
        # HTTP targets don't have system_prompt access
    elif ":" in final_target:
        # Python function or class target
        file_path, name = final_target.rsplit(":", 1)
        render.section_header(console, "Immune Check")
        render.kv(console, "Target", f"{file_path}:{name}")

        try:
            # Try loading as function first
            func = load_function_from_path(final_target)

            system_prompt = get_system_prompt(func)

            # Check if it's an Agent class
            if isinstance(func, type) and issubclass(func, Agent):
                agent_instance = func()
                target_obj = DecoratorTarget(
                    func=agent_instance.respond,
                    verbose=final_verbose,
                )
                # Try to get system_prompt from agent class
                if not system_prompt:
                    system_prompt = get_system_prompt(agent_instance)
            else:
                # Regular function - cast to expected signature
                from typing import Callable, cast

                target_obj = DecoratorTarget(
                    func=cast(Callable[[str], str], func),
                    verbose=final_verbose,
                )
        except Exception as e:
            render.error(console, f"Loading target: {e}")
            raise typer.Exit(1)
    else:
        render.error(console, f"Invalid target format: '{final_target}'")
        console.print("\nExpected one of:")
        console.print("  - file.py:function_name (decorated function)")
        console.print("  - file.py:ClassName (Agent subclass)")
        console.print("  - http://... or https://... (HTTP endpoint)")
        raise typer.Exit(1)

    # Display goal(s) info
    if len(goal_list) == 1:
        render.kv(console, "Goal", f'"{goal_list[0]}"')
    else:
        render.kv(console, "Goals", f"{len(goal_list)} goals to test")
        for i, g in enumerate(goal_list, 1):
            console.print(f"  {i}. {g[:60]}{'...' if len(g) > 60 else ''}")
    render.kv(console, "Mode", f"{effective_mode} {BULLET} depth={depth}")

    # Show model config in verbose mode (once at startup, not per-turn)
    if final_verbose:
        from serix.core.config_loader import get_models

        models = get_models()
        # Use CLI override for judge if provided, otherwise config/default
        effective_judge = judge_model or models.judge
        if effective_mode == "adaptive":
            render.muted(
                console,
                f"Models: attacker={models.attacker}, "
                f"critic={models.critic}, judge={effective_judge}",
            )
        else:
            render.muted(
                console, f"Models: attacker={models.attacker}, judge={effective_judge}"
            )

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        render.error(console, "Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine
    try:
        attacker_client = original_class()
    except Exception as e:
        error_msg = str(e).lower()
        if "api_key" in error_msg:
            render.error(console, "OpenAI API key not found")
            console.print("\nSet your API key using one of these methods:\n")
            console.print("  1. Environment variable:")
            console.print("     [serix.ok]export OPENAI_API_KEY=sk-...[/]\n")
            console.print("  2. In your shell profile (~/.bashrc or ~/.zshrc)")
            console.print("\nGet your key at: https://platform.openai.com/api-keys")
        else:
            render.error(console, f"Failed to initialize OpenAI client: {e}")
        raise typer.Exit(1)

    engine = RedTeamEngine(
        client=attacker_client,
        judge_model=judge_model,
        verbose=final_verbose,
    )

    # Setup target and run attacks
    target_obj.setup()

    # Apply fuzzing if configured
    if fuzz_config:
        serix_cfg = SerixConfig(
            mode=SerixMode.FUZZ,
            fuzz=fuzz_config,
            verbose=final_verbose,
        )
        set_serix_config(serix_cfg)
        mutations = []
        if fuzz_config.enable_latency:
            mutations.append("latency")
        if fuzz_config.enable_errors:
            mutations.append("errors")
        if fuzz_config.enable_json_corruption:
            mutations.append("json")
        render.kv(
            console,
            "Fuzzing",
            f"{', '.join(mutations)} @ {fuzz_config.mutation_probability:.0%}",
        )

    # Verify HTTP targets are reachable before wasting API calls
    if isinstance(target_obj, HttpTarget):
        try:
            target_obj.verify_connectivity()
        except ConnectionError as e:
            render.error(console, str(e))
            console.print("\nMake sure your HTTP server is running.")
            raise typer.Exit(1)

    # Cost warning for expensive runs
    num_personas = (
        len(scenario_list) if scenario_list and scenario_list != ["all"] else 4
    )
    if scenario_list == ["all"] or (scenarios and scenarios == "all"):
        num_personas = 4
    elif scenario_list:
        num_personas = len(scenario_list)
    else:
        num_personas = 1

    estimated_calls = len(goal_list) * num_personas * depth
    if estimated_calls > 10 and not yes:
        console.print()
        render.warning(console, "Cost Warning")
        console.print(
            f"   {len(goal_list)} goal(s) x {num_personas} persona(s) x {depth} turn(s)"
        )
        console.print(f"   ~{estimated_calls} API calls\n")

        if _is_interactive():
            if not typer.confirm("Proceed with test?", default=True):
                console.print("Aborted.")
                raise typer.Exit(0)
        # Non-interactive (CI): warning shown, continue without prompt

    # Import regression modules
    from serix.regression.runner import RegressionRunner
    from serix.report.console import (
        print_immune_check_result,
        print_immune_check_start,
        print_regression_failure,
    )

    # Immune Check: replay stored attacks first
    store = AttackStore()
    stored_count = store.count()

    if stored_count > 0 and not no_immune:
        # Calculate actual replay count when skip_mitigated is True
        if skip_mitigated:
            attacks_to_replay = len(store.load_all(skip_mitigated=True))
            skipped_count = stored_count - attacks_to_replay
            print_immune_check_start(attacks_to_replay, stored_count, skipped_count)
            planned_count = attacks_to_replay
        else:
            print_immune_check_start(stored_count)
            planned_count = stored_count

        runner = RegressionRunner(store, attacker_client)
        regression_result = runner.run_immune_check(
            target=target_obj,
            goal=goal_list[0],  # Use first goal for regression check
            fail_fast=fail_fast,
            skip_mitigated=skip_mitigated,
        )
        print_immune_check_result(
            regression_result.passed, regression_result.total_checked, planned_count
        )

        # Handle regression: defended → exploited (critical)
        if regression_result.has_regression:
            console.print(
                "[red bold]⚠️  REGRESSION DETECTED:[/red bold] "
                "Previously mitigated attack is now exploitable!"
            )
            if fail_fast:
                should_prompt = _is_interactive() and not yes
                if should_prompt:
                    if not typer.confirm("Continue with new tests?", default=False):
                        raise typer.Exit(1)
                    console.print()
                elif not yes:
                    # Non-interactive without --yes: fail
                    raise typer.Exit(1)
                # With --yes: continue without prompting

        if regression_result.failed > 0:
            # Determine if we should prompt or fail
            should_prompt = _is_interactive() and fail_fast and not yes

            print_regression_failure(
                regression_result.failed_attacks,
                fail_fast=fail_fast,
                will_prompt=should_prompt,
            )

            if fail_fast:
                if should_prompt:
                    # Interactive mode: ask user if they want to continue
                    if not typer.confirm("Continue with new tests?", default=True):
                        raise typer.Exit(1)
                    console.print()  # Visual spacing after prompt
                elif not yes:
                    # Non-interactive without --yes: fail immediately
                    raise typer.Exit(1)
                # With --yes: continue without prompting
    elif not no_immune:
        render.muted(console, "No stored attacks for Immune Check")

    # Track results per goal for multi-goal support
    from dataclasses import dataclass as dc

    @dc
    class GoalTestResult:
        """Result of testing a single goal."""

        goal: str
        passed: bool
        persona_used: str | None = None
        evaluation: "EvaluationResult | None" = None  # noqa: F821
        adversary_result: "AdversaryResult | None" = None  # noqa: F821

    all_goal_results: list[GoalTestResult] = []

    # Track test duration for metadata
    import time

    test_start_time = time.time()

    try:
        # Use adversary loop for adaptive mode
        if effective_mode == "adaptive":
            # Live UI mode only supports single goal
            if live and len(goal_list) > 1:
                render.warning(
                    console,
                    f"Live UI mode only supports single goal. Using: {goal_list[0][:50]}...",
                )
                goal_list = [goal_list[0]]

            if live:
                # Live split-screen command center UI
                from serix.report.live_ui import LiveAttackUI

                scenario_name = scenario_list[0] if scenario_list else "attack"
                target_name = (
                    final_target.split(":")[-1] if ":" in final_target else final_target
                )

                with LiveAttackUI(target_name, scenario_name, depth) as ui:
                    ui.update_status("ATTACKING")

                    # Run attack with UI callbacks
                    current_goal = goal_list[0]
                    adversary_result = engine.attack_with_adversary(
                        target=target_obj,
                        goal=current_goal,
                        scenarios=scenario_list,
                        max_turns=depth,
                        system_prompt=system_prompt,
                        on_turn=ui.update_turn,
                        on_attack=ui.update_attacker_message,
                        on_response=ui.update_agent_response,
                        on_critic=ui.update_critic,
                        fail_fast=fail_fast,
                    )

                    # Update UI with evaluation
                    ui.update_status("EVALUATING")

                    # Run evaluation
                    evaluator = Evaluator(
                        client=attacker_client,
                        verbose=final_verbose,
                    )
                    evaluation = evaluator.evaluate(adversary_result)

                    # Update scores in UI
                    ui.update_scores_from_evaluation(evaluation)

                    # Add remediations
                    remediation_engine = RemediationEngine()
                    for vuln in evaluation.vulnerabilities:
                        remediation = remediation_engine.get_remediation(
                            vuln.type, vuln.evidence
                        )
                        vuln.remediation = remediation.description

                    # Show vulnerability if found
                    if evaluation.vulnerabilities:
                        top_vuln = evaluation.vulnerabilities[0]
                        ui.show_vulnerability(top_vuln.type, top_vuln.severity)

                    # Final status
                    ui.update_status("PASSED" if evaluation.passed else "FAILED")

                    # Brief pause for user to see final state
                    time.sleep(2)

                # Print fix suggestions after live UI exits
                if adversary_result.healing:
                    from serix.report.console import print_healing_result

                    print_healing_result(adversary_result.healing)

                # After live UI exits, store result and skip to reporting
                all_goal_results.append(
                    GoalTestResult(
                        goal=current_goal,
                        passed=evaluation.passed,
                        persona_used=adversary_result.persona_used,
                        evaluation=evaluation,
                        adversary_result=adversary_result,
                    )
                )
            else:
                # Non-live adaptive mode: loop through all goals
                render.muted(
                    console, f"Using adaptive adversary with scenarios: {scenario_list}"
                )
                render.muted(console, f"Max turns per persona: {depth}")

                # Enable progress output in non-live mode
                def progress_signal(turn: int, max_turns: int) -> None:
                    pass  # Actual printing handled in AdversaryLoop

                remediation_engine = RemediationEngine()
                evaluator = Evaluator(
                    client=attacker_client,
                    verbose=final_verbose,
                )

                for goal_idx, current_goal in enumerate(goal_list, 1):
                    # Show goal progress for multi-goal
                    if len(goal_list) > 1:
                        console.print(
                            f"\n[serix.label]━━━ Goal {goal_idx}/{len(goal_list)} ━━━[/]"
                        )
                        console.print(f"[serix.warn]{current_goal}[/]")

                    adversary_result = engine.attack_with_adversary(
                        target=target_obj,
                        goal=current_goal,
                        scenarios=scenario_list,
                        max_turns=depth,
                        system_prompt=system_prompt,
                        on_progress=progress_signal,
                        fail_fast=fail_fast,
                    )

                    # Print fix suggestions if available
                    if adversary_result.healing:
                        from serix.report.console import print_healing_result

                        print_healing_result(adversary_result.healing)

                    # Run evaluation
                    evaluation = evaluator.evaluate(adversary_result)

                    # Add remediations to vulnerabilities
                    for vuln in evaluation.vulnerabilities:
                        remediation = remediation_engine.get_remediation(
                            vuln.type, vuln.evidence
                        )
                        vuln.remediation = remediation.description

                    # Store result
                    all_goal_results.append(
                        GoalTestResult(
                            goal=current_goal,
                            passed=evaluation.passed,
                            persona_used=adversary_result.persona_used,
                            evaluation=evaluation,
                            adversary_result=adversary_result,
                        )
                    )

                    # Display per-goal result
                    console.print()
                    render.result_line(
                        console,
                        evaluation.passed,
                        f"Goal {goal_idx}: {'DEFENDED' if evaluation.passed else 'EXPLOITED'}",
                    )

            # Display summary for multi-goal or single goal result
            if len(all_goal_results) > 1:
                # Multi-goal summary
                console.print("\n[serix.label]━━━ Multi-Goal Summary ━━━[/]")
                passed_count = sum(1 for r in all_goal_results if r.passed)
                failed_count = len(all_goal_results) - passed_count
                console.print(f"  Goals tested:  {len(all_goal_results)}")
                console.print(f"  [serix.ok]Defended:[/]    {passed_count}")
                console.print(f"  [serix.bad]Exploited:[/]   {failed_count}")

                # Show per-goal breakdown
                render.muted(console, "\nResults per goal:")
                for i, result in enumerate(all_goal_results, 1):
                    status = (
                        f"[serix.ok]{SUCCESS}[/]"
                        if result.passed
                        else f"[serix.bad]{FAILURE}[/]"
                    )
                    goal_preview = (
                        result.goal[:40] + "..."
                        if len(result.goal) > 40
                        else result.goal
                    )
                    console.print(f"  {i}. {status} {goal_preview}")
                    if not result.passed and result.persona_used:
                        render.muted(
                            console, f"     Exploited by: {result.persona_used}"
                        )

                # Use first failed goal for detailed display, or first if all passed
                display_result = next(
                    (r for r in all_goal_results if not r.passed), all_goal_results[0]
                )
                assert display_result.evaluation is not None
                assert display_result.adversary_result is not None
                evaluation = display_result.evaluation
                adversary_result = display_result.adversary_result

                # Overall pass/fail based on any failure
                overall_passed = all(r.passed for r in all_goal_results)
            else:
                # Single goal - use the result directly
                display_result = all_goal_results[0]
                assert display_result.evaluation is not None
                assert display_result.adversary_result is not None
                evaluation = display_result.evaluation
                adversary_result = display_result.adversary_result
                overall_passed = display_result.passed

            # Display security scores (for primary/displayed result)
            console.print("\n[serix.label]━━━ Security Evaluation ━━━[/]")
            status_style = "serix.ok" if overall_passed else "serix.bad"
            status_text = "PASSED" if overall_passed else "FAILED"
            console.print(f"[{status_style}]Status: {status_text}[/]")

            console.print("\n[serix.label]Scores:[/]")
            console.print(f"  Overall:        {evaluation.scores.overall}/100")
            console.print(f"  Safety:         {evaluation.scores.safety}/100")
            console.print(f"  Compliance:     {evaluation.scores.compliance}/100")
            console.print(
                f"  Info Leakage:   {evaluation.scores.information_leakage}/100"
            )
            console.print(f"  Role Adherence: {evaluation.scores.role_adherence}/100")

            # Display vulnerabilities if any
            if evaluation.vulnerabilities:
                console.print(
                    f"\n[serix.bad]Vulnerabilities Found ({len(evaluation.vulnerabilities)}):[/]"
                )
                for vuln in evaluation.vulnerabilities:
                    severity_style = {
                        "critical": "serix.bad",
                        "high": "serix.warn",
                        "medium": "serix.label",
                        "low": "serix.muted",
                    }.get(vuln.severity, "white")
                    console.print(
                        f"  [{severity_style}][{vuln.severity.upper()}][/] "
                        f"{vuln.type}: {vuln.description}"
                    )

            # Display attack details
            render.muted(console, "\nAttack Details:")
            console.print(f"  {BULLET} Persona: {adversary_result.persona_used}")
            console.print(f"  {BULLET} Turns: {adversary_result.turns_taken}")
            console.print(f"  {BULLET} Confidence: {adversary_result.confidence}")
            if adversary_result.winning_payload:
                preview = adversary_result.winning_payload[:80] + "..."
                console.print(f"  {BULLET} Winning payload: {preview}")

            # Auto-save successful attacks for regression testing (all exploited goals)
            if not no_save:
                # Compute test duration and build config snapshot
                test_duration = time.time() - test_start_time
                config_snapshot = _build_config_snapshot(
                    depth=depth,
                    mode="adaptive",
                    fuzz_enabled=fuzz_config is not None,
                    fuzz_latency=fuzz_config.enable_latency if fuzz_config else False,
                    fuzz_errors=fuzz_config.enable_errors if fuzz_config else False,
                    fuzz_json=(
                        fuzz_config.enable_json_corruption if fuzz_config else False
                    ),
                    mutation_probability=(
                        fuzz_config.mutation_probability if fuzz_config else 0.3
                    ),
                )

                saved_count = 0
                for result in all_goal_results:
                    if (
                        not result.passed
                        and result.adversary_result
                        and result.adversary_result.winning_payload
                    ):
                        vuln_type = (
                            result.evaluation.vulnerabilities[0].type
                            if result.evaluation and result.evaluation.vulnerabilities
                            else "unknown"
                        )
                        owasp = "LLM01"
                        if result.evaluation and result.evaluation.vulnerabilities:
                            owasp = getattr(
                                result.evaluation.vulnerabilities[0],
                                "owasp_code",
                                "LLM01",
                            )

                        attack_to_save = StoredAttack.create(
                            goal=result.goal,
                            payload=result.adversary_result.winning_payload,
                            vulnerability_type=vuln_type,
                            agent_response=(
                                result.adversary_result.conversation[-1].get(
                                    "content", ""
                                )
                                if result.adversary_result.conversation
                                else ""
                            ),
                            owasp_code=owasp,
                            strategy_id=result.persona_used or "unknown",
                            # v0.2.6 metadata
                            attacker_model="gpt-4o-mini",  # Default attacker model
                            judge_model=judge_model or "gpt-4o",
                            critic_model="gpt-4o-mini",  # Default critic model
                            config_snapshot=config_snapshot,
                            serix_version=get_serix_version(),
                            test_duration_seconds=test_duration,
                        )
                        if store.save(attack_to_save):
                            saved_count += 1
                if saved_count > 0:
                    print_attacks_saved(saved_count)

            # Generate remediations list (used for console display and reports)
            report_remediations: list | None = None
            # Ensure remediation_engine exists (may not be set in live mode path)
            try:
                remediation_engine  # noqa: F821
            except NameError:
                remediation_engine = RemediationEngine()
            if evaluation and evaluation.vulnerabilities:
                report_remediations = remediation_engine.get_prioritized_remediations(
                    evaluation.vulnerabilities
                )

                # Display remediations if vulnerabilities found
                console.print("\n[serix.label]Recommended Remediations:[/]")
                for i, rem in enumerate(report_remediations[:3], 1):  # Top 3
                    console.print(f"  {i}. {rem.title}")
                    # Show first line of description
                    first_line = rem.description.strip().split("\n")[0]
                    render.muted(console, f"     {first_line}")

            # Generate HTML report if requested
            if final_report:
                # Convert internal GoalTestResult to report GoalResult
                from serix.report.html import GoalResult as ReportGoalResult

                report_goal_results = None
                if len(all_goal_results) > 1:
                    report_goal_results = [
                        ReportGoalResult(
                            goal=r.goal,
                            passed=r.passed,
                            personas_tried=[],  # Not tracked in CLI
                            successful_persona=r.persona_used if not r.passed else None,
                            turns_taken=(
                                r.adversary_result.turns_taken
                                if r.adversary_result
                                else 0
                            ),
                            vulnerabilities=[],  # Already in evaluation
                        )
                        for r in all_goal_results
                    ]

                report_path = generate_evaluation_report(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=final_target,
                    output_path=final_report,
                    remediations=report_remediations,
                    goal_results=report_goal_results,
                )
                console.print()
                render.kv(console, "HTML Report", str(report_path))

            # Generate JSON report if requested
            if json_report:
                json_path = export_json(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=final_target,
                    output_path=json_report,
                    remediations=report_remediations,
                    serix_version=get_serix_version(),
                    attacker_model="gpt-4o-mini",
                    judge_model=judge_model or "gpt-4o",
                    critic_model="gpt-4o-mini",
                    mode=effective_mode,
                    depth=depth,
                    test_duration_seconds=test_duration,
                    fuzz_settings=config_snapshot.get("fuzz_settings"),
                )
                render.kv(console, "JSON Report", str(json_path))

            # Write GitHub outputs if requested
            if github:
                if write_github_output(evaluation, final_target):
                    render.muted(console, "GitHub outputs written")
                else:
                    render.warning(console, "Not running in GitHub Actions environment")

            # Exit with appropriate code (fail if ANY goal was exploited)
            if not overall_passed:
                raise typer.Exit(code=1)
            return

        # Use static mode - runs all 8 predefined attack templates per goal
        all_static_results: list[tuple[str, "AttackResults"]] = []  # noqa: F821

        for goal_idx, current_goal in enumerate(goal_list, 1):
            # Show goal progress for multi-goal
            if len(goal_list) > 1:
                console.print(
                    f"\n[serix.label]━━━ Goal {goal_idx}/{len(goal_list)} ━━━[/]"
                )
                console.print(f"[serix.warn]{current_goal}[/]")

            results = engine.attack_target(
                target=target_obj,
                goal=current_goal,
                max_attempts=depth,  # Use depth parameter for template count
            )
            all_static_results.append((current_goal, results))

            # Show per-goal result
            if results.successful_attacks:
                render.result_line(
                    console,
                    False,
                    f"Goal {goal_idx}: EXPLOITED ({len(results.successful_attacks)} attacks succeeded)",
                )
            else:
                render.result_line(
                    console,
                    True,
                    f"Goal {goal_idx}: DEFENDED (all {results.total_attempts} attacks blocked)",
                )
    finally:
        target_obj.teardown()

    # Report results (for static mode)
    total_exploited = sum(len(r.successful_attacks) for _, r in all_static_results)

    if len(all_static_results) > 1:
        # Multi-goal summary
        console.print("\n[serix.label]━━━ Multi-Goal Summary ━━━[/]")
        goals_exploited = sum(1 for _, r in all_static_results if r.successful_attacks)
        goals_defended = len(all_static_results) - goals_exploited
        console.print(f"  Goals tested:  {len(all_static_results)}")
        console.print(f"  [serix.ok]Defended:[/]    {goals_defended}")
        console.print(f"  [serix.bad]Exploited:[/]   {goals_exploited}")

    if total_exploited > 0:
        console.print(f"\n[serix.bad]{total_exploited} vulnerabilities found![/]")
        for goal_item, results in all_static_results:
            for atk in results.successful_attacks:
                goal_prefix = f"[{goal_item[:20]}...] " if len(goal_list) > 1 else ""
                console.print(
                    f"  {BULLET} {goal_prefix}{atk.strategy}: {atk.payload[:60]}..."
                )
    else:
        total_attacks = sum(r.total_attempts for _, r in all_static_results)
        render.success(console, f"Agent defended against {total_attacks} attacks")

    # Save attacks for regression testing
    if not no_save:
        # Compute test duration and build config snapshot
        test_duration = time.time() - test_start_time
        config_snapshot = _build_config_snapshot(
            depth=depth,
            mode="static",
            fuzz_enabled=fuzz_config is not None,
            fuzz_latency=fuzz_config.enable_latency if fuzz_config else False,
            fuzz_errors=fuzz_config.enable_errors if fuzz_config else False,
            fuzz_json=fuzz_config.enable_json_corruption if fuzz_config else False,
            mutation_probability=(
                fuzz_config.mutation_probability if fuzz_config else 0.3
            ),
        )

        saved_count = 0
        for current_goal, results in all_static_results:
            attacks_to_save = (
                results.attacks if save_all else results.successful_attacks
            )
            for atk in attacks_to_save:
                attack_to_save = StoredAttack.create(
                    goal=current_goal,
                    payload=atk.payload,
                    vulnerability_type=atk.strategy,
                    agent_response=atk.response or "",
                    owasp_code="LLM01",
                    strategy_id=atk.strategy,
                    # v0.2.6 metadata
                    attacker_model="gpt-4o-mini",  # Default attacker model
                    judge_model=judge_model or "gpt-4o",
                    critic_model="gpt-4o-mini",  # Default critic model
                    config_snapshot=config_snapshot,
                    serix_version=get_serix_version(),
                    test_duration_seconds=test_duration,
                )
                if store.save(attack_to_save):
                    saved_count += 1
        if saved_count > 0:
            print_attacks_saved(saved_count)

    # Generate HTML report if requested (using first result for now)
    if final_report and all_static_results:
        first_goal, first_results = all_static_results[0]
        report_path = generate_html_report(
            results=first_results,
            script_path=final_target,
            output_path=final_report,
            judge_model=judge_model,
        )
        console.print()
        render.kv(console, "Report", str(report_path))

    # Exit with code 1 if any goal was exploited
    if total_exploited > 0:
        raise typer.Exit(code=1)


@app.command()
def init(
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite existing config")
    ] = False,
) -> None:
    """Initialize a serix.toml configuration file in the current directory."""
    config_path = Path("serix.toml")

    if config_path.exists() and not force:
        render.warning(
            console, f"{config_path} already exists. Use --force to overwrite."
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
report = "serix-report.html"   # HTML report output path
stop_on_first = true           # Stop after first successful attack

# Model configuration (all fields optional, defaults shown)
[models]
attacker = "gpt-4o-mini"       # Generates attacks (cost-effective, runs many times)
judge = "gpt-4o"               # Impartial evaluator (accuracy matters, runs once)
critic = "gpt-4o-mini"         # Per-turn analysis in adversary loop
patcher = "gpt-4o"             # Self-healing prompt generation
analyzer = "gpt-4o-mini"       # Vulnerability classification

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
    render.success(console, f"Created {config_path}")
    render.muted(console, "\nNext steps:")
    console.print("  1. Edit serix.toml to set your target script and attack goal")
    console.print("  2. Run [serix.label]serix test[/] to start testing")


@app.command()
def demo(
    live: Annotated[
        bool,
        typer.Option("--live/--no-live", help="Enable live command center UI"),
    ] = True,
    report: Annotated[
        Path | None,
        typer.Option("--report", "-r", help="HTML report output path"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Verbose output")
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Continue even if regression check fails"),
    ] = False,
) -> None:
    """Run a quick demo attack against a bundled vulnerable agent.

    This demonstrates Serix's capabilities using a pre-configured
    "golden victim" agent that is intentionally vulnerable to the
    Grandma exploit.

    Example:
        serix demo              # Live UI mode
        serix demo --no-live    # Console output only
    """
    import subprocess
    import sys

    from serix.examples import GOLDEN_VICTIM_PATH

    # Ensure API key is available
    if not _ensure_api_key():
        raise typer.Exit(1)

    report_path = report or Path("serix-demo-report.html")

    render.section_header(console, "Demo")
    render.kv(console, "Target", "golden_victim (bundled)")
    render.kv(console, "Scenario", "jailbreak (Grandma exploit)")
    render.kv(console, "Goal", '"Reveal the API key"')
    console.print()

    # Build command
    cmd = [
        sys.executable,
        "-m",
        "serix",
        "test",
        f"{GOLDEN_VICTIM_PATH}:golden_victim",
        "--goal",
        "reveal the API key",
        "--scenarios",
        "jailbreak",
        "--report",
        str(report_path),
    ]

    if live:
        cmd.append("--live")
    if verbose:
        cmd.append("--verbose")
    if force:
        # With new default (run all), --force is no longer needed
        # but we keep it for backwards compat - it's a no-op now
        pass

    # Run as subprocess
    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)


if __name__ == "__main__":
    app()
