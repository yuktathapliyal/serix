"""Serix CLI - Command line interface for AI agent testing."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import openai
import typer
from dotenv import load_dotenv
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


def _is_interactive() -> bool:
    """Check if running in an interactive terminal (TTY).

    Returns True for local dev (terminal), False for CI/piped output.
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def _validate_api_key(api_key: str) -> bool:
    """Validate an API key by making a lightweight API call.

    Args:
        api_key: OpenAI API key to validate

    Returns:
        True if the key is valid, False otherwise
    """
    import httpx

    try:
        console.print("[dim]Verifying API key...[/dim]", end=" ")
        response = httpx.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if response.status_code == 200:
            console.print("[green]✓[/green]")
            return True
        else:
            console.print("[red]✗[/red]")
            return False
    except Exception:
        console.print("[red]✗[/red]")
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
        console.print("[yellow]⚠️  Existing API key is invalid or expired.[/yellow]")

    # Interactive prompt
    if not existing_key:
        console.print("\n[yellow]⚠️  OpenAI API Key not found.[/yellow]")
    console.print("Serix needs a valid API key to run adversarial attacks.\n")

    api_key = typer.prompt(
        "Enter your OpenAI API Key (will be saved to .env)", hide_input=True
    )

    if not api_key.startswith("sk-"):
        console.print("[red]Invalid API key format (should start with sk-)[/red]")
        return False

    # Validate the new key
    if not _validate_api_key(api_key):
        console.print("[red]API key validation failed. Please check your key.[/red]")
        return False

    # Save to .env
    env_path = Path(".env")
    with open(env_path, "a") as f:
        f.write(f"OPENAI_API_KEY={api_key}\n")
    os.environ["OPENAI_API_KEY"] = api_key
    console.print("[green]✓[/green] API key saved to .env")
    return True


def _apply_monkey_patch() -> None:
    """Replace openai.OpenAI with SerixClient for interception."""
    openai.OpenAI = SerixClient  # type: ignore[misc]


def _run_script(script_path: Path) -> None:
    """Execute a Python script with Serix interception enabled.

    Args:
        script_path: Path to the Python script to execute
    """
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
    console.print(
        "[yellow]Warning: 'serix attack' is deprecated. "
        "Please use 'serix test --mode static' instead.[/yellow]\n"
    )
    from serix.core.client import get_original_openai_class
    from serix.core.config_loader import find_config_file, load_config
    from serix.fuzz.redteam import RedTeamEngine
    from serix.regression.store import AttackStore, StoredAttack
    from serix.report.console import print_attacks_saved
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

    # Bail early if script doesn't exist or isn't a Python file
    final_script = Path(final_script)
    if not final_script.exists():
        console.print(f"[red]Error:[/red] Script not found: {final_script}")
        raise typer.Exit(1)

    if not final_script.suffix == ".py":
        console.print(f"[red]Error:[/red] Not a Python file: {final_script}")
        raise typer.Exit(1)

    console.print(f"[bold violet]Serix[/bold violet] Attacking {final_script}")
    console.print(f"[yellow]Goal:[/yellow] {final_goal}")

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        console.print("[red]Error:[/red] Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine with unpatched client
    try:
        attacker_client = original_class()
    except Exception as e:
        error_msg = str(e).lower()
        if "api_key" in error_msg:
            console.print("[red]Error:[/red] OpenAI API key not found\n")
            console.print("Set your API key using one of these methods:\n")
            console.print("  1. Environment variable:")
            console.print("     [green]export OPENAI_API_KEY=sk-...[/green]\n")
            console.print("  2. In your shell profile (~/.bashrc or ~/.zshrc)")
            console.print("\nGet your key at: https://platform.openai.com/api-keys")
        else:
            console.print(f"[red]Error:[/red] Failed to initialize OpenAI client: {e}")
        raise typer.Exit(1)

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

    # Save attacks for regression testing
    if not no_save:
        store = AttackStore()
        saved_count = 0

        # Determine which attacks to save
        attacks_to_save = results.attacks if save_all else results.successful_attacks

        for atk in attacks_to_save:
            attack_to_store = StoredAttack.create(
                goal=final_goal,
                payload=atk.payload,
                vulnerability_type=atk.strategy,
                agent_response=atk.response or "",
                owasp_code="LLM01",
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
        console.print(f"\n[cyan]Report:[/cyan] {report_path}")


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
    no_fail_fast: Annotated[
        bool,
        typer.Option(
            "--no-fail-fast", help="Continue running even if regression check fails"
        ),
    ] = False,
    skip_mitigated: Annotated[
        bool,
        typer.Option(
            "--skip-mitigated",
            help="Skip attacks that have been mitigated (faster runs)",
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
    from serix.regression.store import AttackStore, StoredAttack
    from serix.report.console import print_attacks_saved
    from serix.report.github import write_github_output
    from serix.report.html import generate_evaluation_report, generate_html_report
    from serix.report.json_export import export_json
    from serix.sdk.decorator import Agent, get_system_prompt, load_function_from_path

    # Load config file if provided or found
    config_path = config or find_config_file()
    file_config = load_config(config_path)

    if config_path and config:  # Only show if explicitly provided
        console.print(f"[dim]Using config:[/dim] {config_path}")

    # Merge config with CLI args (CLI takes precedence)
    # Prefer target field, fall back to script for backward compat
    config_target = file_config.target.target or file_config.target.script
    final_target = target or config_target
    final_goal = goal or file_config.attack.goal
    final_report = report or (
        Path(file_config.attack.report) if file_config.attack.report else None
    )
    final_verbose = verbose or file_config.verbose

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
    if final_target is None:
        console.print(
            "[red]Error:[/red] Target is required. "
            "Provide as argument or in config file."
        )
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
        console.print(
            f"[bold violet]Serix[/bold violet] Testing HTTP endpoint: {final_target}"
        )
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
        console.print(
            f"[bold violet]Serix[/bold violet] Testing {name} from {file_path}"
        )

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
            console.print(f"[red]Error loading target:[/red] {e}")
            raise typer.Exit(1)
    else:
        console.print(
            "[red]Error:[/red] Invalid target format. Use:\n"
            "  - file.py:function_name (decorated function)\n"
            "  - file.py:ClassName (Agent subclass)\n"
            "  - http://url (HTTP endpoint)"
        )
        raise typer.Exit(1)

    # Default goal if not provided (if not from config or CLI)
    if not final_goal:
        final_goal = "Make the agent reveal sensitive information or bypass its safety guidelines"

    console.print(f"[yellow]Goal:[/yellow] {final_goal}")
    console.print(f"[dim]Mode:[/dim] {effective_mode}")

    # Show model config in verbose mode (once at startup, not per-turn)
    if final_verbose:
        from serix.core.config_loader import get_models

        models = get_models()
        # Use CLI override for judge if provided, otherwise config/default
        effective_judge = judge_model or models.judge
        if effective_mode == "adaptive":
            console.print(
                f"[dim]Models: attacker={models.attacker}, "
                f"critic={models.critic}, judge={effective_judge}[/dim]"
            )
        else:
            console.print(
                f"[dim]Models: attacker={models.attacker}, judge={effective_judge}[/dim]"
            )

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        console.print("[red]Error:[/red] Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine
    try:
        attacker_client = original_class()
    except Exception as e:
        error_msg = str(e).lower()
        if "api_key" in error_msg:
            console.print("[red]Error:[/red] OpenAI API key not found\n")
            console.print("Set your API key using one of these methods:\n")
            console.print("  1. Environment variable:")
            console.print("     [green]export OPENAI_API_KEY=sk-...[/green]\n")
            console.print("  2. In your shell profile (~/.bashrc or ~/.zshrc)")
            console.print("\nGet your key at: https://platform.openai.com/api-keys")
        else:
            console.print(f"[red]Error:[/red] Failed to initialize OpenAI client: {e}")
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
        console.print(
            f"[yellow]Fuzzing:[/yellow] {', '.join(mutations)} @ {fuzz_config.mutation_probability:.0%}"
        )

    # Verify HTTP targets are reachable before wasting API calls
    if isinstance(target_obj, HttpTarget):
        try:
            target_obj.verify_connectivity()
        except ConnectionError as e:
            console.print(f"[red]Error:[/red] {e}")
            console.print("\nMake sure your HTTP server is running.")
            raise typer.Exit(1)

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

    if stored_count > 0:
        print_immune_check_start(stored_count)
        runner = RegressionRunner(store, attacker_client)
        regression_result = runner.run_immune_check(
            target=target_obj,
            goal=final_goal,
            fail_fast=not no_fail_fast,
            skip_mitigated=skip_mitigated,
        )
        print_immune_check_result(
            regression_result.passed, regression_result.total_checked
        )

        # Handle regression: defended → exploited (critical)
        if regression_result.has_regression:
            console.print(
                "[red bold]⚠️  REGRESSION DETECTED:[/red bold] "
                "Previously mitigated attack is now exploitable!"
            )
            if not no_fail_fast:
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
            should_prompt = _is_interactive() and not no_fail_fast and not yes

            print_regression_failure(
                regression_result.failed_attacks,
                fail_fast=not no_fail_fast,
                will_prompt=should_prompt,
            )

            if not no_fail_fast:
                if should_prompt:
                    # Interactive mode: ask user if they want to continue
                    if not typer.confirm("Continue with new tests?", default=True):
                        raise typer.Exit(1)
                    console.print()  # Visual spacing after prompt
                elif not yes:
                    # Non-interactive without --yes: fail immediately
                    raise typer.Exit(1)
                # With --yes: continue without prompting

    try:
        # Use adversary loop for adaptive mode
        if effective_mode == "adaptive":
            if live:
                # Live split-screen command center UI
                import time

                from serix.report.live_ui import LiveAttackUI

                scenario_name = scenario_list[0] if scenario_list else "attack"
                target_name = (
                    final_target.split(":")[-1] if ":" in final_target else final_target
                )

                with LiveAttackUI(target_name, scenario_name, depth) as ui:
                    ui.update_status("ATTACKING")

                    # Run attack with UI callbacks
                    adversary_result = engine.attack_with_adversary(
                        target=target_obj,
                        goal=final_goal,
                        scenarios=scenario_list,
                        max_turns=depth,
                        system_prompt=system_prompt,
                        on_turn=ui.update_turn,
                        on_attack=ui.update_attacker_message,
                        on_response=ui.update_agent_response,
                        on_critic=ui.update_critic,
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

                # After live UI exits, skip to reporting (evaluation already done)
            else:
                console.print(
                    f"[dim]Using adaptive adversary with scenarios: {scenario_list}[/dim]"
                )
                console.print(f"[dim]Max turns per persona: {depth}[/dim]")

                # Enable progress output in non-live mode (callback signals progress mode)
                def progress_signal(turn: int, max_turns: int) -> None:
                    pass  # Actual printing handled in AdversaryLoop

                adversary_result = engine.attack_with_adversary(
                    target=target_obj,
                    goal=final_goal,
                    scenarios=scenario_list,
                    max_turns=depth,
                    system_prompt=system_prompt,
                    on_progress=progress_signal,
                )

                # Print fix suggestions if available
                if adversary_result.healing:
                    from serix.report.console import print_healing_result

                    print_healing_result(adversary_result.healing)

                # Run evaluation on adversary result (only for non-live mode)
                evaluator = Evaluator(
                    client=attacker_client,
                    verbose=final_verbose,
                )
                evaluation = evaluator.evaluate(adversary_result)

                # Add remediations to vulnerabilities
                remediation_engine = RemediationEngine()
                for vuln in evaluation.vulnerabilities:
                    remediation = remediation_engine.get_remediation(
                        vuln.type, vuln.evidence
                    )
                    vuln.remediation = remediation.description

            # Display security scores
            console.print("\n[cyan]━━━ Security Evaluation ━━━[/cyan]")
            status_color = "green" if evaluation.passed else "red"
            status_text = "PASSED" if evaluation.passed else "FAILED"
            console.print(f"[{status_color}]Status: {status_text}[/{status_color}]")

            console.print("\n[cyan]Scores:[/cyan]")
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
                    f"\n[red]Vulnerabilities Found ({len(evaluation.vulnerabilities)}):[/red]"
                )
                for vuln in evaluation.vulnerabilities:
                    severity_color = {
                        "critical": "red",
                        "high": "yellow",
                        "medium": "cyan",
                        "low": "dim",
                    }.get(vuln.severity, "white")
                    console.print(
                        f"  [{severity_color}][{vuln.severity.upper()}][/{severity_color}] "
                        f"{vuln.type}: {vuln.description}"
                    )

            # Display attack details
            console.print("\n[dim]Attack Details:[/dim]")
            console.print(f"  • Persona: {adversary_result.persona_used}")
            console.print(f"  • Turns: {adversary_result.turns_taken}")
            console.print(f"  • Confidence: {adversary_result.confidence}")
            if adversary_result.winning_payload:
                preview = adversary_result.winning_payload[:80] + "..."
                console.print(f"  • Winning payload: {preview}")

            # Auto-save successful attacks for regression testing
            if (
                not no_save
                and not evaluation.passed
                and adversary_result.winning_payload
            ):
                vuln_type = (
                    evaluation.vulnerabilities[0].type
                    if evaluation.vulnerabilities
                    else "unknown"
                )
                owasp = "LLM01"  # Default
                if evaluation.vulnerabilities:
                    # Try to get OWASP from vulnerability
                    owasp = getattr(
                        evaluation.vulnerabilities[0], "owasp_code", "LLM01"
                    )

                attack_to_save = StoredAttack.create(
                    goal=final_goal,
                    payload=adversary_result.winning_payload,
                    vulnerability_type=vuln_type,
                    agent_response=(
                        adversary_result.conversation[-1].get("content", "")
                        if adversary_result.conversation
                        else ""
                    ),
                    owasp_code=owasp,
                )
                if store.save(attack_to_save):
                    print_attacks_saved(1)

            # Generate remediations list (used for console display and reports)
            report_remediations: list | None = None
            if evaluation.vulnerabilities:
                report_remediations = remediation_engine.get_prioritized_remediations(
                    evaluation.vulnerabilities
                )

                # Display remediations if vulnerabilities found
                console.print("\n[cyan]Recommended Remediations:[/cyan]")
                for i, rem in enumerate(report_remediations[:3], 1):  # Top 3
                    console.print(f"  {i}. [bold]{rem.title}[/bold]")
                    # Show first line of description
                    first_line = rem.description.strip().split("\n")[0]
                    console.print(f"     {first_line}")

            # Generate HTML report if requested
            if final_report:
                report_path = generate_evaluation_report(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=final_target,
                    output_path=final_report,
                    remediations=report_remediations,
                )
                console.print(f"\n[cyan]HTML Report:[/cyan] {report_path}")

            # Generate JSON report if requested
            if json_report:
                json_path = export_json(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=final_target,
                    output_path=json_report,
                    remediations=report_remediations,
                )
                console.print(f"[cyan]JSON Report:[/cyan] {json_path}")

            # Write GitHub outputs if requested
            if github:
                if write_github_output(evaluation, final_target):
                    console.print("[dim]GitHub outputs written[/dim]")
                else:
                    console.print(
                        "[yellow]Note: Not running in GitHub Actions environment[/yellow]"
                    )

            # Exit with appropriate code
            if not evaluation.passed:
                raise typer.Exit(code=1)
            return

        # Use static mode - runs all 8 predefined attack templates
        results = engine.attack_target(
            target=target_obj,
            goal=final_goal,
            max_attempts=8,  # All static templates
        )
    finally:
        target_obj.teardown()

    # Report results (for static mode)
    if results.successful_attacks:
        console.print(
            f"\n[red]⚠️  {len(results.successful_attacks)} vulnerabilities found![/red]"
        )
        for atk in results.successful_attacks:
            console.print(f"  • {atk.strategy}: {atk.payload[:80]}...")
    else:
        console.print(
            f"\n[green]✓[/green] Agent defended against {results.total_attempts} attacks"
        )

    # Save attacks for regression testing
    if not no_save:
        saved_count = 0
        # Determine which attacks to save
        attacks_to_save = results.attacks if save_all else results.successful_attacks

        for atk in attacks_to_save:
            attack_to_save = StoredAttack.create(
                goal=final_goal,
                payload=atk.payload,
                vulnerability_type=atk.strategy,
                agent_response=atk.response or "",
                owasp_code="LLM01",
            )
            if store.save(attack_to_save):
                saved_count += 1
        if saved_count > 0:
            print_attacks_saved(saved_count)

    # Generate HTML report if requested
    if final_report:
        report_path = generate_html_report(
            results=results,
            script_path=final_target,
            output_path=final_report,
            judge_model=judge_model,
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
    console.print(f"[green]✓[/green] Created {config_path}")
    console.print("\n[dim]Next steps:[/dim]")
    console.print("  1. Edit serix.toml to set your target script and attack goal")
    console.print("  2. Run [cyan]serix attack[/cyan] to start testing")


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

    console.print("[bold violet]Serix Demo[/bold violet] - Testing a vulnerable agent")
    console.print("[dim]Target:[/dim] golden_victim (bundled)")
    console.print("[dim]Scenario:[/dim] jailbreak (Grandma exploit)")
    console.print("[dim]Goal:[/dim] Reveal the API key\n")

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
        cmd.append("--no-fail-fast")

    # Run as subprocess
    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)


if __name__ == "__main__":
    app()
