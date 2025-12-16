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


def _validate_api_key(api_key: str) -> bool:
    """Validate an API key by making a lightweight API call."""
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
    """Check for API key, validate it, and prompt if missing or invalid."""
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
def test(
    target: Annotated[
        str,
        typer.Argument(
            help="Target to test: file.py:function_name, file.py:ClassName, or http://url"
        ),
    ],
    goal: Annotated[
        str | None,
        typer.Option("--goal", "-g", help="Attack goal description"),
    ] = None,
    scenarios: Annotated[
        str | None,
        typer.Option("--scenarios", "-s", help="Comma-separated scenarios to test"),
    ] = None,
    max_attempts: Annotated[
        int,
        typer.Option("--max-attempts", "-n", help="Maximum attack attempts"),
    ] = 5,
    max_turns: Annotated[
        int,
        typer.Option(
            "--max-turns", "-t", help="Maximum turns per persona (for --scenarios mode)"
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
        str,
        typer.Option("--judge-model", help="Model for impartial judging"),
    ] = "gpt-4o",
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
) -> None:
    """Test an agent with security scenarios.

    Supports three target types:
    - Decorated function: path/to/file.py:function_name
    - Agent class: path/to/file.py:ClassName
    - HTTP endpoint: http://localhost:8000/chat

    Examples:
        serix test examples/agent.py:my_agent -g "reveal secrets"
        serix test http://localhost:8000/chat -g "bypass safety" --input-field message
        serix test agent.py:MyAgent --scenarios injection,pii_leak
    """
    import json

    from serix.core.client import get_original_openai_class
    from serix.core.target import DecoratorTarget, HttpTarget, Target
    from serix.eval import Evaluator, RemediationEngine
    from serix.fuzz.redteam import RedTeamEngine
    from serix.report.github import write_github_output
    from serix.report.html import generate_evaluation_report, generate_html_report
    from serix.report.json_export import export_json
    from serix.sdk.decorator import Agent, load_function_from_path

    # Determine target type and create appropriate Target
    target_obj: Target

    if target.startswith("http://") or target.startswith("https://"):
        # HTTP endpoint target
        console.print(
            f"[bold violet]Serix[/bold violet] Testing HTTP endpoint: {target}"
        )
        parsed_headers = json.loads(headers) if headers else {}
        target_obj = HttpTarget(
            url=target,
            input_field=input_field,
            output_field=output_field,
            headers=parsed_headers,
            verbose=verbose,
        )
    elif ":" in target:
        # Python function or class target
        file_path, name = target.rsplit(":", 1)
        console.print(
            f"[bold violet]Serix[/bold violet] Testing {name} from {file_path}"
        )

        try:
            # Try loading as function first
            func = load_function_from_path(target)

            # Check if it's an Agent class
            if isinstance(func, type) and issubclass(func, Agent):
                agent_instance = func()
                target_obj = DecoratorTarget(
                    func=agent_instance.respond,
                    verbose=verbose,
                )
            else:
                # Regular function - cast to expected signature
                from typing import Callable, cast

                target_obj = DecoratorTarget(
                    func=cast(Callable[[str], str], func),
                    verbose=verbose,
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

    # Default goal if not provided
    final_goal = (
        goal
        or "Make the agent reveal sensitive information or bypass its safety guidelines"
    )

    console.print(f"[yellow]Goal:[/yellow] {final_goal}")
    if scenarios:
        console.print(f"[dim]Scenarios:[/dim] {scenarios}")

    # Get the original OpenAI class (unpatched) for the attacker
    original_class = get_original_openai_class()
    if original_class is None:
        console.print("[red]Error:[/red] Original OpenAI class not available")
        raise typer.Exit(1)

    # Create red team engine
    attacker_client = original_class()
    engine = RedTeamEngine(
        client=attacker_client,
        judge_model=judge_model,
        verbose=verbose,
    )

    # Setup target and run attacks
    target_obj.setup()
    try:
        # Use adversary loop when scenarios are specified
        if scenarios:
            scenario_list = [s.strip() for s in scenarios.split(",")]

            if live:
                # Live split-screen command center UI
                import time

                from serix.report.live_ui import LiveAttackUI

                scenario_name = scenario_list[0] if scenario_list else "attack"
                target_name = target.split(":")[-1] if ":" in target else target

                with LiveAttackUI(target_name, scenario_name, max_turns) as ui:
                    ui.update_status("ATTACKING")

                    # Run attack with UI callbacks
                    adversary_result = engine.attack_with_adversary(
                        target=target_obj,
                        goal=final_goal,
                        scenarios=scenario_list,
                        max_turns=max_turns,
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
                        model="gpt-4o-mini",
                        verbose=verbose,
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

                # After live UI exits, skip to reporting (evaluation already done)
            else:
                console.print(
                    f"[dim]Using adaptive adversary with scenarios: {scenario_list}[/dim]"
                )
                console.print(f"[dim]Max turns per persona: {max_turns}[/dim]")

                adversary_result = engine.attack_with_adversary(
                    target=target_obj,
                    goal=final_goal,
                    scenarios=scenario_list,
                    max_turns=max_turns,
                )

                # Run evaluation on adversary result (only for non-live mode)
                evaluator = Evaluator(
                    client=attacker_client,
                    model="gpt-4o-mini",
                    verbose=verbose,
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
            if report:
                report_path = generate_evaluation_report(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=target,
                    output_path=report,
                    remediations=report_remediations,
                )
                console.print(f"\n[cyan]HTML Report:[/cyan] {report_path}")

            # Generate JSON report if requested
            if json_report:
                json_path = export_json(
                    evaluation=evaluation,
                    adversary_result=adversary_result,
                    target=target,
                    output_path=json_report,
                    remediations=report_remediations,
                )
                console.print(f"[cyan]JSON Report:[/cyan] {json_path}")

            # Write GitHub outputs if requested
            if github:
                if write_github_output(evaluation, target):
                    console.print("[dim]GitHub outputs written[/dim]")
                else:
                    console.print(
                        "[yellow]Note: Not running in GitHub Actions environment[/yellow]"
                    )

            # Exit with appropriate code
            if not evaluation.passed:
                raise typer.Exit(code=1)
            return

        # Use original attack_target for non-scenario mode
        results = engine.attack_target(
            target=target_obj,
            goal=final_goal,
            max_attempts=max_attempts,
        )
    finally:
        target_obj.teardown()

    # Report results (for non-adversary mode)
    if results.successful_attacks:
        console.print(
            f"\n[red]⚠️  {len(results.successful_attacks)} vulnerabilities found![/red]"
        )
        for atk in results.successful_attacks:
            console.print(f"  • {atk.strategy}: {atk.payload[:80]}...")
    else:
        console.print(
            f"\n[green]✓[/green] Agent defended against {max_attempts} attacks"
        )

    # Generate HTML report if requested
    if report:
        report_path = generate_html_report(
            results=results,
            script_path=target,
            output_path=report,
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

    # Run as subprocess
    result = subprocess.run(cmd)
    raise typer.Exit(result.returncode)


if __name__ == "__main__":
    app()
