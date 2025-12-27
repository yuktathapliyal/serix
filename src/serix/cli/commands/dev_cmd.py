"""Dev command implementation.

Provides the `serix dev` command for running scripts with OpenAI interception.
Consolidates the legacy run/record/replay commands into a unified interface.

Modes:
- Default (passthrough): Run script normally, intercept for logging
- --capture: Record all API interactions to JSON
- --playback: Replay from recorded file (no API calls)
- --fuzz-*: Inject faults for resilience testing
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from ...core.types import SerixMode
from ...ui import render
from ...workflows.dev_workflow import DevWorkflow
from ..output.static import StaticRenderer

console = Console()


def dev_command(
    script: Annotated[
        Path,
        typer.Argument(help="Python script to run"),
    ],
    capture: Annotated[
        Path | None,
        typer.Option(
            "--capture",
            "-c",
            help="Capture API interactions to file (auto-generated if path not specified)",
        ),
    ] = None,
    playback: Annotated[
        Path | None,
        typer.Option(
            "--playback",
            "-p",
            help="Replay API responses from recording file",
        ),
    ] = None,
    fuzz: Annotated[
        bool,
        typer.Option(
            "--fuzz",
            help="Enable all fuzzing mutations",
        ),
    ] = False,
    fuzz_latency: Annotated[
        bool,
        typer.Option(
            "--fuzz-latency",
            help="Inject random latency to API calls",
        ),
    ] = False,
    fuzz_errors: Annotated[
        bool,
        typer.Option(
            "--fuzz-errors",
            help="Inject HTTP errors (429, 500, 503)",
        ),
    ] = False,
    fuzz_json: Annotated[
        bool,
        typer.Option(
            "--fuzz-json",
            help="Corrupt JSON responses",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "-v",
            "--verbose",
            help="Verbose output",
        ),
    ] = False,
) -> None:
    """Run a script with OpenAI API interception.

    Modes:

    - Default: Passthrough (intercept and log only)

    - --capture: Record all API interactions to JSON

    - --playback: Replay from recorded file (no API calls)

    - --fuzz-*: Inject faults for resilience testing

    Examples:

        serix dev my_agent.py

        serix dev my_agent.py --capture recording.json

        serix dev my_agent.py --playback recording.json

        serix dev my_agent.py --fuzz
    """
    # Validate incompatible flags
    has_capture = capture is not None
    has_playback = playback is not None
    has_fuzz = fuzz or fuzz_latency or fuzz_errors or fuzz_json

    if has_playback and has_capture:
        render.error(console, "--playback cannot be used with --capture")
        raise typer.Exit(1)

    if has_playback and has_fuzz:
        render.error(console, "--playback cannot be used with --fuzz-* flags")
        raise typer.Exit(1)

    # Create workflow
    renderer = StaticRenderer()
    workflow = DevWorkflow(
        event_listener=renderer,
        verbose=verbose,
    )

    # Determine mode and run
    if has_playback:
        assert playback is not None
        render.section_header(console, f"Replaying {script.name}")
        render.kv(console, "Script", str(script), label_width=10)
        render.kv(console, "Recording", str(playback), label_width=10)
        console.print()
        result = workflow.run_playback(script, playback)

    elif has_fuzz:
        render.section_header(console, f"Fuzzing {script.name}")
        render.kv(console, "Script", str(script), label_width=10)
        mutations = []
        if fuzz or fuzz_latency:
            mutations.append("latency")
        if fuzz or fuzz_errors:
            mutations.append("errors")
        if fuzz or fuzz_json:
            mutations.append("json")
        render.kv(console, "Mutations", ", ".join(mutations), label_width=10)
        console.print()
        result = workflow.run_fuzz(
            script,
            enable_latency=fuzz or fuzz_latency,
            enable_errors=fuzz or fuzz_errors,
            enable_json_corruption=fuzz or fuzz_json,
        )

    elif has_capture:
        render.section_header(console, f"Capturing {script.name}")
        render.kv(console, "Script", str(script), label_width=10)
        if capture:
            render.kv(console, "Output", str(capture), label_width=10)
        else:
            render.kv(console, "Output", "(auto-generated)", label_width=10)
        console.print()
        result = workflow.run_capture(script, capture)

    else:
        render.section_header(console, f"Running {script.name}")
        render.kv(console, "Script", str(script), label_width=10)
        render.kv(console, "Mode", "passthrough", label_width=10)
        console.print()
        result = workflow.run_passthrough(script)

    # Display result
    console.print()  # Blank line before result

    if result.success:
        if result.recording_path:
            render.success(
                console,
                f"Recorded {result.interaction_count} interactions to {result.recording_path}",
            )
        elif result.mode == SerixMode.REPLAY:
            render.success(
                console,
                f"Replayed {result.interaction_count} interactions",
            )
        elif result.mode == SerixMode.FUZZ:
            render.success(console, "Fuzz run completed")
        else:
            render.success(console, "Completed successfully")
    else:
        render.error(console, result.error or "Script execution failed")
        raise typer.Exit(result.exit_code)
