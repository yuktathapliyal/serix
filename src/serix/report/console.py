"""Rich console reporting for Serix."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from serix.core.types import RecordingSession
from serix.fuzz.engine import FuzzResult
from serix.fuzz.redteam import Attack, AttackResults

console = Console()


def print_banner() -> None:
    """Print Serix banner."""
    banner = """
[bold cyan]  ____            _
 / ___|  ___ _ __(_)_  __
 \\___ \\ / _ \\ '__| \\ \\/ /
  ___) |  __/ |  | |>  <
 |____/ \\___|_|  |_/_/\\_\\[/bold cyan]

[dim]AI Agent Testing Framework[/dim]
"""
    console.print(banner)


def print_recording_summary(session: RecordingSession) -> None:
    """Print a summary of recorded interactions."""
    table = Table(title="Recording Summary", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Model", width=20)
    table.add_column("Messages", width=10)
    table.add_column("Latency", width=12)
    table.add_column("Tokens", width=10)

    for interaction in session.interactions:
        req = interaction.request
        resp = interaction.response
        tokens = resp.usage.get("total_tokens", "N/A") if resp.usage else "N/A"

        table.add_row(
            str(interaction.index),
            req.model,
            str(len(req.messages)),
            f"{interaction.latency_ms:.0f}ms",
            str(tokens),
        )

    console.print(table)
    console.print(
        f"\n[green]Total:[/green] {len(session.interactions)} interactions recorded"
    )


def print_fuzz_result(result: FuzzResult, index: int) -> None:
    """Print result of a single fuzz test."""
    if result.error_raised:
        status = "[red]ERROR[/red]"
        details = str(result.error_raised)
    elif result.mutations_applied:
        status = "[yellow]MUTATED[/yellow]"
        details = ", ".join(result.mutations_applied)
    else:
        status = "[green]CLEAN[/green]"
        details = "No mutations applied"

    console.print(f"  [{index}] {status}: {details}")


def print_fuzz_summary(results: list[FuzzResult]) -> None:
    """Print summary of fuzzing results."""
    total = len(results)
    mutated = sum(1 for r in results if r.mutations_applied)
    errors = sum(1 for r in results if r.error_raised)
    clean = total - mutated

    table = Table(title="Fuzzing Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", width=20)
    table.add_column("Count", width=10)
    table.add_column("Percentage", width=15)

    table.add_row("Total Requests", str(total), "100%")
    table.add_row(
        "Mutated",
        str(mutated),
        f"{(mutated/total)*100:.1f}%" if total > 0 else "0%",
    )
    table.add_row(
        "Errors Injected",
        str(errors),
        f"{(errors/total)*100:.1f}%" if total > 0 else "0%",
    )
    table.add_row(
        "Clean",
        str(clean),
        f"{(clean/total)*100:.1f}%" if total > 0 else "0%",
    )

    console.print(table)


def print_critical_vulnerability(attack: Attack) -> None:
    """Print dramatic vulnerability alert for demo."""
    console.print()
    console.print(
        Panel(
            "[bold white on red]  CRITICAL VULNERABILITY FOUND  [/bold white on red]",
            border_style="red",
            padding=(1, 4),
        )
    )
    console.print()
    console.print(f"[bold red]Strategy:[/bold red] {attack.strategy}")
    console.print("[bold red]Payload:[/bold red]")
    console.print(Panel(attack.payload, border_style="yellow"))
    console.print("[bold red]Agent Response:[/bold red]")
    console.print(Panel(attack.response or "[No response]", border_style="red"))


def print_attack_results(results: AttackResults) -> None:
    """Print red team attack results."""
    # Header
    panel_content = f"[bold]Goal:[/bold] {results.goal}\n"
    panel_content += f"[bold]Attempts:[/bold] {len(results.attacks)}\n"
    panel_content += f"[bold]Successful:[/bold] {len(results.successful_attacks)}"

    console.print(
        Panel(
            panel_content,
            title="[bold red]Red Team Results[/bold red]",
            border_style="red" if results.successful_attacks else "green",
        )
    )

    # Detailed table
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Strategy", width=20)
    table.add_column("Result", width=12)
    table.add_column("Payload Preview", width=40)

    for i, attack in enumerate(results.attacks):
        if attack.success:
            result_str = "[bold red]EXPLOITED[/bold red]"
        else:
            result_str = "[green]DEFENDED[/green]"
        payload_preview = (
            attack.payload[:37] + "..." if len(attack.payload) > 40 else attack.payload
        )

        table.add_row(str(i + 1), attack.strategy, result_str, payload_preview)

    console.print(table)

    # Final verdict
    if results.successful_attacks:
        console.print(
            f"\n[bold red]VULNERABLE:[/bold red] Agent was compromised by "
            f"{len(results.successful_attacks)} attack(s)"
        )
    else:
        console.print("\n[bold green]SECURE:[/bold green] Agent resisted all attacks")
