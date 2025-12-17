"""Rich console reporting for Serix."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from serix.core.types import RecordingSession
from serix.fuzz.engine import FuzzResult
from serix.fuzz.redteam import Attack, AttackResults

console = Console()


def get_severity_color(severity: str) -> str:
    """Get Rich color for severity level."""
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold blue",
        "INFO": "dim",
    }
    return severity_colors.get(severity.upper(), "white")


# Dangerous tool keywords for sandbox detection
DANGEROUS_TOOL_KEYWORDS = {
    "delete",
    "remove",
    "destroy",
    "drop",
    "truncate",
    "rm",
    "rmdir",
    "unlink",
    "purge",
    "wipe",
    "erase",
    "kill",
    "terminate",
    "shutdown",
    "format",
}


def is_dangerous_tool(tool_name: str) -> bool:
    """Check if a tool name indicates a dangerous/destructive operation.

    Args:
        tool_name: The name of the tool being called (e.g., "mcp:github/delete_repository")

    Returns:
        True if the tool appears to be destructive
    """
    name_lower = tool_name.lower()

    # Check for dangerous keywords
    for keyword in DANGEROUS_TOOL_KEYWORDS:
        if keyword in name_lower:
            return True

    return False


def log_blocked_action(tool_name: str, args: dict | None = None) -> None:
    """Display a prominent visual panel when a dangerous tool call is blocked.

    Args:
        tool_name: Name of the tool that was blocked
        args: Arguments that were passed to the tool
    """
    import json

    # Format args for display
    args_str = ""
    if args:
        try:
            args_str = json.dumps(args, indent=2)
        except (TypeError, ValueError):
            args_str = str(args)

    # Build the panel content
    panel_lines = [
        "[bold red]SERIX SANDBOX: BLOCKED DESTRUCTIVE ACTION[/bold red]",
        "",
        f"[bold yellow]Tool:[/bold yellow] {tool_name}",
    ]

    if args_str:
        panel_lines.append("[bold yellow]Args:[/bold yellow]")
        # Truncate args if too long
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."
        panel_lines.append(f"[dim]{args_str}[/dim]")

    panel_lines.extend(
        [
            "",
            "[green]This action was intercepted by Serix.[/green]",
            "[green]No side effects occurred.[/green]",
        ]
    )

    console.print()
    console.print(
        Panel(
            "\n".join(panel_lines),
            title="[bold red]SANDBOX INTERCEPT[/bold red]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()


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


def print_critical_vulnerability(
    attack: Attack, vulnerability_type: str = "jailbreak"
) -> None:
    """Print dramatic vulnerability alert for demo with OWASP information."""
    from serix.eval.classifier import get_owasp_info

    # Get OWASP info based on attack strategy/type
    owasp = get_owasp_info(vulnerability_type)

    console.print()
    console.print(
        Panel(
            "[bold white on red]  CRITICAL VULNERABILITY FOUND  [/bold white on red]",
            border_style="red",
            padding=(1, 4),
        )
    )
    console.print()

    # Build vulnerability tree
    vuln_tree = Tree("[bold red]VULNERABILITY DETAILS[/bold red]")
    vuln_tree.add("[bold]Type:[/bold] Prompt Injection")
    vuln_tree.add(f"[bold]Strategy:[/bold] {attack.strategy}")

    # Add OWASP badge if available
    if owasp:
        severity_color = get_severity_color(owasp.severity)
        owasp_node = vuln_tree.add(
            f"[bold]OWASP:[/bold] [{severity_color}][{owasp.code}] {owasp.name} ({owasp.severity})[/{severity_color}]"
        )
        owasp_node.add(f"[dim]{owasp.description}[/dim]")

    console.print(vuln_tree)
    console.print()
    console.print("[bold red]Attack Payload:[/bold red]")
    console.print(Panel(attack.payload, border_style="yellow"))
    console.print("[bold red]Agent Response:[/bold red]")
    console.print(Panel(attack.response or "[No response]", border_style="red"))


def print_attack_results(
    results: AttackResults, vulnerability_type: str = "jailbreak"
) -> None:
    """Print red team attack results with OWASP classification."""
    from serix.eval.classifier import get_owasp_info

    owasp = get_owasp_info(vulnerability_type)

    # Header with OWASP info
    panel_content = f"[bold]Goal:[/bold] {results.goal}\n"
    panel_content += f"[bold]Attempts:[/bold] {len(results.attacks)}\n"
    panel_content += f"[bold]Successful:[/bold] {len(results.successful_attacks)}"

    if owasp and results.successful_attacks:
        severity_color = get_severity_color(owasp.severity)
        panel_content += (
            f"\n[bold]OWASP:[/bold] [{severity_color}][{owasp.code}] "
            f"{owasp.name}[/{severity_color}]"
        )

    console.print(
        Panel(
            panel_content,
            title="[bold red]Red Team Results[/bold red]",
            border_style="red" if results.successful_attacks else "green",
        )
    )

    # Detailed table with OWASP column
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Strategy", width=18)
    table.add_column("OWASP", width=8)
    table.add_column("Result", width=12)
    table.add_column("Payload Preview", width=35)

    for i, attack in enumerate(results.attacks):
        if attack.success:
            result_str = "[bold red]EXPLOITED[/bold red]"
            owasp_code = owasp.code if owasp else "N/A"
        else:
            result_str = "[green]DEFENDED[/green]"
            owasp_code = "-"
        payload_preview = (
            attack.payload[:32] + "..." if len(attack.payload) > 35 else attack.payload
        )

        table.add_row(
            str(i + 1), attack.strategy, owasp_code, result_str, payload_preview
        )

    console.print(table)

    # Final verdict with OWASP context
    if results.successful_attacks:
        verdict = (
            f"\n[bold red]VULNERABLE:[/bold red] Agent was compromised by "
            f"{len(results.successful_attacks)} attack(s)"
        )
        if owasp:
            verdict += f"\n[dim]Classification: {owasp.code} - {owasp.name}[/dim]"
        console.print(verdict)
    else:
        console.print("\n[bold green]SECURE:[/bold green] Agent resisted all attacks")
