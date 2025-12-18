"""Rich console reporting for Serix."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from serix.core.types import RecordingSession
from serix.fuzz.engine import FuzzResult
from serix.fuzz.redteam import Attack, AttackResults

if TYPE_CHECKING:
    from serix.heal.types import HealingResult

console = Console()


def get_severity_color(severity: str) -> str:
    """Get Rich color for severity level.

    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    Returns:
        Rich color string for the severity
    """
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


def parse_mcp_tool(tool_name: str) -> tuple[str | None, str]:
    """Parse 'mcp__server__tool' format into (server, tool).

    Args:
        tool_name: Tool name, possibly in MCP format

    Returns:
        Tuple of (server, tool) or (None, tool_name) if not MCP format
    """
    if tool_name.startswith("mcp__"):
        # Format: mcp__server__tool_name
        parts = tool_name[5:].split("__", 1)  # Remove "mcp__" prefix
        if len(parts) == 2:
            return parts[0], parts[1]
    return None, tool_name


def is_dangerous_tool(tool_name: str) -> bool:
    """Check if a tool name indicates a dangerous/destructive operation.

    Args:
        tool_name: The name of the tool being called (e.g., "mcp:github/delete_repository")

    Returns:
        True if the tool appears to be destructive
    """
    name_lower = tool_name.lower()

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

    # Parse MCP format if present
    server, parsed_tool = parse_mcp_tool(tool_name)
    is_mcp = server is not None

    # Format args for display
    args_str = ""
    if args:
        try:
            args_str = json.dumps(args, indent=2)
        except (TypeError, ValueError):
            args_str = str(args)

    # Build the panel content with MCP-aware formatting
    if is_mcp:
        panel_lines = [
            "[bold red]SERIX SANDBOX: BLOCKED MCP ACTION[/bold red]",
            "",
            f"[bold yellow]Server:[/bold yellow] {server}",
            f"[bold yellow]Tool:[/bold yellow] {parsed_tool}",
        ]
    else:
        panel_lines = [
            "[bold red]SERIX SANDBOX: BLOCKED DESTRUCTIVE ACTION[/bold red]",
            "",
            f"[bold yellow]Tool:[/bold yellow] {tool_name}",
        ]

    if args_str:
        panel_lines.append("[bold yellow]Args:[/bold yellow]")
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
    """Print Serix banner to console."""
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
    """Print a summary of recorded interactions.

    Args:
        session: The recording session to summarize
    """
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
    """Print result of a single fuzz test.

    Args:
        result: The fuzz test result
        index: Test index for display
    """
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
    """Print summary of fuzzing results.

    Args:
        results: List of fuzz test results
    """
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
    """Print dramatic vulnerability alert for demo with OWASP information.

    Args:
        attack: The successful attack to display
        vulnerability_type: Type of vulnerability for OWASP lookup
    """
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
    """Print red team attack results with OWASP classification.

    Args:
        results: Attack results to display
        vulnerability_type: Type of vulnerability for OWASP lookup
    """
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


# Maximum lines to show in CLI diff (truncate if longer)
MAX_DIFF_LINES_CLI = 50


def print_healing_result(healing: "HealingResult") -> None:
    """Print healing result with diff and tool fixes.

    Args:
        healing: HealingResult from the Self-Healing engine
    """
    console.print()
    console.print(
        Panel(
            "[bold cyan]SELF-HEALING PROPOSAL[/bold cyan]",
            border_style="cyan",
            padding=(0, 2),
        )
    )

    # Show confidence and OWASP code
    confidence_pct = int(healing.confidence * 100)
    console.print(
        f"\n[dim]Confidence:[/dim] {confidence_pct}%  "
        f"[dim]OWASP:[/dim] {healing.owasp_code}  "
        f"[dim]Type:[/dim] {healing.vulnerability_type}"
    )

    # Text Fix (System Prompt Diff)
    if healing.text_fix:
        console.print("\n[bold green]TEXT FIX (System Prompt):[/bold green]")
        console.print(f"[dim]{healing.text_fix.explanation}[/dim]")

        diff_text = healing.text_fix.diff
        diff_lines = diff_text.split("\n")

        # Truncate if too long for CLI
        if len(diff_lines) > MAX_DIFF_LINES_CLI:
            truncated_diff = "\n".join(diff_lines[:MAX_DIFF_LINES_CLI])
            truncated_diff += (
                f"\n... ({len(diff_lines) - MAX_DIFF_LINES_CLI} more lines)"
            )
            diff_text = truncated_diff

        # Display diff with syntax highlighting
        if diff_text.strip():
            syntax = Syntax(
                diff_text,
                "diff",
                theme="monokai",
                line_numbers=False,
                word_wrap=True,
            )
            console.print(
                Panel(
                    syntax,
                    title="[bold]Unified Diff[/bold]",
                    border_style="green",
                    padding=(0, 1),
                )
            )
        else:
            console.print("[dim]No diff generated[/dim]")

    else:
        console.print(
            "\n[yellow]No text fix available (system_prompt required)[/yellow]"
        )

    # Tool Fixes (Policy Recommendations)
    if healing.tool_fixes:
        console.print("\n[bold blue]TOOL FIXES (Policy):[/bold blue]")

        tool_tree = Tree("[bold]Recommendations[/bold]")
        for fix in healing.tool_fixes:
            # Color-code by severity
            if fix.severity == "required":
                severity_badge = "[bold red][REQUIRED][/bold red]"
            elif fix.severity == "recommended":
                severity_badge = "[bold yellow][RECOMMENDED][/bold yellow]"
            else:
                severity_badge = "[dim][OPTIONAL][/dim]"

            node_text = f"{severity_badge} {fix.recommendation}"
            if fix.owasp_code:
                node_text += f" [dim]({fix.owasp_code})[/dim]"

            tool_tree.add(node_text)

        console.print(tool_tree)

    console.print()


def print_healing_summary(healing: "HealingResult") -> None:
    """Print a compact summary of healing result.

    Args:
        healing: HealingResult from the Self-Healing engine
    """
    if not healing:
        return

    console.print()
    console.print("[cyan]Fix suggestions generated.[/cyan]", end=" ")

    fix_count = 0
    if healing.text_fix:
        fix_count += 1
    fix_count += len(healing.tool_fixes)

    console.print(f"[dim]({fix_count} recommendations)[/dim]")


# Regression testing output functions


def print_immune_check_start(count: int) -> None:
    """Print the start of the Immune Check phase.

    Args:
        count: Number of stored attacks to replay
    """
    console.print()
    console.print(
        f"[bold cyan]🛡️ Immune Check:[/bold cyan] Replaying {count} stored attack(s)..."
    )


def print_immune_check_result(passed: int, total: int) -> None:
    """Print the result of the Immune Check.

    Args:
        passed: Number of attacks defended
        total: Total attacks checked
    """
    if passed == total:
        console.print(
            f"[green]✓ {passed}/{total} defended[/green] "
            "[dim](previously vulnerable payloads)[/dim]"
        )
    else:
        failed = total - passed
        console.print(f"[red]✗ {failed}/{total} still vulnerable[/red]")


def print_regression_failure(
    failed_attacks: list,
    fail_fast: bool = True,
) -> None:
    """Print detailed regression failure information.

    Args:
        failed_attacks: List of StoredAttack objects that still succeed
        fail_fast: Whether we stopped early due to fail-fast
    """
    console.print()
    console.print(
        Panel(
            "[bold red]REGRESSION DETECTED[/bold red]",
            border_style="red",
            padding=(0, 2),
        )
    )

    for attack in failed_attacks[:3]:  # Show max 3
        console.print()
        console.print(f"[bold yellow]Attack:[/bold yellow] {attack.id}")
        payload_preview = (
            attack.payload[:80] + "..." if len(attack.payload) > 80 else attack.payload
        )
        console.print(f"[bold yellow]Payload:[/bold yellow] {payload_preview}")
        console.print("[bold yellow]Status:[/bold yellow] [red]STILL VULNERABLE[/red]")

    if len(failed_attacks) > 3:
        console.print(f"\n[dim]...and {len(failed_attacks) - 3} more[/dim]")

    console.print()
    if fail_fast:
        console.print("[dim]Fix these regressions before running new attacks.[/dim]")


def print_attacks_saved(count: int) -> None:
    """Print confirmation of saved attacks.

    Args:
        count: Number of attacks saved
    """
    if count > 0:
        console.print(
            f"\n[dim]📦 Saved {count} new attack(s) to .serix/attacks.json[/dim]"
        )
