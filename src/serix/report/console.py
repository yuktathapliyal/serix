"""Rich console reporting for Serix."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from serix.core.types import RecordingSession
from serix.fuzz.engine import FuzzResult
from serix.fuzz.redteam import Attack, AttackResults
from serix.ui import BULLET, FAILURE, SEPARATOR, SUCCESS, get_console

if TYPE_CHECKING:
    from serix.heal.types import HealingResult

console = get_console()


def get_severity_color(severity: str) -> str:
    """Get Rich color for severity level."""
    severity_colors = {
        "CRITICAL": "serix.bad",
        "HIGH": "serix.warn",
        "MEDIUM": "serix.label",
        "LOW": "serix.muted",
        "INFO": "serix.muted",
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
            "[serix.bad]SERIX SANDBOX: BLOCKED MCP ACTION[/]",
            "",
            f"[serix.warn]Server:[/] {server}",
            f"[serix.warn]Tool:[/] {parsed_tool}",
        ]
    else:
        panel_lines = [
            "[serix.bad]SERIX SANDBOX: BLOCKED DESTRUCTIVE ACTION[/]",
            "",
            f"[serix.warn]Tool:[/] {tool_name}",
        ]

    if args_str:
        panel_lines.append("[serix.warn]Args:[/]")
        if len(args_str) > 200:
            args_str = args_str[:200] + "..."
        panel_lines.append(f"[serix.muted]{args_str}[/]")

    panel_lines.extend(
        [
            "",
            f"[serix.ok]{SUCCESS} This action was intercepted by Serix.[/]",
            f"[serix.ok]{SUCCESS} No side effects occurred.[/]",
        ]
    )

    console.print()
    console.print(
        Panel(
            "\n".join(panel_lines),
            title="[serix.bad]SANDBOX INTERCEPT[/]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()


def print_banner() -> None:
    """Print Serix banner to console."""
    from serix import __version__
    from serix.ui import render

    render.banner(console, __version__)


def print_recording_summary(session: RecordingSession) -> None:
    """Print a summary of recorded interactions."""
    table = Table(
        title="Recording Summary", show_header=True, header_style="serix.label"
    )
    table.add_column("#", style="serix.muted", width=4)
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
        f"\n[serix.ok]{SUCCESS}[/] {len(session.interactions)} interactions recorded"
    )


def print_fuzz_result(result: FuzzResult, index: int) -> None:
    """Print result of a single fuzz test."""
    if result.error_raised:
        status = f"[serix.bad]{FAILURE} ERROR[/]"
        details = str(result.error_raised)
    elif result.mutations_applied:
        status = "[serix.warn]MUTATED[/]"
        details = ", ".join(result.mutations_applied)
    else:
        status = f"[serix.ok]{SUCCESS} CLEAN[/]"
        details = "No mutations applied"

    console.print(f"  [{index}] {status}: {details}")


def print_fuzz_summary(results: list[FuzzResult]) -> None:
    """Print summary of fuzzing results."""
    total = len(results)
    mutated = sum(1 for r in results if r.mutations_applied)
    errors = sum(1 for r in results if r.error_raised)
    clean = total - mutated

    table = Table(title="Fuzzing Summary", show_header=True, header_style="serix.label")
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
            "[serix.bad]CRITICAL VULNERABILITY FOUND[/]",
            border_style="red",
            padding=(1, 4),
        )
    )
    console.print()

    # Build vulnerability tree
    vuln_tree = Tree("[serix.bad]VULNERABILITY DETAILS[/]")
    vuln_tree.add("Type: Prompt Injection")
    vuln_tree.add(f"Strategy: {attack.strategy}")

    # Add OWASP badge if available
    if owasp:
        severity_color = get_severity_color(owasp.severity)
        owasp_node = vuln_tree.add(
            f"OWASP: [{severity_color}][{owasp.code}] {owasp.name} ({owasp.severity})[/]"
        )
        owasp_node.add(f"[serix.muted]{owasp.description}[/]")

    console.print(vuln_tree)
    console.print()
    console.print("[serix.bad]Attack Payload:[/]")
    console.print(Panel(attack.payload, border_style="yellow"))
    console.print("[serix.bad]Agent Response:[/]")
    console.print(Panel(attack.response or "[No response]", border_style="red"))


def print_attack_results(
    results: AttackResults, vulnerability_type: str = "jailbreak"
) -> None:
    """Print red team attack results with OWASP classification."""
    from serix.eval.classifier import get_owasp_info

    owasp = get_owasp_info(vulnerability_type)

    # Header with OWASP info
    panel_content = f"Goal: {results.goal}\n"
    panel_content += f"Attempts: {len(results.attacks)}\n"
    panel_content += f"Successful: {len(results.successful_attacks)}"

    if owasp and results.successful_attacks:
        severity_color = get_severity_color(owasp.severity)
        panel_content += f"\nOWASP: [{severity_color}][{owasp.code}] {owasp.name}[/]"

    console.print(
        Panel(
            panel_content,
            title="[serix.bad]Red Team Results[/]",
            border_style="red" if results.successful_attacks else "green",
        )
    )

    # Detailed table with OWASP column
    table = Table(show_header=True, header_style="serix.label")
    table.add_column("#", style="serix.muted", width=4)
    table.add_column("Strategy", width=18)
    table.add_column("OWASP", width=8)
    table.add_column("Result", width=12)
    table.add_column("Payload Preview", width=35)

    for i, attack in enumerate(results.attacks):
        if attack.success:
            result_str = f"[serix.bad]{FAILURE} EXPLOITED[/]"
            owasp_code = owasp.code if owasp else "N/A"
        else:
            result_str = f"[serix.ok]{SUCCESS} DEFENDED[/]"
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
            f"\n[serix.bad]VULNERABLE:[/] Agent was compromised by "
            f"{len(results.successful_attacks)} attack(s)"
        )
        if owasp:
            verdict += f"\n[serix.muted]Classification: {owasp.code} - {owasp.name}[/]"
        console.print(verdict)
    else:
        console.print(f"\n[serix.ok]{SUCCESS} SECURE:[/] Agent resisted all attacks")


# Maximum lines to show in CLI diff (truncate if longer)
MAX_DIFF_LINES_CLI = 50


def print_healing_result(healing: "HealingResult") -> None:
    """Print healing result with diff and tool fixes.

    Visually isolated with separator for clear hierarchy.
    """
    # Visual separator to isolate this section
    console.print()
    console.print("[serix.rule]────────────────────────────────────────[/]")

    # Header with confidence inline
    confidence_pct = int(healing.confidence * 100)
    console.print(
        f"[serix.label]Self-Healing Proposal[/] "
        f"[serix.muted](Confidence: {confidence_pct}%)[/]"
    )
    console.print()

    # Classification line
    console.print(
        f"[serix.muted]Classification:[/] OWASP {healing.owasp_code} {BULLET} "
        f"Type: {healing.vulnerability_type}"
    )

    # Text Fix (System Prompt Diff)
    if healing.text_fix:
        console.print("\n[serix.label]Suggested Fix (System Prompt):[/]")
        console.print(f"[serix.muted]{healing.text_fix.explanation}[/]")

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
                    title="Unified Diff",
                    border_style="green",
                    padding=(0, 1),
                )
            )
        else:
            console.print("[serix.muted]No diff generated[/]")

    else:
        console.print("\n[serix.warn]No text fix available (system_prompt required)[/]")

    # Policy Recommendations
    if healing.tool_fixes:
        console.print("\n[serix.label]Recommendations:[/]")

        tool_tree = Tree("")
        for fix in healing.tool_fixes:
            # Color-code by severity
            if fix.severity == "required":
                severity_badge = "[serix.bad][REQUIRED][/]"
            elif fix.severity == "recommended":
                severity_badge = "[serix.warn][RECOMMENDED][/]"
            else:
                severity_badge = "[serix.muted][OPTIONAL][/]"

            node_text = f"{severity_badge} {fix.recommendation}"
            if fix.owasp_code:
                node_text += f" [serix.muted]({fix.owasp_code})[/]"

            tool_tree.add(node_text)

        console.print(tool_tree)

    console.print()


def print_healing_summary(healing: "HealingResult") -> None:
    """Print a compact summary of healing result."""
    if not healing:
        return

    console.print()
    console.print("[serix.label]Fix suggestions generated.[/]", end=" ")

    fix_count = 0
    if healing.text_fix:
        fix_count += 1
    fix_count += len(healing.tool_fixes)

    console.print(f"[serix.muted]({fix_count} recommendations)[/]")


# Regression testing output functions


def print_immune_check_start(
    count: int, total_stored: int | None = None, skipped: int | None = None
) -> None:
    """Print the start of the Immune Check phase."""
    console.print()
    if skipped and total_stored and skipped > 0:
        console.print(
            f"[serix.label]Immune Check:[/] Replaying {count} of {total_stored} "
            f"stored attacks ({skipped} mitigated, skipped)..."
        )
    else:
        console.print(
            f"[serix.label]Immune Check:[/] Replaying {count} stored attack(s)..."
        )


def print_immune_check_result(
    passed: int, total: int, planned: int | None = None
) -> None:
    """Print the result of the Immune Check.

    Uses red sparingly - only the word FAILED is red, not the entire line.
    """
    if passed == total:
        console.print(
            f"[serix.label]Immune Check:[/] [serix.ok]PASSED[/] "
            f"({passed}/{total} defended)"
        )
    else:
        failed = total - passed
        console.print(
            f"[serix.label]Immune Check:[/] [serix.bad]FAILED[/] "
            f"({failed}/{total} exploits reproduced)"
        )


def print_regression_failure(
    failed_attacks: list,
    fail_fast: bool = True,
    will_prompt: bool = False,
) -> None:
    """Print regression failure information.

    Uses bold red text (no panel border) for a cleaner, less alarming look.
    Shows a single explanation line instead of per-attack details.

    Args:
        failed_attacks: List of attacks that are still exploitable
        fail_fast: Whether --fail-fast flag is set (unused, kept for API compat)
        will_prompt: Whether user will be prompted to continue (unused)
    """
    console.print()
    console.print("[bold red]REGRESSION DETECTED[/bold red]")
    console.print("[serix.muted]Previously mitigated vulnerability has resurfaced.[/]")

    # Show count of failed attacks
    if len(failed_attacks) > 1:
        console.print(
            f"[serix.muted]{len(failed_attacks)} stored attacks are still exploitable.[/]"
        )
    console.print(f"[serix.rule]{SEPARATOR}[/]")


def print_attacks_saved(count: int) -> None:
    """Print confirmation of saved attacks."""
    if count > 0:
        console.print(
            f"\n[serix.muted]Saved {count} new attack(s) to .serix/attacks.json[/]"
        )
