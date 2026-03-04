"""
Rich-based display rendering for CryptKit analysis reports.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text


def _conf_bar(confidence: float, width: int = 8) -> str:
    filled = int(confidence * width)
    empty = width - filled
    return f"[green]{'█' * filled}[/green][dim]{'░' * empty}[/dim] [cyan]{confidence:.0%}[/cyan]"


def _print_header(con: Console) -> None:
    con.print()
    con.print(Rule("[bold cyan][ CRYPTKIT ANALYSIS REPORT ][/bold cyan]", style="cyan"))
    con.print()


def _print_input_summary(report, con: Console) -> None:
    ent = report.entropy
    if ent > 7.0:
        ent_str = f"[red]{ent:.2f} bits[/red] (high — likely encrypted/compressed)"
    elif ent > 4.5:
        ent_str = f"[yellow]{ent:.2f} bits[/yellow] (medium)"
    else:
        ent_str = f"[green]{ent:.2f} bits[/green] (low — likely plaintext/structured)"

    mode_str = f"[bold]Mode:[/bold]    [cyan]{report.input_mode.upper()}[/cyan]"
    summary_str = f"[bold]Input:[/bold]   {report.input_summary}"
    entropy_str = f"[bold]Entropy:[/bold] {ent_str}"

    content = f"{mode_str}\n{summary_str}\n{entropy_str}"
    con.print(
        Panel(content, title="[bold white]INPUT SUMMARY[/bold white]",
              border_style="dim", expand=False)
    )
    con.print()


def _print_findings(report, con: Console) -> None:
    if not report.findings:
        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        expand=True,
    )
    table.add_column("Confidence", style="bold", width=28)
    table.add_column("Detection", style="yellow", width=22)
    table.add_column("Hint", style="white")

    for f in report.findings:
        bar = _conf_bar(f.confidence)
        table.add_row(bar, f.type, f.hint)

    con.print(
        Panel(table, title="[bold white]FINGERPRINT RESULTS[/bold white]",
              border_style="dim")
    )
    con.print()


def _is_hash_result(result) -> bool:
    return result.finding_type.startswith('hash_')


def _render_solver_result(result, con: Console, indent: int = 0) -> None:
    prefix = "  " * indent

    if indent > 0:
        depth_tag = f"[dim](depth {result.depth})[/dim] "
    else:
        depth_tag = ""

    if not result.success or result.decoded is None:
        con.print(f"{prefix}[dim]  - {result.solver_name} — no result[/dim]")
        return

    key_str = ""
    if result.key is not None:
        key_str = f"  key=[bold magenta]{result.key}[/bold magenta]"

    bar = _conf_bar(result.confidence)
    label_style = "[bold yellow]" if _is_hash_result(result) else "[bold green]"
    label_end = "[/bold yellow]" if _is_hash_result(result) else "[/bold green]"

    con.print(
        f"{prefix}  {depth_tag}"
        f"{label_style}>[/{label_style[1:]} "
        f"[bold]{result.solver_name}[/bold]{key_str}  {bar}"
    )

    panel_title = (
        "[bold yellow]>> IDENTIFIED[/bold yellow]"
        if _is_hash_result(result)
        else "[bold green]>> DECODED[/bold green]"
    )
    panel_style = "yellow" if _is_hash_result(result) else "green"

    decoded_preview = (result.decoded or "")[:200]
    con.print(
        Panel(decoded_preview,
              title=panel_title,
              border_style=panel_style,
              expand=True)
    )

    # Render children (recursive depth)
    for child in result.children:
        _render_solver_result(child, con, indent + 1)


def _print_solver_results(report, con: Console) -> None:
    con.print(Rule("[bold white]SOLVER OUTPUT[/bold white]", style="white"))
    con.print()

    if not report.solver_results:
        con.print(
            Panel(
                "[ NO SOLUTION FOUND — MANUAL ANALYSIS REQUIRED ]\n"
                "Try: hashcat / john for hashes, stegsolve for images, "
                "CyberChef for visual inspection",
                border_style="dim",
                expand=True,
            )
        )
        return

    # Group by finding_type for section headers
    current_type = None
    for result in report.solver_results:
        ftype = result.finding_type.upper().replace('_', ' ')
        if ftype != current_type:
            current_type = ftype
            con.print(Rule(f"[bold yellow]{ftype}[/bold yellow]", style="yellow"))
        _render_solver_result(result, con)

    con.print()


def _print_footer(report, con: Console) -> None:
    elapsed = report.stats.get('elapsed_s', 0.0)
    n_run = report.stats.get('solvers_run', 0)
    n_hits = sum(1 for r in report.solver_results if r.success)
    con.print(Rule(style="dim"))
    con.print(
        f"[dim]  {n_run} solver(s) run  |  {n_hits} hit(s)  |  {elapsed:.3f}s[/dim]"
    )
    con.print()


def render_report(report, con: Console) -> None:
    _print_header(con)
    _print_input_summary(report, con)
    _print_findings(report, con)
    _print_solver_results(report, con)
    _print_footer(report, con)
