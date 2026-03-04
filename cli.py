"""
CryptKit CLI entry point.
"""
import json
import math
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.text import Text
from rich.panel import Panel

# Ensure UTF-8 on Windows so Rich box-drawing characters render correctly.
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

__version__ = "0.1"

BANNER = r"""
  ____ ____  ___ _____ _____ _  _____ _____
 / ___|  _ \\ \ / /  _|_   _| |/ /_ _|_   _|
| |   | |_) \\ V /| |_  | | | ' / | |  | |
| |___|  _ <  | | |  _| | | | . \ | |  | |
 \____|_| \_\ |_| |_|   |_| |_|\_|___| |_|
"""


def _make_console(output_path: str | None = None, force_plain: bool = False) -> Console:
    """Create the Rich Console, optionally writing to a file."""
    if output_path:
        fh = open(output_path, "w", encoding="utf-8")
        return Console(file=fh, highlight=False, no_color=True)
    return Console(highlight=False, force_terminal=not force_plain)


def _print_banner(con: Console) -> None:
    con.print(Text(BANNER, style="bold cyan"))
    con.print(
        Panel(
            f"[bold white]v{__version__}[/bold white]  "
            "[dim]— cryptography and steganography tool kit[/dim]",
            border_style="cyan",
            expand=False,
        )
    )
    con.print()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _report_to_dict(report) -> dict:
    """Serialise an AnalysisReport to a plain dict for JSON output."""
    def _result_to_dict(r) -> dict:
        return {
            "finding_type": r.finding_type,
            "solver": r.solver_name,
            "success": r.success,
            "confidence": round(r.confidence, 3),
            "decoded": r.decoded,
            "key": r.key,
            "depth": r.depth,
            "children": [_result_to_dict(c) for c in r.children],
        }

    return {
        "version": __version__,
        "input": {
            "mode": report.input_mode,
            "summary": report.input_summary,
            "entropy": round(report.entropy, 3),
        },
        "findings": [
            {"type": f.type, "confidence": round(f.confidence, 3), "hint": f.hint}
            for f in report.findings
        ],
        "results": [_result_to_dict(r) for r in report.solver_results],
        "stats": {
            "solvers_run": report.stats.get("solvers_run", 0),
            "elapsed_s": round(report.stats.get("elapsed_s", 0.0), 4),
        },
    }


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="cryptkit")
@click.option("--text",    "-t", default=None, help="Raw text input to analyse")
@click.option("--file",    "-f", "file_path", default=None, help="Path to file to analyse")
@click.option("--hex",     "-x", "hex_input", default=None,
              help="Hex string to analyse (e.g. deadbeef)")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show each solver as it runs")
@click.option("--output",  "-o", default=None,
              help="Save report to this file (plain text, no colour)")
@click.option("--json",    "-j", "as_json", is_flag=True, default=False,
              help="Output raw JSON instead of styled report")
def main(
    text: str | None,
    file_path: str | None,
    hex_input: str | None,
    verbose: bool,
    output: str | None,
    as_json: bool,
) -> None:
    """CryptKit — fingerprint and solve CTF crypto/stego challenges."""
    from core.fingerprint import fingerprint
    from core.pipeline import run_pipeline
    from core.result import AnalysisReport
    from utils.display import render_report

    con = _make_console(output_path=output)
    if not as_json:
        _print_banner(con)

    # --- Input validation ---
    inputs_given = sum(x is not None for x in [text, file_path, hex_input])
    if inputs_given == 0:
        con.print("[bold red][!][/bold red] No input provided. "
                  "Use --text, --file, or --hex.")
        raise SystemExit(1)
    if inputs_given > 1:
        con.print("[bold red][!][/bold red] Provide only one input mode at a time.")
        raise SystemExit(1)

    # --- Resolve input ---
    if text is not None:
        if not text.strip():
            con.print("[bold red][!][/bold red] Input text is empty.")
            raise SystemExit(1)
        raw = text
        mode = "text"
        summary = f"{len(text)} chars"
        entropy = _entropy(text.encode("utf-8", errors="replace"))

    elif file_path is not None:
        fp = Path(file_path)
        if not fp.exists():
            con.print(f"[bold red][!][/bold red] File not found: {file_path}")
            raise SystemExit(1)
        if fp.stat().st_size == 0:
            con.print(f"[bold red][!][/bold red] File is empty: {file_path}")
            raise SystemExit(1)
        raw = fp
        mode = "file"
        summary = f"{file_path}  ({fp.stat().st_size:,} bytes)"
        entropy = _entropy(fp.read_bytes()[:8192])

    else:
        stripped_hex = hex_input.strip().replace(" ", "")
        if not stripped_hex:
            con.print("[bold red][!][/bold red] Hex input is empty.")
            raise SystemExit(1)
        if len(stripped_hex) % 2 != 0:
            con.print("[bold red][!][/bold red] Hex string has odd length — "
                      "must be an even number of hex digits.")
            raise SystemExit(1)
        try:
            raw = bytes.fromhex(stripped_hex)
        except ValueError as exc:
            con.print(f"[bold red][!][/bold red] Invalid hex string: {exc}")
            raise SystemExit(1)
        if not raw:
            con.print("[bold red][!][/bold red] Hex decodes to zero bytes.")
            raise SystemExit(1)
        mode = "hex"
        summary = f"{len(stripped_hex)} nibbles → {len(raw)} bytes"
        entropy = _entropy(raw)

    if not as_json:
        con.print("[bold yellow][ SCANNING INPUT... ][/bold yellow]")
        con.print()

    # --- Fingerprint ---
    findings = fingerprint(raw)

    # --- Verbose callback ---
    verbose_cb = None
    if verbose:
        def verbose_cb(msg: str) -> None:  # type: ignore[misc]
            con.print(f"[dim]{msg}[/dim]")

    # --- Pipeline ---
    solver_results, stats = run_pipeline(raw, findings, verbose_cb=verbose_cb)

    # --- Build report ---
    report = AnalysisReport(
        raw_input=raw,
        input_mode=mode,
        input_summary=summary,
        entropy=entropy,
        findings=findings,
        solver_results=solver_results,
        stats=stats,
    )

    # --- Output ---
    if as_json:
        print(json.dumps(_report_to_dict(report), indent=2, ensure_ascii=False))
    else:
        render_report(report, con=con)


if __name__ == "__main__":
    main()
