"""
Analysis report data model.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AnalysisReport:
    raw_input: str | bytes | Path
    input_mode: str                  # "text" | "file" | "hex"
    input_summary: str
    entropy: float
    findings: list                   # list[Finding]
    solver_results: list             # list[SolverResult]
    stats: dict = field(default_factory=dict)
