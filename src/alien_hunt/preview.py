"""What a run would draw from a tree, before it spends anything.

A run's first paid call filters the docstring invariants with the model; everything before it is free. This module
does the free part, `extract_atoms` and `pool_pairs`, so a tree can be looked at before a budget is spent on it. The
invariants are unfiltered here, so the preview's pool is an upper bound on a run's: a run drops the invariants the model
rejects, then asks the model for mechanisms and a coherence rating per pair.
"""

from __future__ import annotations

from pathlib import Path

from alien_hunt.atoms import extract_atoms
from alien_hunt.score import pool_pairs
from alien_hunt.types import Atom


def preview(checkout: Path, *, sample_limit: int = 80, seed: int = 0) -> dict:
    """The kept atoms by kind and the pairs a run with this seed would draw."""

    sources, sinks, invariants, mechanisms = extract_atoms(checkout)
    pairs = pool_pairs(sources, sinks, invariants, sample_limit=sample_limit, seed=seed)
    return {
        "atoms": {"sources": len(sources), "sinks": len(sinks), "invariants": len(invariants),
                  "mechanisms": len(mechanisms)},
        "files": len({atom.file for atom in [*sources, *sinks, *invariants] if atom.file}),
        "pairs": [{"file": source.file, "source": _side(source), "other": _side(other)} for source, other in pairs],
        "sample_limit": sample_limit,
        "seed": seed,
    }


def _side(atom: Atom) -> dict:
    return {"kind": atom.kind, "text": atom.text, "scope": atom.scope, "line": atom.line}


def render(result: dict, label: str) -> str:
    atoms = result["atoms"]
    lines = [
        f"Pool preview for {label} (seed {result['seed']}, sample_limit {result['sample_limit']})",
        "",
        f"- Atoms kept: {atoms['sources']} sources, {atoms['sinks']} sinks, {atoms['invariants']} invariants, "
        f"from {result['files']} file{'' if result['files'] == 1 else 's'}; {atoms['mechanisms']} mechanisms",
        f"- Pairs a run would draw: {len(result['pairs'])}",
        "",
    ]
    if result["pairs"]:
        lines += ["| file | source | sink or invariant |", "|---|---|---|"]
        lines += [f"| {pair['file']} | {_cell(pair['source'])} | {_cell(pair['other'])} |" for pair in result["pairs"]]
        lines.append("")
    lines.append("Invariants are not filtered here, so a run's pool is the same or smaller. A run then has the model "
                 "propose mechanisms for each pair and rate it; only that part costs money.")
    return "\n".join(lines) + "\n"


def _cell(side: dict) -> str:
    where = f" ({side['scope']}, line {side['line']})" if side.get("scope") else (f" (line {side['line']})" if side.get("line") else "")
    text = " ".join(str(side["text"]).split()).replace("|", "/")
    if len(text) > 80:
        text = text[:77] + "..."
    return f"{side['kind']}: {text}{where}"
