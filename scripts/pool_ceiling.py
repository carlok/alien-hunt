#!/usr/bin/env python3
"""How often can the candidate pool reach the code a fix changed?

A hunt can find a defect only if the pool holds a candidate near it. This script measures that ceiling offline, with no
model call: for each case (a vulnerable tree, the tree after its fix) it takes the functions the fix changed, builds the
pool's atoms and co-located pairs with alien-hunt's own `extract_atoms`, `colocated_pairs` and `pool_pairs`, and asks
whether an atom or a pair lands in those functions.

Per case it records
  atom_hit    some source, sink or invariant atom sits in a fix function (file and line inside the function)
  pair_hit    some co-located pair, before the pair limit applies, has an atom in a fix function
  drawn_hit   the share of seeds whose kept pairs (the limit the pipeline sets) include such a pair
  pool_size   the number of co-located pairs before the limit
  touch_share the share of those pairs that touch a fix function (the brief's "dilution": higher is better)

The atoms are the ones before a model filters the invariants, so atom_hit and pair_hit are upper bounds on what a run
sees. A case whose fix changes no function that exists in the vulnerable tree has no target and is counted apart.

Only `ast` parses the target code. Nothing in a case directory is imported or run.

    python -I scripts/pool_ceiling.py measure CASES [--json out.json] [--src DIR] [--family F] [--split S]
    python -I scripts/pool_ceiling.py explain CASES/GHSA-xxxx-xxxx-xxxx [--src DIR]
    python -I scripts/pool_ceiling.py compare BEFORE.json AFTER.json

`compare` keeps a change only if drawn_hit rises and touch_share stays at least four fifths of what it was, over the cases
both files measured.

CASES holds one folder per case: `before/`, `after/` and `case.json` ({"id", "family", "split", ...}).
`--src` puts another checkout's `src/` first on the path, to measure a change in a worktree.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

SEEDS = 20
SAMPLE_LIMIT = 80          # alien-hunt's default `sample_limit`, which sets the pair limit at a quarter of it
NO_LIMIT = 10**9


def load_alien_hunt(src: Path | None = None) -> tuple[ModuleType, ModuleType]:
    """The pool's own modules. Neither imports a model client."""

    if src is not None:
        sys.path.insert(0, str(Path(src).resolve()))
    from alien_hunt import atoms, score

    return atoms, score


@dataclass(frozen=True)
class Func:
    """A function or method of one tree, keyed by file and qualified name."""

    file: str
    qualname: str
    name: str
    start: int
    end: int
    digest: str


def _digest(node: ast.AST) -> str:
    """The function's code without positions and without its own docstring: a docstring edit is no fix."""

    body = list(node.body)
    first = body[0] if body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        body = body[1:] or [ast.Pass()]
    clone = copy.copy(node)
    clone.body = body
    return ast.dump(clone)


def functions_of(root: Path, atoms: ModuleType) -> dict[tuple[str, str, int], Func]:
    """Every function in the tree's library files (the files `extract_atoms` reads), keyed by file, qualified name and
    occurrence. Files that do not parse are skipped, as `extract_atoms` skips them."""

    found: dict[tuple[str, str, int], Func] = {}
    for path in atoms._py_files(root):
        relative = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        seen: dict[str, int] = defaultdict(int)

        def walk(node: ast.AST, prefix: str) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    qualname = f"{prefix}{child.name}"
                    if not isinstance(child, ast.ClassDef):
                        index = seen[qualname]
                        seen[qualname] += 1
                        end = getattr(child, "end_lineno", None) or child.lineno
                        found[(relative, qualname, index)] = Func(
                            relative, qualname, child.name, child.lineno, end, _digest(child)
                        )
                    walk(child, f"{qualname}.")
                else:
                    walk(child, prefix)

        walk(tree, "")
    return found


def fix_functions(before: Path, after: Path, atoms: ModuleType) -> list[Func]:
    """The functions of the vulnerable tree that the fix changes or removes, in the vulnerable tree's positions. A
    function the fix adds is not here: no pool built from the vulnerable tree could hold it."""

    old = functions_of(before, atoms)
    new = functions_of(after, atoms)
    return sorted(
        (func for key, func in old.items() if key not in new or new[key].digest != func.digest),
        key=lambda func: (func.file, func.start),
    )


def atom_in(atom, func: Func) -> bool:
    """An atom is in a function when it sits in its file and inside its lines. `function` on a sink names the callee
    (`pickle.loads`), not the function around it, so the lines decide; an atom with no line falls back to the name."""

    if atom.file != func.file:
        return False
    if atom.line is not None:
        return func.start <= atom.line <= func.end
    return atom.function in (func.name, func.qualname)


def atom_in_literal(atom, func: Func) -> bool:
    """The strict reading: the atom's own `function` field names the fix function."""

    return atom.file == func.file and atom.function in (func.name, func.qualname)


def measure_case(
    before: Path,
    after: Path,
    *,
    seeds: int = SEEDS,
    sample_limit: int = SAMPLE_LIMIT,
    alien: tuple[ModuleType, ModuleType] | None = None,
) -> dict:
    atoms, score = alien or load_alien_hunt()
    targets = fix_functions(before, after, atoms)
    record: dict = {
        "status": "ok" if targets else "no_targets",
        "targets": [f"{func.file}:{func.qualname}:{func.start}-{func.end}" for func in targets],
    }
    if not targets:
        return record
    sources, sinks, invariants, _mechanisms = atoms.extract_atoms(before)
    everything = [*sources, *sinks, *invariants]
    memo: dict[int, bool] = {}

    def inside(atom) -> bool:
        key = id(atom)
        if key not in memo:
            memo[key] = any(atom_in(atom, func) for func in targets)
        return memo[key]

    full = score.colocated_pairs(sources, [*sinks, *invariants], limit=NO_LIMIT, seed=0)
    touching = sum(1 for left, right in full if inside(left) or inside(right))
    drawn = 0
    kept = 0
    for seed in range(seeds):
        pairs = score.pool_pairs(sources, sinks, invariants, sample_limit=sample_limit, seed=seed)
        kept = len(pairs)
        drawn += any(inside(left) or inside(right) for left, right in pairs)
    in_targets = [atom for atom in everything if inside(atom)]
    record.update(
        {
            "atom_hit": bool(in_targets),
            "atom_hit_literal": any(atom_in_literal(atom, func) for atom in everything for func in targets),
            "pair_hit": touching > 0,
            "drawn_hit": drawn / seeds if seeds else 0.0,
            "pool_size": len(full),
            "touching_pairs": touching,
            "touch_share": touching / len(full) if full else 0.0,
            "kept_pairs": kept,
            "atoms": {"source": len(sources), "sink": len(sinks), "invariant": len(invariants)},
            "atoms_in_targets": {
                kind: sum(1 for atom in in_targets if atom.kind == kind) for kind in ("source", "sink", "invariant")
            },
            "targets_without_atoms": [
                f"{func.file}:{func.qualname}"
                for func in targets
                if not any(atom_in(atom, func) for atom in everything)
            ],
        }
    )
    return record


def summarize(records: list[dict]) -> dict:
    """Rates over the cases that have a target. `touch_share` is the mean of the per-case shares; `pooled_touch_share`
    is touching pairs over all pairs."""

    measured = [rec for rec in records if rec.get("status") == "ok"]
    out: dict = {"cases": len(records), "measured": len(measured), "no_targets": len(records) - len(measured)}
    if not measured:
        return out
    count = len(measured)
    pool = sum(rec["pool_size"] for rec in measured)
    out.update(
        {
            "atom_hit": sum(rec["atom_hit"] for rec in measured) / count,
            "atom_hit_literal": sum(rec["atom_hit_literal"] for rec in measured) / count,
            "pair_hit": sum(rec["pair_hit"] for rec in measured) / count,
            "drawn_hit": sum(rec["drawn_hit"] for rec in measured) / count,
            "mean_pool_size": pool / count,
            "touch_share": sum(rec["touch_share"] for rec in measured) / count,
            "pooled_touch_share": sum(rec["touching_pairs"] for rec in measured) / pool if pool else 0.0,
        }
    )
    return out


SMALL_FIX = 5


def small_fixes(records: list[dict]) -> list[dict]:
    """Cases whose fix changes at most SMALL_FIX functions. A few huge commits (a refactor, a reformat) change hundreds and
    are hit by almost any pool, which lifts the headline; the median fix changes two."""

    return [rec for rec in records if rec.get("status") == "ok" and len(rec.get("targets") or []) <= SMALL_FIX]


def by_family(records: list[dict]) -> dict[str, dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        groups[rec.get("family") or "other"].append(rec)
    return {name: summarize(items) for name, items in sorted(groups.items())}


KEEP_FLOOR = 0.8        # touch_share may fall by at most a fifth


def compare(before: dict, after: dict, *, floor: float = KEEP_FLOOR) -> dict:
    """The rates before and after over the cases both files measured, and whether the change is kept: drawn_hit must rise
    and touch_share ("dilution", higher is better) must stay at least `floor` of what it was."""

    def measured(payload: dict) -> dict[str, dict]:
        return {rec["id"]: rec for rec in payload["cases"] if rec.get("status") == "ok" and rec.get("id")}

    old, new = measured(before), measured(after)
    common = sorted(old.keys() & new.keys())
    old_rates, new_rates = summarize([old[i] for i in common]), summarize([new[i] for i in common])
    families = {
        name: (summarize([old[i] for i in common if (old[i].get("family") or "other") == name]),
               summarize([new[i] for i in common if (new[i].get("family") or "other") == name]))
        for name in sorted({old[i].get("family") or "other" for i in common})
    }
    verdict = {"cases": len(common), "before": old_rates, "after": new_rates, "families": families}
    if not common:
        return {**verdict, "keep": False, "why": "no case was measured in both"}
    rose = new_rates["drawn_hit"] > old_rates["drawn_hit"]
    held = new_rates["touch_share"] >= floor * old_rates["touch_share"] - 1e-9      # not a rounding error
    why = [] if rose else ["drawn_hit did not rise"]
    if not held:
        why.append(f"touch_share fell below {floor:.0%} of {_pct(old_rates['touch_share'])}")
    return {**verdict, "keep": rose and held, "why": "; ".join(why) or "drawn_hit rose and touch_share held"}


def render_comparison(result: dict) -> str:
    lines = [f"{result['cases']} cases measured in both", "| rate | before | after | change |", "|---|---|---|---|"]
    for key in ("atom_hit", "pair_hit", "drawn_hit", "touch_share"):
        old, new = result["before"].get(key), result["after"].get(key)
        if old is None or new is None:
            continue
        lines.append(f"| {key} | {_pct(old)} | {_pct(new)} | {100 * (new - old):+.1f} pts |")
    if result["before"].get("mean_pool_size") is not None:
        lines.append(f"| pool | {result['before']['mean_pool_size']:.0f} | {result['after']['mean_pool_size']:.0f} | |")
    for name, (old, new) in result["families"].items():
        if old.get("measured"):
            lines.append(f"| {name} drawn_hit ({old['measured']} cases) | {_pct(old['drawn_hit'])} | {_pct(new['drawn_hit'])} | "
                         f"{100 * (new['drawn_hit'] - old['drawn_hit']):+.1f} pts |")
    lines.append(f"keep: {'yes' if result['keep'] else 'no'} ({result['why']})")
    return "\n".join(lines)


def load_cases(root: Path, *, family: str | None = None, split: str | None = None) -> list[tuple[dict, Path, Path]]:
    cases = []
    for folder in sorted(path for path in root.iterdir() if (path / "case.json").is_file()):
        meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
        if family and meta.get("family") != family:
            continue
        if split and meta.get("split") != split:
            continue
        cases.append((meta, folder / "before", folder / "after"))
    return cases


_WORKER: tuple[ModuleType, ModuleType] | None = None


def _init_worker(src: str | None) -> None:
    global _WORKER
    _WORKER = load_alien_hunt(Path(src) if src else None)


def _measure(job: tuple[dict, str, str, int, int]) -> dict:
    meta, before, after, seeds, sample_limit = job
    try:
        rec = measure_case(Path(before), Path(after), seeds=seeds, sample_limit=sample_limit, alien=_WORKER)
    except Exception as exc:                        # one odd tree must not end the run; the error is on its record
        rec = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:300], "targets": []}
    return {**{key: meta.get(key) for key in ("id", "family", "split", "repo")}, **rec}


def measure_all(
    cases: list[tuple[dict, Path, Path]], *, src: Path | None, seeds: int, sample_limit: int, jobs: int
) -> list[dict]:
    work = [(meta, str(before), str(after), seeds, sample_limit) for meta, before, after in cases]
    if jobs <= 1 or len(work) <= 1:
        _init_worker(str(src) if src else None)
        return [_measure(job) for job in work]
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker, initargs=(str(src) if src else None,)) as pool:
        return list(pool.map(_measure, work, chunksize=1))


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


def render_table(overall: dict, families: dict[str, dict], extra: dict[str, dict] | None = None) -> str:
    head = "| group | cases | atom_hit | pair_hit | drawn_hit | pool | touch_share |\n|---|---|---|---|---|---|---|\n"
    rows = []
    for name, stats in [("all", overall), *(extra or {}).items(), *families.items()]:
        if not stats.get("measured"):
            rows.append(f"| {name} | 0 | | | | | |")
            continue
        rows.append(
            f"| {name} | {stats['measured']} | {_pct(stats['atom_hit'])} | {_pct(stats['pair_hit'])} | "
            f"{_pct(stats['drawn_hit'])} | {stats['mean_pool_size']:.0f} | {_pct(stats['touch_share'])} |"
        )
    return head + "\n".join(rows) + "\n"


def explain(case: Path, *, src: Path | None, sample_limit: int) -> str:
    atoms, score = load_alien_hunt(src)
    before, after = case / "before", case / "after"
    targets = fix_functions(before, after, atoms)
    sources, sinks, invariants, _ = atoms.extract_atoms(before)
    lines = [f"targets: {len(targets)}   atoms: {len(sources)} sources, {len(sinks)} sinks, {len(invariants)} invariants"]
    for func in targets:
        inside = [atom for atom in [*sources, *sinks, *invariants] if atom_in(atom, func)]
        lines.append(f"- {func.file}:{func.qualname} lines {func.start}-{func.end}: {len(inside)} atoms")
        lines.extend(f"    {atom.kind}: {atom.text}" for atom in inside[:6])
    full = score.colocated_pairs(sources, [*sinks, *invariants], limit=NO_LIMIT, seed=0)
    lines.append(f"co-located pairs: {len(full)}; kept per run: {len(score.pool_pairs(sources, sinks, invariants, sample_limit=sample_limit, seed=0))}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pool_ceiling", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    measure = sub.add_parser("measure", help="measure every case under a folder")
    measure.add_argument("cases", type=Path)
    measure.add_argument("--json", type=Path, help="write the records and the summaries here")
    measure.add_argument("--family")
    measure.add_argument("--split")
    measure.add_argument("--seeds", type=int, default=SEEDS)
    measure.add_argument("--sample-limit", type=int, default=SAMPLE_LIMIT)
    measure.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    measure.add_argument("--src", type=Path, help="use this checkout's src/ instead of the installed package")
    cmp = sub.add_parser("compare", help="compare two result files and say whether the change is kept")
    cmp.add_argument("before", type=Path)
    cmp.add_argument("after", type=Path)
    show = sub.add_parser("explain", help="list a case's fix functions and the atoms in them")
    show.add_argument("case", type=Path)
    show.add_argument("--sample-limit", type=int, default=SAMPLE_LIMIT)
    show.add_argument("--src", type=Path)
    args = parser.parse_args(argv)
    if args.command == "compare":
        result = compare(json.loads(args.before.read_text(encoding="utf-8")), json.loads(args.after.read_text(encoding="utf-8")))
        print(render_comparison(result))
        return 0
    if args.command == "explain":
        print(explain(args.case, src=args.src, sample_limit=args.sample_limit))
        return 0
    cases = load_cases(args.cases, family=args.family, split=args.split)
    records = measure_all(cases, src=args.src, seeds=args.seeds, sample_limit=args.sample_limit, jobs=args.jobs)
    overall, families = summarize(records), by_family(records)
    small = summarize(small_fixes(records))
    print(render_table(overall, families, {f"fix of at most {SMALL_FIX} functions": small}))
    errors = [rec for rec in records if rec.get("status") == "error"]
    if errors:
        print(f"{len(errors)} cases failed: " + ", ".join(rec["id"] or "?" for rec in errors[:10]), file=sys.stderr)
    if args.json:
        payload = {"overall": overall, "small_fix": small, "by_family": families, "cases": records}
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
