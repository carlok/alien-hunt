"""Harvest sources, sinks, invariants, and the fixed mechanism list."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from alien_hunt.types import Atom

_PROMISE = re.compile(r"\b(must|never|always|equals|at least|at most|length)\b", re.IGNORECASE)
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "build", "dist"}

_SINK_NAMES = {
    "eval": "eval of an expression",
    "exec": "exec of a code string",
    "pickle.loads": "pickle.loads of caller bytes",
    "pickle.load": "pickle.load of a file",
    "marshal.loads": "marshal.loads of caller bytes",
    "yaml.load": "yaml.load of a document",
    "os.system": "os.system of a command string",
    "subprocess.run": "subprocess.run",
    "subprocess.call": "subprocess.call",
    "subprocess.Popen": "subprocess.Popen",
    "os.path.join": "os.path.join of path parts",
    "hashlib.md5": "md5 digest",
    "hashlib.sha1": "sha1 digest",
    "hmac.compare_digest": "hmac.compare_digest",
    "hmac.new": "hmac.new",
}


def load_mechanisms() -> list[Atom]:
    """Load the packaged mechanism atoms. Wording is original to this package."""

    path = Path(__file__).resolve().parent / "data" / "mechanisms.json"
    texts = json.loads(path.read_text(encoding="utf-8"))
    return [
        Atom(kind="mechanism", id=f"m{index:02d}", text=text)
        for index, text in enumerate(texts, start=1)
    ]


def _py_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.stat().st_size > 500_000:
            continue
        files.append(path)
    return files


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    parts: list[str] = []
    current = func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _sentences(doc: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", doc.strip())
    return [part.strip() for part in parts if part.strip()]


def _spread(items: list[Atom], limit: int) -> list[Atom]:
    if len(items) <= limit:
        return items
    step = len(items) / limit
    return [items[int(index * step)] for index in range(limit)]


def extract_atoms(root: Path) -> tuple[list[Atom], list[Atom], list[Atom], list[Atom]]:
    """Return sources, sinks, docstring invariants, and mechanisms present for this tree.

    Sources and sinks are only those the AST actually finds. Mechanisms are the
    fixed list, because they are generic defect shapes rather than calls.
    """

    sources: list[Atom] = []
    sinks: list[Atom] = []
    invariants: list[Atom] = []
    seen: set[str] = set()

    def add(bucket: list[Atom], atom: Atom) -> None:
        if atom.id in seen:
            return
        seen.add(atom.id)
        bucket.append(atom)

    for path in _py_files(root):
        relative = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args:
                    if arg.arg in {"self", "cls"}:
                        continue
                    add(
                        sources,
                        Atom(
                            kind="source",
                            id=f"src-{relative}-{node.name}-{arg.arg}",
                            text=f"caller argument {arg.arg} of {node.name}",
                            file=relative,
                            function=node.name,
                        ),
                    )
                doc = ast.get_docstring(node)
                if doc:
                    for index, sentence in enumerate(_sentences(doc)):
                        if not _PROMISE.search(sentence):
                            continue
                        add(
                            invariants,
                            Atom(
                                kind="invariant",
                                id=f"inv-{relative}-{node.name}-{index}",
                                text=sentence,
                                file=relative,
                                function=node.name,
                            ),
                        )
            if isinstance(node, ast.Call):
                name = _call_name(node)
                if name in _SINK_NAMES:
                    add(
                        sinks,
                        Atom(
                            kind="sink",
                            id=f"sink-{relative}-{name}-{getattr(node, 'lineno', 0)}",
                            text=f"{_SINK_NAMES[name]} in {relative}",
                            file=relative,
                            function=name,
                        ),
                    )
            if isinstance(node, ast.Subscript):
                target = node.value
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "os"
                    and target.attr == "environ"
                ):
                    add(
                        sources,
                        Atom(
                            kind="source",
                            id=f"src-{relative}-environ-{getattr(node, 'lineno', 0)}",
                            text=f"environment variable read in {relative}",
                            file=relative,
                        ),
                    )
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "sys" and node.attr == "argv":
                    add(
                        sources,
                        Atom(
                            kind="source",
                            id=f"src-{relative}-argv",
                            text=f"command line argv in {relative}",
                            file=relative,
                        ),
                    )
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
                add(
                    sinks,
                    Atom(
                        kind="sink",
                        id=f"sink-{relative}-mul-{getattr(node, 'lineno', 0)}",
                        text=f"size multiplication in {relative}",
                        file=relative,
                        function="multiplication",
                    ),
                )
    return (
        _spread(sources, 80),
        _spread(sinks, 80),
        _spread(invariants, 40),
        load_mechanisms(),
    )


def filter_invariants(invariants: list[Atom], keep_ids: set[str]) -> list[Atom]:
    """Keep the invariants the model accepted. An empty reply keeps the harvest."""

    if not keep_ids:
        return invariants
    kept = [item for item in invariants if item.id in keep_ids]
    return kept or invariants
