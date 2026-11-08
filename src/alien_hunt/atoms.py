"""Harvest sources, sinks, invariants, and the fixed mechanism list."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from alien_hunt.types import Atom

_PROMISE = re.compile(r"\b(must|never|always|equals|at least|at most|length)\b", re.IGNORECASE)
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "build", "dist", ".tox", ".eggs", "node_modules", "site-packages"}
# Atoms come from the library itself: a test's argument or the docs' config is no entry point anyone reaches.
_NOT_LIBRARY_DIRS = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "scripts"}
_NOT_LIBRARY_FILES = {"setup.py", "conftest.py", "noxfile.py", "fabfile.py"}

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
        if path.is_symlink() or not path.is_file():     # a link can point anywhere the process can read, or nowhere
            continue
        parts = path.relative_to(root).parts            # the checkout's own folders only, not the ones above it
        if any(part in _SKIP_DIRS or part in _NOT_LIBRARY_DIRS for part in parts[:-1]):
            continue
        name = parts[-1]
        if name in _NOT_LIBRARY_FILES or name.startswith("test_") or name.endswith("_test.py"):
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


# Calls that turn caller input into new objects: what they allocate is in proportion to the input.
_DECODERS = {
    "base64.urlsafe_b64decode": "base64 decode", "base64.b64decode": "base64 decode", "urlsafe_b64decode": "base64 decode",
    "b64decode": "base64 decode", "json.loads": "json.loads", "zlib.decompress": "zlib decompress",
    "gzip.decompress": "gzip decompress", "bz2.decompress": "bz2 decompress", "lzma.decompress": "lzma decompress",
}


def _rooted_in(node: ast.AST, params: set[str]) -> bool:
    """True when an expression is a parameter, or reaches one through subscripts, attributes and method calls
    (`data["recipients"]`, `obj.items()`, `value.split(b".")`)."""

    while True:
        if isinstance(node, ast.Name):
            return node.id in params
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func.value if isinstance(node.func, ast.Attribute) else (node.args[0] if node.args else None)
            if node is None:
                return False
        else:
            return False


def _input_sinks(func: ast.AST, relative: str) -> list[Atom]:
    """Where a function's own input sets the work or the memory: a loop over it, or a decode, split or decompress of it.
    joserfc's two advisories are of this kind (a JWE recipients list processed in full; compact segments split and
    decoded before the size check), and the first sinks (eval, pickle, a multiplication) gave the hunts nothing there."""

    params = {arg.arg for arg in func.args.args + func.args.kwonlyargs} - {"self", "cls"}
    if not params:
        return []
    out: list[Atom] = []
    for node in ast.walk(func):
        iters = []
        if isinstance(node, (ast.For, ast.AsyncFor)):
            iters = [node.iter]
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            iters = [gen.iter for gen in node.generators]
        for it in iters:
            if _rooted_in(it, params):
                expr = ast.unparse(it)[:60]
                out.append(Atom(kind="sink", id=f"sink-{relative}-{func.name}-loop-{getattr(it, 'lineno', 0)}",
                                text=f"loop over caller-supplied {expr} in {func.name}", file=relative, function=func.name,
                                line=getattr(it, "lineno", None)))
        if isinstance(node, ast.Call):
            name = _call_name(node)
            label = _DECODERS.get(name)
            if label is None and isinstance(node.func, ast.Attribute) and node.func.attr in ("split", "rsplit", "splitlines"):
                label = node.func.attr
                arg = node.func.value
            else:
                arg = node.args[0] if node.args else None
            if label and arg is not None and _rooted_in(arg, params):
                expr = ast.unparse(arg)[:60]
                out.append(Atom(kind="sink", id=f"sink-{relative}-{func.name}-{label}-{getattr(node, 'lineno', 0)}",
                                text=f"{label} of caller-supplied {expr} in {func.name}", file=relative, function=func.name,
                                line=getattr(node, "lineno", None)))
    return out


def _function_spans(tree: ast.AST) -> list[tuple[int, int, str]]:
    """(first line, last line, dotted name) of every function in a file, the names running through the classes and
    functions around it."""

    spans: list[tuple[int, int, str]] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    spans.append((child.lineno, getattr(child, "end_lineno", None) or child.lineno, name))
                walk(child, f"{name}.")
            else:
                walk(child, prefix)

    walk(tree, "")
    return spans


def _scope_at(spans: list[tuple[int, int, str]], line: int | None) -> str | None:
    """The innermost function holding a line, or None for module-level code."""

    if line is None:
        return None
    inside = [span for span in spans if span[0] <= line <= span[1]]
    return min(inside, key=lambda span: span[1] - span[0])[2] if inside else None


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
    spans: list[tuple[int, int, str]] = []          # the functions of the file being read

    def add(bucket: list[Atom], atom: Atom) -> None:
        if atom.id in seen:
            return
        seen.add(atom.id)
        atom.scope = _scope_at(spans, atom.line)
        bucket.append(atom)

    for path in _py_files(root):
        relative = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        spans[:] = _function_spans(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for atom in _input_sinks(node, relative):
                    add(sinks, atom)
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
                            line=node.lineno,
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
                                line=node.lineno,
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
                            line=getattr(node, "lineno", None),
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
                            line=getattr(node, "lineno", None),
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
                            line=getattr(node, "lineno", None),
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
                        line=getattr(node, "lineno", None),
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
