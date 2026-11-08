"""Confirm a claim by running its reproducer.

The script must import the checkout, enter a function the claim names, print the defect marker from a branch, and
exit 0. Reading source text does not count. The CLI runs that script in Podman with the network off and the checkout
read-only.

The trace and the reproducer share one process, so a script written to fool the trace could. The blocked modules and
attributes stop the obvious routes, and the marker asks the script to test something; neither makes the check
adversary-proof, and a broad `except` around a call that raises still counts as a branch.
"""

from __future__ import annotations

import ast
import configparser
import functools
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.habits import package_names, src_layout
from alien_hunt.prompts import BLOCKED_ATTRS, BLOCKED_MODULES, MARKER
from alien_hunt.types import Claim, Confirmation

log = logging.getLogger("alien_hunt")

_RUNNER = r'''
import json
import os
import sys
import threading
import traceback

repro_path, calls_path, checkout = sys.argv[1], sys.argv[2], sys.argv[3]
sites_path = os.path.splitext(calls_path)[0] + ".sites.json"
root = os.path.realpath(checkout)
calls = []
sites = []
seen_sites = set()
resolved_files = {}
imports_running = [0]       # what an import runs is the library starting up, not the script calling it

def library_file(filename):
    # a real file under the checkout: code the script compiled under a library path is not that file's code
    if filename not in resolved_files:
        try:
            resolved = os.path.realpath(filename)
        except OSError:
            resolved = filename
        inside = resolved.startswith(root + os.sep) and os.path.isfile(resolved)
        resolved_files[filename] = resolved if inside else ""
    return resolved_files[filename]

def leave(frame, event, arg):
    if event == "return":
        imports_running[0] -= 1
    return leave

def tracer(frame, event, arg):
    code = frame.f_code
    filename = code.co_filename or ""
    if filename.startswith("<frozen importlib"):
        imports_running[0] += 1
        return leave
    if imports_running[0] == 0 and code.co_flags & 1:   # CO_OPTIMIZED: a function, not a module or class body
        resolved = library_file(filename)
        if resolved:
            calls.append(f"{resolved}:{code.co_name}")
            if (resolved, code.co_firstlineno) not in seen_sites:
                seen_sites.add((resolved, code.co_firstlineno))
                sites.append([resolved, code.co_firstlineno])
    return None

status = 1
try:
    with open(repro_path, encoding="utf-8") as handle:
        code = compile(handle.read(), repro_path, "exec")
    threading.settrace(tracer)
    sys.settrace(tracer)
    exec(code, {"__name__": "__main__", "__file__": repro_path})
    status = 0
except SystemExit as exc:
    code_value = exc.code
    if code_value in (None, 0):
        status = 0
    elif isinstance(code_value, int):
        status = code_value
    else:
        status = 1
except Exception:
    traceback.print_exc()
    status = 1
finally:
    sys.settrace(None)
    with open(calls_path, "w", encoding="utf-8") as handle:
        json.dump(calls, handle)
    with open(sites_path, "w", encoding="utf-8") as handle:
        json.dump(sites, handle)
raise SystemExit(status)
'''

# Model-written code runs in these containers: no capabilities, no privilege gain, bounded processes, memory and CPU.
HARDENING = (
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--pids-limit=256",
    "--memory=2g",
    "--cpus=1",
)

_REQ = re.compile(r"^([A-Za-z0-9_.-]+)\s*(?:==\s*([A-Za-z0-9_.*+-]+))?")


@dataclass
class DepsStatus:
    """Whether wheels for the commit date are ready."""

    ok: bool
    why: str
    target: Path | None = None


def linux_arch() -> str:
    """Container architecture tag used in wheel filenames."""

    machine = platform.machine().lower()
    if machine in {"aarch64", "arm64"}:
        return "aarch64"
    if machine in {"x86_64", "amd64"}:
        return "x86_64"
    return machine


CHANGES = "reproducer replaces or changes repository code or what it returned"

_MUTATORS = frozenset(
    {"append", "extend", "insert", "pop", "remove", "clear", "update", "add", "discard", "sort", "reverse", "setdefault",
     "popitem"}
)
_UNKNOWN = object()


def _root_name(node: ast.AST) -> str | None:
    """The name an expression starts from: `pkg.mod.f` and `Cls(1).go` both start from their first Name."""

    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            return None


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for item in target.elts for name in _target_names(item)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _flatten(target: ast.AST) -> list[ast.AST]:
    if isinstance(target, (ast.Tuple, ast.List)):
        return [leaf for item in target.elts for leaf in _flatten(item)]
    if isinstance(target, ast.Starred):
        return _flatten(target.value)
    return [target]


_COLLECT = frozenset({"append", "appendleft", "extend", "extendleft", "insert", "add", "update", "setdefault"})


def _empty_container(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("list", "dict", "set") \
        and not node.args and not node.keywords


class _Script:
    """What a reproducer's names stand for: which come from the repository, and which hold something it returned.

    A name holds a repository result when every assignment to it is made from the repository's names or from other such
    names (`size = len(got); size = size + 1` counts). A list or dict the script starts empty and only feeds with such
    results holds them too, which is how a thread hands one back. A function the script defines is a repository call when
    its body calls the repository."""

    def __init__(self, tree: ast.AST, packages: set[str]) -> None:
        self.tree = tree
        self.bound: set[str] = set()                       # bound by importing the repository
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.bound.update(alias.asname or alias.name.split(".")[0] for alias in node.names
                                  if alias.name.split(".")[0] in packages)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and (node.module or "").split(".")[0] in packages:
                self.bound.update(alias.asname or alias.name for alias in node.names)
        self.repo = set(self.bound)                        # plus aliases such as `orig = pkg.mod.f`
        entries: dict[str, list[tuple[str, ast.AST | None]]] = {}
        functions: list[ast.AST] = []

        def note(name: str, kind: str, expr: ast.AST | None) -> None:
            entries.setdefault(name, []).append((kind, expr))

        def assign(target: ast.AST, value: ast.AST | None) -> None:
            for name in _target_names(target):
                if value is not None and _empty_container(value):
                    entries.setdefault(name, [])
                else:
                    note(name, "assign", value)
            if isinstance(target, ast.Subscript) and isinstance(_root_name(target), str) and value is not None:
                note(_root_name(target), "write", value)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    assign(target, node.value)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                assign(node.target, node.value)
            elif isinstance(node, ast.AugAssign):
                assign(node.target, None)
            elif isinstance(node, ast.NamedExpr):
                note(node.target.id, "assign", node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                assign(node.target, node.iter)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        assign(item.optional_vars, item.context_expr)
            elif isinstance(node, (ast.Try, ast.TryStar)):  # `except E as exc`: exc comes from what the body called
                for handler in node.handlers:
                    if handler.name:
                        note(handler.name, "assign", ast.Module(body=list(node.body), type_ignores=[]))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(node)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _COLLECT \
                    and isinstance(node.func.value, ast.Name):
                for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                    note(node.func.value.id, "write", argument)
        for name, items in entries.items():                # `orig = samplelib.allocate`: an alias, not a result
            values = [expr for kind, expr in items if kind == "assign"]
            if values and all(isinstance(v, (ast.Name, ast.Attribute)) and _root_name(v) in self.repo for v in values):
                self.repo.add(name)
        self.tainted: set[str] = set()
        self.returned: set[str] = set()                    # tainted by assignment, so what the repository itself handed over
        self.helpers: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, items in entries.items():
                if name in self.tainted or name in self.repo:
                    continue
                values = [expr for kind, expr in items if kind == "assign"]
                writes = [expr for kind, expr in items if kind == "write"]
                if values:
                    if all(v is not None and self.derived(v, name) for v in values) and any(
                            v is not None and self.derived(v) for v in values):
                        self.tainted.add(name)
                        self.returned.add(name)
                        changed = True
                elif writes and all(self.derived(w) for w in writes):
                    self.tainted.add(name)
                    changed = True
            for function in functions:
                if function.name not in self.helpers and function.name not in self.bound and \
                        any(self.derived(statement) for statement in function.body):
                    self.helpers.add(function.name)
                    changed = True

    def derived(self, node: ast.AST, also: str | None = None) -> bool:
        """True when the expression reads a repository name, something a repository call returned, or a helper that calls
        the repository. `also` is a name to count as derived, for an assignment that reads its own target."""

        names = self.repo | self.tainted | self.helpers | ({also} if also else set())
        return any(isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in names for sub in ast.walk(node))

    def calls_repository(self, node: ast.AST) -> bool:
        names = self.repo | self.tainted | self.helpers
        return any(isinstance(sub, ast.Call) and _root_name(sub.func) in names for sub in ast.walk(node))

    def changes_repository(self) -> bool:
        """The script patches, shadows or subclasses repository code, or edits what a repository call handed it."""

        touched = self.repo | self.returned
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
                for leaf in [leaf for target in targets for leaf in _flatten(target)]:
                    if isinstance(leaf, ast.Name):
                        if leaf.id in self.bound:
                            return True
                    elif isinstance(leaf, (ast.Attribute, ast.Subscript)) and _root_name(leaf) in touched:
                        return True
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in self.bound:
                    return True
                if isinstance(node, ast.ClassDef) and any(_root_name(base) in touched for base in node.bases):
                    return True
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("setattr", "delattr") and node.args \
                        and _root_name(node.args[0]) in touched:
                    return True
                if isinstance(func, ast.Attribute) and func.attr in _MUTATORS and _root_name(func.value) in self.returned:
                    return True
        return False


def _value(node: ast.AST):
    """The value of an expression made only of literals, or _UNKNOWN. Nothing is evaluated by Python: each node type is
    handled here, so a model's script is read and never run."""

    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        items = [_value(item) for item in node.elts]
        if any(item is _UNKNOWN for item in items):
            return _UNKNOWN
        try:
            return tuple(items) if isinstance(node, ast.Tuple) else list(items) if isinstance(node, ast.List) else frozenset(items)
        except TypeError:
            return _UNKNOWN
    if isinstance(node, ast.UnaryOp):
        operand = _value(node.operand)
        if operand is _UNKNOWN:
            return _UNKNOWN
        try:
            return {ast.Not: lambda v: not v, ast.USub: lambda v: -v, ast.UAdd: lambda v: +v}[type(node.op)](operand)
        except (KeyError, TypeError):
            return _UNKNOWN
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        left, right = _value(node.left), _value(node.right)
        numbers = (int, float)
        if isinstance(left, numbers) and isinstance(right, numbers) and abs(left) < 10**6 and abs(right) < 10**6:
            return left + right if isinstance(node.op, ast.Add) else left - right if isinstance(node.op, ast.Sub) else left * right
        if isinstance(node.op, ast.Add) and type(left) is type(right) and isinstance(left, (str, tuple, list)) \
                and len(left) + len(right) < 10**4:
            return left + right
        return _UNKNOWN
    if isinstance(node, ast.Compare):
        values = [_value(node.left), *[_value(c) for c in node.comparators]]
        if any(v is _UNKNOWN for v in values):
            return _UNKNOWN
        ops = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b, ast.Lt: lambda a, b: a < b,
               ast.LtE: lambda a, b: a <= b, ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b,
               ast.Is: lambda a, b: a is b, ast.IsNot: lambda a, b: a is not b, ast.In: lambda a, b: a in b,
               ast.NotIn: lambda a, b: a not in b}
        try:
            return all(ops[type(op)](values[i], values[i + 1]) for i, op in enumerate(node.ops))
        except (KeyError, TypeError):
            return _UNKNOWN
    if isinstance(node, ast.BoolOp):
        truth = _truth(node)
        return _UNKNOWN if truth is None else truth
    if isinstance(node, ast.IfExp):
        test = _value(node.test)
        return _UNKNOWN if test is _UNKNOWN else _value(node.body if test else node.orelse)
    if isinstance(node, ast.NamedExpr):
        return _value(node.value)
    if isinstance(node, ast.JoinedStr):
        parts = [_value(part.value) if isinstance(part, ast.FormattedValue) else _value(part) for part in node.values]
        return _UNKNOWN if any(part is _UNKNOWN for part in parts) else "".join(str(part) for part in parts)
    if isinstance(node, ast.Subscript):
        base, index = _value(node.value), _value(node.slice)
        if base is _UNKNOWN or index is _UNKNOWN:
            return _UNKNOWN
        try:
            return base[index]
        except (TypeError, IndexError, KeyError):
            return _UNKNOWN
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Lambda) and not node.args and not node.keywords and not func.args.args:
            return _value(func.body)
        if isinstance(func, ast.Name) and func.id in ("bool", "len") and len(node.args) == 1 and not node.keywords:
            arg = _value(node.args[0])
            if arg is _UNKNOWN:
                return _UNKNOWN
            try:
                return bool(arg) if func.id == "bool" else len(arg)
            except TypeError:
                return _UNKNOWN
    return _UNKNOWN


def _truth(node: ast.AST):
    """True or False when the test comes out the same whatever a repository call returns, else None."""

    value = _value(node) if not isinstance(node, ast.BoolOp) else _UNKNOWN
    if value is not _UNKNOWN:
        return bool(value)
    if isinstance(node, ast.BoolOp):
        results = [_truth(item) for item in node.values]
        if isinstance(node.op, ast.Or):
            return True if any(r is True for r in results) else False if all(r is False for r in results) else None
        return False if any(r is False for r in results) else True if all(r is True for r in results) else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _truth(node.operand)
        return None if inner is None else not inner
    if isinstance(node, ast.NamedExpr):
        return _truth(node.value)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.left, ast.Call) \
            and isinstance(node.left.func, ast.Name) and node.left.func.id == "len" and len(node.left.args) == 1:
        bound = _value(node.comparators[0])                # a length is never negative
        if isinstance(bound, int) and not isinstance(bound, bool):
            op = node.ops[0]
            if (isinstance(op, ast.GtE) and bound <= 0) or (isinstance(op, ast.Gt) and bound < 0):
                return True
            if (isinstance(op, ast.Lt) and bound <= 0) or (isinstance(op, ast.LtE) and bound < 0):
                return False
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and ast.dump(node.left) == ast.dump(node.comparators[0]) \
            and not any(isinstance(sub, ast.Call) for sub in ast.walk(node)):
        if isinstance(node.ops[0], (ast.Eq, ast.Is, ast.LtE, ast.GtE)):
            return True
        if isinstance(node.ops[0], (ast.NotEq, ast.IsNot, ast.Lt, ast.Gt)):
            return False
    return None


def _decides(script: _Script, test: ast.expr) -> bool:
    """A test the repository decides: it reads a repository name or a repository result, it is not about `__name__`
    (the runner executes the script as __main__), and it does not come out the same whatever the call returned."""

    if any(isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(test)):
        return False
    if not script.derived(test):
        return False
    try:
        return _truth(test) is None
    except (RecursionError, ValueError, OverflowError, MemoryError):
        return True


def _try_calls_repository(script: _Script, node: ast.Try) -> bool:
    """The body calls the repository, and the script does not raise anything of its own in it."""

    return any(script.calls_repository(statement) for statement in node.body) and not any(
        isinstance(sub, ast.Raise) for statement in node.body for sub in ast.walk(statement)
    )


def _marker_is_decided(script: _Script) -> bool:
    """Every mention of the marker is a print that a repository result or exception decides.

    A print counts when an enclosing `if` tests something the repository returned; or it is in an `except` or in the
    `else` of a `try` whose body calls the repository and raises nothing itself; or it follows such a call in a `try`
    body that has a handler (the call raising skips it). One honest print does not excuse another that always runs."""

    tree = script.tree
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    marked = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and MARKER in n.value]
    if not marked:
        return False

    def decided(call: ast.AST) -> bool:
        child: ast.AST = call
        parent = parents.get(call)
        while parent is not None:
            if isinstance(parent, ast.If) and child is not parent.test and _decides(script, parent.test):
                return True
            if isinstance(parent, ast.ExceptHandler):
                owner = parents.get(parent)
                if isinstance(owner, (ast.Try, ast.TryStar)) and _try_calls_repository(script, owner):
                    return True
            if isinstance(parent, (ast.Try, ast.TryStar)) and parent.handlers:
                if child in parent.orelse and _try_calls_repository(script, parent):
                    return True
                if child in parent.body:
                    earlier = parent.body[: parent.body.index(child)]
                    if any(script.calls_repository(statement) for statement in earlier) and not any(
                        isinstance(sub, ast.Raise) for statement in parent.body for sub in ast.walk(statement)
                    ):
                        return True
            child, parent = parent, parents.get(parent)
        return False

    covered: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            inside = [c for arg in node.args for c in ast.walk(arg) if c in marked]
            if inside and decided(node):
                covered.update(id(c) for c in inside)
    return all(id(c) in covered for c in marked)


def ast_block_reason(source: str, packages: set[str]) -> str | None:
    """Reject reproducers that do not call the repository, read its source, get around the trace, change the repository
    or what it returned, or print no marker that a repository result decides. Decided before anything runs."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "reproducer is not valid Python"
    module_aliases: set[str] = set()
    func_aliases: set[str] = set()
    reads_source = False
    blocked = False
    has_import = False
    has_call = False

    class Scanner(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            nonlocal has_import, blocked
            for alias in node.names:
                root_name = alias.name.split(".")[0]
                if root_name in packages:
                    has_import = True
                    module_aliases.add(alias.asname or root_name)
                elif root_name in BLOCKED_MODULES or tuple(alias.name.split(".")[:2]) in BLOCKED_ATTRS:
                    blocked = True
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            nonlocal has_import, blocked
            root_name = (node.module or "").split(".")[0]
            if root_name in packages:
                has_import = True
                for alias in node.names:
                    func_aliases.add(alias.asname or alias.name)
            elif (root_name in BLOCKED_MODULES or tuple((node.module or "").split(".")[:2]) in BLOCKED_ATTRS
                  or any((root_name, alias.name) in BLOCKED_ATTRS for alias in node.names)):
                blocked = True
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal has_call
            func = node.func
            if isinstance(func, ast.Name) and func.id in func_aliases:
                has_call = True
            elif isinstance(func, ast.Attribute):           # pkg.fn(), pkg.mod.fn(), and mod.fn() after `from pkg import mod`
                base = func.value
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name) and (base.id in module_aliases or base.id in func_aliases):
                    has_call = True
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            nonlocal reads_source, blocked
            if node.attr == "__file__":
                reads_source = True
            if isinstance(node.value, ast.Name) and (node.value.id, node.attr) in BLOCKED_ATTRS:
                blocked = True
            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:
            nonlocal reads_source
            if isinstance(node.value, str) and node.value.endswith(".py"):
                reads_source = True
            self.generic_visit(node)

    Scanner().visit(tree)
    if reads_source:
        return "reproducer reads source text"
    if blocked:
        return "reproducer uses a blocked module or attribute"
    if not has_import:
        return "reproducer does not import the repository"
    script = _Script(tree, packages)
    if script.changes_repository():
        return CHANGES
    if not has_call:
        return "reproducer does not call the repository"
    if not _marker_is_decided(script):
        return f"reproducer has no {MARKER} marker in a branch"
    return None


@dataclass(frozen=True)
class FuncDef:
    """A function or method of the library: its file, its dotted name inside the file, and the lines its code object may
    report as its first (the `def` line, or the first decorator)."""

    file: str
    parts: tuple[str, ...]
    lines: tuple[int, ...]


@functools.lru_cache(maxsize=16)
def _function_index(root: str) -> tuple[FuncDef, ...]:
    from alien_hunt.atoms import _py_files

    found: list[FuncDef] = []
    base = Path(root)
    for path in _py_files(base):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, ValueError):
            continue
        relative = path.relative_to(base).as_posix()

        def walk(node: ast.AST, prefix: tuple[str, ...]) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    parts = (*prefix, child.name)
                    if not isinstance(child, ast.ClassDef):
                        lines = {child.lineno, *(d.lineno for d in child.decorator_list)}
                        found.append(FuncDef(relative, parts, tuple(sorted(lines))))
                    walk(child, parts)
                else:
                    walk(child, prefix)

        walk(tree, ())
    return tuple(found)


def function_index(root: Path) -> tuple[FuncDef, ...]:
    return _function_index(str(root.resolve()))


def _claim_parts(name: str) -> tuple[str, ...]:
    """`pkg.mod.Class.fn`, `pkg/mod.py:fn`, `fn()` and `pkg.fn(0)` as their dotted parts: the file and the call are dropped."""

    text = name.split("(")[0].strip()
    if ":" in text:
        text = text.rsplit(":", 1)[1]
    return tuple(part for part in text.split(".") if part)


def _function_tail(name: str) -> str:
    """The bare function in a claim's name: `pkg.mod.Class.fn`, `pkg/mod.py:fn` or `fn()` all give `fn`."""

    return re.split(r"[.:]", name.split("(")[0].strip())[-1]


def _entered(claim: Claim, defs: tuple[FuncDef, ...], sites: list, run_root: str) -> bool:
    """A function the claim names ran, by file and line. `Class.fn` means that class's `fn`, not any `fn`; a name with no
    definition of its own in the library (a method inherited from a base, say) is matched by its bare name."""

    prefix = run_root.rstrip("/") + "/"
    seen = {(str(file)[len(prefix):] if str(file).startswith(prefix) else str(file), line) for file, line in sites}
    at = {(d.file, line): d for d in defs for line in d.lines}
    ran = [at[site] for site in seen if site in at]
    for name in claim.functions:
        parts = _claim_parts(name)
        if not parts:
            continue
        own = [d for d in defs if (k := min(len(parts), len(d.parts))) and parts[-k:] == d.parts[-k:]]
        if own:
            if any(d in ran for d in own):
                return True
        elif any(d.parts[-1] == parts[-1] for d in ran):
            return True
    return False


def interpret_run(
    claim: Claim,
    exit_code: int,
    calls: list[str],
    output: str,
    *,
    marker_seen: bool,
    sites: list | None = None,
    defs: tuple[FuncDef, ...] | None = None,
    run_root: str = "",
) -> Confirmation:
    """A claim is confirmed only when a function it names was entered, the marker was printed, and the script exited 0.
    `marker_seen` comes from the whole of stdout: `output` is only its tail. With `sites` (the file and first line of each
    library function the trace entered) and `defs`, "entered" means that very function; without them, the same bare name."""

    called = {item.split(":")[-1] for item in calls}
    expected = {tail for tail in map(_function_tail, claim.functions) if tail}
    if not expected:
        return Confirmation(False, "claim names no function", exit_code, output, calls)
    if exit_code != 0:
        return Confirmation(False, "exit status was not 0", exit_code, output, calls)
    if not calls:
        return Confirmation(False, "script did not call repository code", exit_code, output, calls)
    if sites is not None and defs is not None:
        entered = _entered(claim, defs, sites, run_root)
    else:
        entered = not called.isdisjoint(expected)
    if not entered:
        return Confirmation(False, "named function was not called", exit_code, output, calls)
    if not marker_seen:
        return Confirmation(False, f"{MARKER} was not printed", exit_code, output, calls)
    return Confirmation(True, "a named function ran, the marker was printed, and the script exited 0", exit_code, output, calls)


def _read_sites(path: Path) -> list | None:
    """The (file, first line) pairs the runner wrote, or None when it wrote none: then the bare names decide."""

    try:
        sites = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return [site for site in sites if isinstance(site, list) and len(site) == 2] if isinstance(sites, list) else None


def _run_with_sites(
    checkout: Path,
    reproducer: str,
    work: Path,
    *,
    python: str,
    extra_env: dict[str, str] | None = None,
    argv_prefix: list[str] | None = None,
    timeout: int = 60,
) -> tuple[int, list[str], str, bool, list]:
    """Returns the exit code, the traced calls, the output's tail, whether stdout had the marker, and the file and first
    line of each library function entered."""

    work.mkdir(parents=True, exist_ok=True)
    repro_path = work / "repro.py"
    runner_path = work / "trace_runner.py"
    calls_path = work / "calls.json"
    repro_path.write_text(reproducer, encoding="utf-8")
    runner_path.write_text(_RUNNER, encoding="utf-8")
    env = {
        "PATH": os_path(),
        "PYTHONPATH": os.pathsep.join([str(checkout / "src"), str(checkout)] if src_layout(checkout) else [str(checkout)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if extra_env:
        env.update(extra_env)
    command = [*(argv_prefix or []), python, str(runner_path), str(repro_path), str(calls_path), str(checkout)]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        env=env,
        check=False,
    )
    marker_seen = MARKER in (completed.stdout or "")
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    try:
        calls = json.loads(calls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        calls = []
    if not isinstance(calls, list):
        calls = []
    return completed.returncode, [str(item) for item in calls], output, marker_seen, _read_sites(work / "calls.sites.json")


def os_path() -> str:
    import os

    return os.environ.get("PATH", "")


def _run_runner(checkout: Path, reproducer: str, work: Path, **kwargs) -> tuple[int, list[str], str, bool]:
    """Returns the exit code, the traced calls, the output's tail, and whether stdout had the marker."""

    return _run_with_sites(checkout, reproducer, work, **kwargs)[:4]


def confirm_local(claim: Claim, checkout: Path, work: Path, *, python: str | None = None) -> Confirmation:
    """Run the trace wrapper on the host. Used for fixtures, not for model output in the CLI."""

    packages = set(package_names(checkout))
    blocked = ast_block_reason(claim.reproducer, packages)
    if blocked:
        return Confirmation(False, blocked)
    import sys

    try:
        code, calls, output, marker_seen, sites = _run_with_sites(
            checkout,
            claim.reproducer,
            work,
            python=python or sys.executable,
        )
    except subprocess.TimeoutExpired:
        return Confirmation(False, "timed out")
    return interpret_run(
        claim, code, calls, output, marker_seen=marker_seen, sites=sites, defs=function_index(checkout),
        run_root=os.path.realpath(checkout),
    )


def python_tag_for(image: str) -> str:
    """The CPython wheel tag of a `python:3.X...` image (`docker.io/library/python:3.12-slim` gives `cp312`); cp310 for
    an image whose name says no version. joserfc needs 3.11 or later, and the run fetched cp310 wheels whatever the
    container."""

    match = re.search(r"python:3\.(\d+)", image)
    return f"cp3{match.group(1)}" if match else "cp310"


def wheel_compatible(filename: str, python_tag: str = "cp310", arch: str = "x86_64") -> bool:
    """Accept a pure-Python wheel, or a glibc Linux wheel for the container's CPython and architecture: built for
    exactly that version, or for the stable ABI (`abi3`) from any earlier 3.x. A musllinux wheel does not run on the
    container (Debian); cryptography ships only `cp36-abi3` wheels, which the first filter never picked."""

    if not filename.endswith(".whl"):
        return False
    if any(token in filename for token in ("macosx", "win32", "win_amd64", "musllinux")):
        return False
    if "py3-none-any" in filename or "py2.py3-none-any" in filename:
        return True
    if not any(token in filename for token in ("manylinux", "linux_")) or arch not in filename:
        return False
    parts = filename[:-4].split("-")
    if len(parts) < 5:
        return False
    interp, abi = parts[-3], parts[-2]
    if python_tag in interp.split("."):
        return True
    want = int(python_tag[3:]) if python_tag.startswith("cp3") and python_tag[3:].isdigit() else 0
    return abi == "abi3" and any(
        tag.startswith("cp3") and tag[3:].isdigit() and int(tag[3:]) <= want for tag in interp.split(".")
    )


def parse_upload_time(value: str | None) -> datetime | None:
    """Parse a PyPI upload timestamp as an aware UTC datetime."""

    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def pick_wheel(
    files: list[dict],
    commit_time: datetime,
    *,
    version: str | None = None,
    python_tag: str = "cp310",
    arch: str | None = None,
) -> dict | None:
    """Newest compatible wheel uploaded on or before the commit."""

    chosen_arch = arch or linux_arch()
    when = commit_time if commit_time.tzinfo else commit_time.replace(tzinfo=timezone.utc)
    eligible: list[tuple[datetime, dict]] = []
    for item in files:
        if item.get("packagetype") not in (None, "bdist_wheel"):
            continue
        if version and item.get("version") not in (None, version):
            continue
        filename = str(item.get("filename") or "")
        if not wheel_compatible(filename, python_tag, chosen_arch):
            continue
        uploaded = parse_upload_time(item.get("upload_time_iso_8601") or item.get("upload_time"))
        if uploaded is None or uploaded > when:
            continue
        eligible.append((uploaded, item))
    if not eligible:
        return None
    eligible.sort(key=lambda pair: pair[0])
    return eligible[-1][1]


def parse_requirement(line: str) -> tuple[str, str | None] | None:
    """Return a project name and an exact pin, if the line has one."""

    raw = line.split("#", 1)[0].strip()
    if not raw or raw.startswith("-"):
        return None
    if ";" in raw:
        raw, marker = raw.split(";", 1)
        marker = marker.lower()
        if "win32" in marker or "darwin" in marker:
            return None
    raw = re.sub(r"\[.*?\]", "", raw).strip()
    match = _REQ.match(raw)
    if not match:
        return None
    return match.group(1), match.group(2)


def dependency_names(root: Path) -> list[tuple[str, str | None]]:
    """Dependencies declared in pyproject.toml, setup.cfg, or requirements.txt.

    setup.py is not executed.
    """

    found: list[tuple[str, str | None]] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            data = {}
        for entry in data.get("project", {}).get("dependencies") or []:
            parsed = parse_requirement(str(entry))
            if parsed:
                found.append(parsed)
    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file():
        parser = configparser.ConfigParser()
        parser.read_string(setup_cfg.read_text(encoding="utf-8"))
        if parser.has_option("options", "install_requires"):
            block = parser.get("options", "install_requires")
            for line in block.splitlines():
                parsed = parse_requirement(line)
                if parsed:
                    found.append(parsed)
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            parsed = parse_requirement(line)
            if parsed:
                found.append(parsed)
    unique: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for name, version in found:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append((name, version))
    return unique


def pypi_release_files(payload: dict) -> list[dict]:
    """Flatten a PyPI JSON document into file records tagged with their version."""

    files: list[dict] = []
    for version, items in (payload.get("releases") or {}).items():
        for item in items:
            copied = dict(item)
            copied["version"] = version
            files.append(copied)
    return files


def fetch_pypi_files(name: str) -> list[dict]:
    """Download the release index for one project."""

    url = f"https://pypi.org/pypi/{name}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "alien-hunt"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    return pypi_release_files(payload)


# Import names that are not their package's name on PyPI.
IMPORT_TO_DIST = {
    "yaml": "PyYAML", "Crypto": "pycryptodome", "Cryptodome": "pycryptodomex", "OpenSSL": "pyOpenSSL",
    "PIL": "Pillow", "dateutil": "python-dateutil", "bs4": "beautifulsoup4", "sklearn": "scikit-learn",
    "cv2": "opencv-python-headless", "jose": "python-jose", "jwt": "PyJWT", "nacl": "PyNaCl", "magic": "python-magic",
    "dns": "dnspython", "attr": "attrs", "pkg_resources": "setuptools", "serial": "pyserial", "usb": "pyusb",
    "zmq": "pyzmq", "google": "protobuf", "markdown": "Markdown", "multipart": "python-multipart",
}


def reproducer_imports(sources: list[str], own: set[str]) -> list[str]:
    """Top-level names the reproducers import that are neither the standard library nor the repository's own.

    The third PyJWT run's two hunt claims imported `cryptography`, an optional extra the project does not declare as a
    dependency; nothing installed it, both scripts stopped on the import, and a replay with it confirmed both."""

    names: set[str] = set()
    for source in sources:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names.add(node.module.split(".")[0])
    stdlib = set(getattr(sys, "stdlib_module_names", ()))
    return sorted(name for name in names if name not in stdlib and name not in own and not name.startswith("_"))


def _marker_applies(marker: str) -> bool:
    """A requirement's environment marker, roughly: no extras, nothing only for Windows or macOS."""

    lowered = marker.lower()
    return "extra" not in lowered and "win32" not in lowered and "darwin" not in lowered and "windows" not in lowered


def fetch_pypi_requires(name: str, version: str) -> list[str]:
    """Requires-Dist of one release."""

    url = f"https://pypi.org/pypi/{name}/{version}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "alien-hunt"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    return list((payload.get("info") or {}).get("requires_dist") or [])


def wheel_requires(path: Path) -> list[str]:
    """Requires-Dist from a wheel's own METADATA. PyPI's JSON leaves them out for some releases: for cryptography
    35.0.0 it says none, and cffi was never fetched."""

    try:
        with zipfile.ZipFile(path) as archive:
            name = next((n for n in archive.namelist() if n.count("/") == 1 and n.endswith(".dist-info/METADATA")), None)
            if name is None:
                return []
            text = archive.read(name).decode("utf-8", "replace")
    except (OSError, zipfile.BadZipFile):
        return []
    return [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("Requires-Dist:")]


def resolve_wheels(
    wanted: list[tuple[str, str | None]],
    commit_time: datetime,
    *,
    python_tag: str = "cp310",
    arch: str | None = None,
    fetch=None,
    requires=None,
    limit: int = 60,
) -> tuple[list[dict], list[str]]:
    """The wanted packages and their dependencies, each as the newest compatible wheel uploaded on or before the
    commit. `requires(item)` gives a chosen wheel's Requires-Dist (default: PyPI's JSON for that version). Returns the
    chosen file records (with "name") and the names that had none."""

    fetch = fetch or fetch_pypi_files
    requires = requires or (lambda item: fetch_pypi_requires(item["name"], str(item.get("version") or "")))
    queue = list(wanted)
    seen: set[str] = set()
    chosen: list[dict] = []
    missing: list[str] = []
    while queue and len(seen) < limit:
        name, version = queue.pop(0)
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            files = fetch(name)
        except Exception:
            missing.append(name)
            continue
        item = pick_wheel(files, commit_time, version=version, python_tag=python_tag, arch=arch)
        if item is None:
            missing.append(name)
            continue
        record = dict(item, name=name)
        chosen.append(record)
        try:
            needs = requires(record)
        except Exception:
            needs = []
        for entry in needs:
            spec, _, marker = str(entry).partition(";")
            if marker and not _marker_applies(marker):
                continue
            parsed = parse_requirement(spec)
            if parsed:
                queue.append((parsed[0], None))
    return chosen, missing


def prepare_wheels(
    root: Path,
    commit_time: datetime,
    work: Path,
    *,
    python_tag: str = "cp310",
    imports: list[str] | None = None,
    fetch=None,
    fetch_requires=None,
    download=None,
) -> DepsStatus:
    """Download wheels uploaded on or before the commit: the declared dependencies, the third-party packages the
    reproducers import (`imports`), and their own dependencies. Nothing is built from source. A package with no wheel
    is named in `why` and left out; the reproducers that need it fail on their own, the others still run. So is a wheel
    that does not match the index's sha256."""

    deps = dependency_names(root)
    have = {re.sub(r"[-_.]+", "-", name).lower() for name, _version in deps}
    for name in imports or []:
        dist = IMPORT_TO_DIST.get(name, name)
        if re.sub(r"[-_.]+", "-", dist).lower() not in have:
            deps.append((dist, None))
            have.add(re.sub(r"[-_.]+", "-", dist).lower())
    if not deps:
        return DepsStatus(True, "no third-party dependencies")
    wheels = work / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    target = work / "deps"
    target.mkdir(parents=True, exist_ok=True)
    download = download or urllib.request.urlretrieve
    fetch_requires = fetch_requires or fetch_pypi_requires
    downloaded: set[str] = set()
    corrupt: list[str] = []

    def requires(item: dict) -> list[str]:
        """Download the chosen wheel now and read its own Requires-Dist; PyPI's JSON only when it has none."""

        link = str(item.get("url") or "")
        path = wheels / Path(str(item.get("filename") or "package.whl")).name
        if link.startswith("https://"):
            try:
                download(link, path)
                expected = (item.get("digests") or {}).get("sha256")
                if expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    path.unlink(missing_ok=True)
                    corrupt.append(item["name"])
                else:
                    downloaded.add(item["name"])
            except Exception:
                pass
        return wheel_requires(path) or fetch_requires(item["name"], str(item.get("version") or ""))

    chosen, missing = resolve_wheels(deps, commit_time, python_tag=python_tag, fetch=fetch, requires=requires)
    names = [item["name"] for item in chosen if item["name"] in downloaded]
    missing += [item["name"] for item in chosen if item["name"] not in downloaded and item["name"] not in corrupt]
    bad = f"; checksum mismatch for {', '.join(corrupt[:10])}" if corrupt else ""
    if not names:
        return DepsStatus(True, "no wheel for any dependency on or before the commit: " + ", ".join(missing[:10]) + bad)
    requirements = work / "requirements.txt"
    requirements.write_text("\n".join(names) + "\n", encoding="utf-8")
    why = "wheels downloaded" + (f"; none for {', '.join(missing[:10])}" if missing else "") + bad
    return DepsStatus(True, why, target)


def podman_exec_argv(
    image: str,
    checkout: Path,
    work: Path,
    result: Path,
    deps: Path | None,
    *,
    name: str | None = None,
) -> list[str]:
    """Podman invocation: no network, checkout mounted read-only. `name` lets a timeout find the container."""

    # The checkout comes first, so an installed package of the same name never shadows the code under review.
    own = "/src/src:/src" if src_layout(checkout) else "/src"
    pythonpath = own if deps is None else f"{own}:/opt/deps"
    argv = [
        "podman",
        "run",
        "--rm",
        *(["--name", name] if name else []),
        "--network",
        "none",
        *HARDENING,
        "--read-only",
        "--tmpfs",
        "/tmp",
        "-v",
        f"{checkout.resolve()}:/src:ro",
        "-v",
        f"{work.resolve()}:/work:ro",
        "-v",
        f"{result.resolve()}:/result",
        "-e",
        f"PYTHONPATH={pythonpath}",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "PYTHONPYCACHEPREFIX=/tmp",
    ]
    if deps is not None:
        argv.extend(["-v", f"{deps.resolve()}:/opt/deps:ro"])
    argv.extend(
        [
            image,
            "python",
            "/work/trace_runner.py",
            "/work/repro.py",
            "/result/calls.json",
            "/src",
        ]
    )
    return argv


def podman_pip_argv(image: str, wheels: Path, deps: Path, requirements: Path, *, name: str | None = None) -> list[str]:
    """Install already-downloaded wheels inside the container. No index, no builds."""

    return [
        "podman",
        "run",
        "--rm",
        *(["--name", name] if name else []),
        "--network",
        "none",
        *HARDENING,
        "-v",
        f"{wheels.resolve()}:/wheels:ro",
        "-v",
        f"{deps.resolve()}:/opt/deps",
        "-v",
        f"{requirements.parent.resolve()}:/req:ro",
        image,
        "python",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--no-deps",
        "--only-binary=:all:",
        "--find-links",
        "/wheels",
        "--target",
        "/opt/deps",
        "-r",
        "/req/requirements.txt",
    ]


def _container_name() -> str:
    return f"alien-hunt-{uuid.uuid4().hex[:12]}"


def _kill_container(name: str) -> None:
    """A timeout ends the podman client, not the container: a runaway script would keep its CPU and memory."""

    try:
        subprocess.run(["podman", "kill", name], capture_output=True, timeout=20, check=False)
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("could not kill container %s: %s", name, exc)


def install_wheels(image: str, work: Path, deps: DepsStatus) -> str | None:
    """Install downloaded wheels. Returns an error string, or None on success."""

    if deps.target is None:
        return None
    wheels = work / "wheels"
    requirements = work / "requirements.txt"
    if not shutil.which("podman"):
        return "podman is not available"
    name = _container_name()
    try:
        completed = subprocess.run(
            podman_pip_argv(image, wheels, deps.target, requirements, name=name),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _kill_container(name)
        return "wheel install timed out"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "pip failed").strip().splitlines()
        return f"wheel install failed: {detail[-1][:300]}"
    return None


def confirm_podman(
    claim: Claim,
    checkout: Path,
    work: Path,
    *,
    image: str,
    deps: DepsStatus,
    timeout: int = 60,
) -> Confirmation:
    """Run one reproducer in Podman. Model output is never executed on the host.

    When the wheels could not be installed the reproducer still runs without them: many need none, and one broken
    wheel must not void every claim. A refusal then carries the reason."""

    packages = set(package_names(checkout))
    blocked = ast_block_reason(claim.reproducer, packages)
    if blocked:
        return Confirmation(False, blocked)
    if not shutil.which("podman"):
        return Confirmation(False, "podman is not available")
    slot = work / "podman"
    result = slot / "result"
    scripts = slot / "scripts"
    result.mkdir(parents=True, exist_ok=True)
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "repro.py").write_text(claim.reproducer, encoding="utf-8")
    (scripts / "trace_runner.py").write_text(_RUNNER, encoding="utf-8")
    note = "" if deps.ok else f"; dependencies unavailable: {deps.why}"
    name = _container_name()
    argv = podman_exec_argv(image, checkout, scripts, result, deps.target if deps.ok else None, name=name)
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        _kill_container(name)
        return Confirmation(False, "timed out" + note)
    marker_seen = MARKER in (completed.stdout or "")
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    calls_path = result / "calls.json"
    if completed.returncode in (125, 126, 127) and not calls_path.exists():
        # podman or the runtime failed, say a resource flag the host's cgroups refuse: the script never ran
        detail = (completed.stderr or "").strip().splitlines()
        return Confirmation(False, f"the container did not start: {detail[-1][:300] if detail else completed.returncode}",
                            completed.returncode, output)
    try:
        calls = json.loads(calls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        calls = []
    if not isinstance(calls, list):
        calls = []
    confirmation = interpret_run(
        claim, completed.returncode, [str(item) for item in calls], output, marker_seen=marker_seen,
        sites=_read_sites(result / "calls.sites.json"), defs=function_index(checkout), run_root="/src",
    )
    if not confirmation.confirmed:
        confirmation.why += note
    return confirmation
