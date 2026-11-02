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
import traceback

repro_path, calls_path, checkout = sys.argv[1], sys.argv[2], sys.argv[3]
root = os.path.realpath(checkout)
calls = []

def tracer(frame, event, arg):
    if event == "call":
        filename = frame.f_code.co_filename or ""
        try:
            resolved = os.path.realpath(filename)
        except OSError:
            resolved = filename
        inside = resolved == root or resolved.startswith(root + os.sep)
        if inside and frame.f_code.co_flags & 1:  # CO_OPTIMIZED: a function, not a module or class body run by the import
            calls.append(f"{resolved}:{frame.f_code.co_name}")
    return tracer

status = 1
try:
    with open(repro_path, encoding="utf-8") as handle:
        code = compile(handle.read(), repro_path, "exec")
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


def _decides_nothing(test: ast.expr) -> bool:
    """`if __name__ == "__main__"` always runs (the runner executes the script as __main__), and so does `if True`."""

    if isinstance(test, ast.Constant):
        return True
    return isinstance(test, ast.Compare) and any(
        isinstance(side, ast.Name) and side.id == "__name__" for side in (test.left, *test.comparators)
    )


def _marker_is_conditional(tree: ast.AST) -> bool:
    """True when a print call that names the marker sits in an `if` body or `else`, an `except`, or a `try`'s `else`
    (the call raised nothing, which is the defect when it should have refused the input)."""

    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print"):
            continue
        if not any(
            isinstance(part, ast.Constant) and isinstance(part.value, str) and MARKER in part.value
            for arg in node.args
            for part in ast.walk(arg)
        ):
            continue
        child: ast.AST = node
        parent = parents.get(node)
        while parent is not None:
            if isinstance(parent, ast.If) and not _decides_nothing(parent.test):
                return True
            if isinstance(parent, ast.ExceptHandler):
                return True
            if isinstance(parent, (ast.Try, ast.TryStar)) and child in parent.orelse:
                return True
            child, parent = parent, parents.get(parent)
    return False


def ast_block_reason(source: str, packages: set[str]) -> str | None:
    """Reject reproducers that do not call the repository, read its source, get around the trace, or print no marker
    from a branch. Decided before anything runs."""

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
                elif root_name in BLOCKED_MODULES:
                    blocked = True
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            nonlocal has_import, blocked
            root_name = (node.module or "").split(".")[0]
            if root_name in packages:
                has_import = True
                for alias in node.names:
                    func_aliases.add(alias.asname or alias.name)
            elif root_name in BLOCKED_MODULES or any((root_name, alias.name) in BLOCKED_ATTRS for alias in node.names):
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
    if not has_call:
        return "reproducer does not call the repository"
    if not _marker_is_conditional(tree):
        return f"reproducer has no {MARKER} marker in a branch"
    return None


def _function_tail(name: str) -> str:
    """The bare function in a claim's name: `pkg.mod.Class.fn`, `pkg/mod.py:fn` or `fn()` all give `fn`."""

    return re.split(r"[.:]", name.split("(")[0].strip())[-1]


def interpret_run(claim: Claim, exit_code: int, calls: list[str], output: str, *, marker_seen: bool) -> Confirmation:
    """A claim is confirmed only when a function it names was entered, the marker was printed, and the script exited 0.
    `marker_seen` comes from the whole of stdout: `output` is only its tail."""

    called = {item.split(":")[-1] for item in calls}
    expected = {tail for tail in map(_function_tail, claim.functions) if tail}
    if not expected:
        return Confirmation(False, "claim names no function", exit_code, output, calls)
    if exit_code != 0:
        return Confirmation(False, "exit status was not 0", exit_code, output, calls)
    if not calls:
        return Confirmation(False, "script did not call repository code", exit_code, output, calls)
    if called.isdisjoint(expected):
        return Confirmation(False, "named function was not called", exit_code, output, calls)
    if not marker_seen:
        return Confirmation(False, f"{MARKER} was not printed", exit_code, output, calls)
    return Confirmation(True, "a named function ran, the marker was printed, and the script exited 0", exit_code, output, calls)


def _run_runner(
    checkout: Path,
    reproducer: str,
    work: Path,
    *,
    python: str,
    extra_env: dict[str, str] | None = None,
    argv_prefix: list[str] | None = None,
    timeout: int = 60,
) -> tuple[int, list[str], str, bool]:
    """Returns the exit code, the traced calls, the output's tail, and whether stdout had the marker."""

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
    return completed.returncode, [str(item) for item in calls], output, marker_seen


def os_path() -> str:
    import os

    return os.environ.get("PATH", "")


def confirm_local(claim: Claim, checkout: Path, work: Path, *, python: str | None = None) -> Confirmation:
    """Run the trace wrapper on the host. Used for fixtures, not for model output in the CLI."""

    packages = set(package_names(checkout))
    blocked = ast_block_reason(claim.reproducer, packages)
    if blocked:
        return Confirmation(False, blocked)
    import sys

    try:
        code, calls, output, marker_seen = _run_runner(
            checkout,
            claim.reproducer,
            work,
            python=python or sys.executable,
        )
    except subprocess.TimeoutExpired:
        return Confirmation(False, "timed out")
    return interpret_run(claim, code, calls, output, marker_seen=marker_seen)


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
    confirmation = interpret_run(claim, completed.returncode, [str(item) for item in calls], output, marker_seen=marker_seen)
    if not confirmation.confirmed:
        confirmation.why += note
    return confirmation
