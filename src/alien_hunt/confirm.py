"""Confirm a claim by running its reproducer.

The script must import and call the checkout. Reading source text does not count.
The CLI runs that script in Podman with the network off and the checkout read-only.
"""

from __future__ import annotations

import ast
import configparser
import json
import platform
import re
import shutil
import subprocess
import tomllib
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.habits import package_names
from alien_hunt.types import Claim, Confirmation

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
        if inside and frame.f_code.co_name != "<module>":
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

# Model-written code runs in these containers: no capabilities, no privilege gain, bounded processes and memory.
HARDENING = (
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--pids-limit=256",
    "--memory=2g",
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


def ast_block_reason(source: str, packages: set[str]) -> str | None:
    """Reject reproducers that do not call the repository, or that read its source."""

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return "reproducer is not valid Python"
    module_aliases: set[str] = set()
    func_aliases: set[str] = set()
    reads_source = False
    has_import = False
    has_call = False

    class Scanner(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            nonlocal has_import
            for alias in node.names:
                root_name = alias.name.split(".")[0]
                if root_name in packages:
                    has_import = True
                    module_aliases.add(alias.asname or root_name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            nonlocal has_import
            if node.module and node.module.split(".")[0] in packages:
                has_import = True
                for alias in node.names:
                    func_aliases.add(alias.asname or alias.name)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            nonlocal has_call
            func = node.func
            if isinstance(func, ast.Name) and func.id in func_aliases:
                has_call = True
            elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id in module_aliases and func.attr != "__file__":
                    has_call = True
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            nonlocal reads_source
            if node.attr == "__file__":
                reads_source = True
            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:
            nonlocal reads_source
            if isinstance(node.value, str) and node.value.endswith(".py"):
                reads_source = True
            self.generic_visit(node)

    Scanner().visit(tree)
    if reads_source:
        return "reproducer reads source text"
    if not has_import:
        return "reproducer does not import the repository"
    if not has_call:
        return "reproducer does not call the repository"
    return None


def interpret_run(claim: Claim, exit_code: int, calls: list[str], output: str) -> Confirmation:
    """A claim is confirmed only when the named code ran and the script exited 0."""

    called = {item.split(":")[-1] for item in calls}
    expected = {name.split(".")[-1] for name in claim.functions if name}
    if exit_code != 0:
        return Confirmation(False, "exit status was not 0", exit_code, output, calls)
    if not calls:
        return Confirmation(False, "script did not call repository code", exit_code, output, calls)
    if expected and called.isdisjoint(expected):
        return Confirmation(False, "named function was not called", exit_code, output, calls)
    return Confirmation(
        True,
        "reproducer called the repository and exited 0",
        exit_code,
        output,
        calls,
    )


def _run_runner(
    checkout: Path,
    reproducer: str,
    work: Path,
    *,
    python: str,
    extra_env: dict[str, str] | None = None,
    argv_prefix: list[str] | None = None,
    timeout: int = 60,
) -> tuple[int, list[str], str]:
    work.mkdir(parents=True, exist_ok=True)
    repro_path = work / "repro.py"
    runner_path = work / "trace_runner.py"
    calls_path = work / "calls.json"
    repro_path.write_text(reproducer, encoding="utf-8")
    runner_path.write_text(_RUNNER, encoding="utf-8")
    env = {
        "PATH": os_path(),
        "PYTHONPATH": str(checkout),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if extra_env:
        env.update(extra_env)
    command = [*(argv_prefix or []), python, str(runner_path), str(repro_path), str(calls_path), str(checkout)]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    try:
        calls = json.loads(calls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        calls = []
    if not isinstance(calls, list):
        calls = []
    return completed.returncode, [str(item) for item in calls], output


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
        code, calls, output = _run_runner(
            checkout,
            claim.reproducer,
            work,
            python=python or sys.executable,
        )
    except subprocess.TimeoutExpired:
        return Confirmation(False, "timed out")
    return interpret_run(claim, code, calls, output)


def wheel_compatible(filename: str, python_tag: str = "cp310", arch: str = "x86_64") -> bool:
    """Accept a pure-Python wheel or a Linux wheel for the container."""

    if not filename.endswith(".whl"):
        return False
    if any(token in filename for token in ("macosx", "win32", "win_amd64")):
        return False
    if "py3-none-any" in filename or "py2.py3-none-any" in filename:
        return True
    if python_tag not in filename:
        return False
    if not any(token in filename for token in ("manylinux", "musllinux", "linux_")):
        return False
    return arch in filename


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


def prepare_wheels(
    root: Path,
    commit_time: datetime,
    work: Path,
    *,
    python_tag: str = "cp310",
) -> DepsStatus:
    """Download wheels uploaded on or before the commit. Nothing is built from source."""

    deps = dependency_names(root)
    if not deps:
        return DepsStatus(True, "no third-party dependencies")
    wheels = work / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    target = work / "deps"
    target.mkdir(parents=True, exist_ok=True)
    for name, version in deps:
        try:
            files = fetch_pypi_files(name)
        except Exception as exc:
            return DepsStatus(False, f"could not read the package index for {name}: {exc}")
        chosen = pick_wheel(files, commit_time, version=version, python_tag=python_tag)
        if chosen is None:
            return DepsStatus(False, f"no compatible wheel for {name} on or before the commit")
        link = str(chosen.get("url") or "")
        if not link.startswith("https://"):
            return DepsStatus(False, f"refusing non-https wheel url for {name}")
        filename = str(chosen.get("filename") or "package.whl")
        destination = wheels / filename
        try:
            urllib.request.urlretrieve(link, destination)
        except Exception as exc:
            return DepsStatus(False, f"could not download a wheel for {name}: {exc}")
    requirements = work / "requirements.txt"
    requirements.write_text("\n".join(name for name, _version in deps) + "\n", encoding="utf-8")
    return DepsStatus(True, "wheels downloaded", target)


def podman_exec_argv(
    image: str,
    checkout: Path,
    work: Path,
    result: Path,
    deps: Path | None,
) -> list[str]:
    """Podman invocation: no network, checkout mounted read-only."""

    pythonpath = "/src" if deps is None else "/opt/deps:/src"
    argv = [
        "podman",
        "run",
        "--rm",
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


def podman_pip_argv(image: str, wheels: Path, deps: Path, requirements: Path) -> list[str]:
    """Install already-downloaded wheels inside the container. No index, no builds."""

    return [
        "podman",
        "run",
        "--rm",
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
        "--only-binary=:all:",
        "--find-links",
        "/wheels",
        "--target",
        "/opt/deps",
        "-r",
        "/req/requirements.txt",
    ]


def install_wheels(image: str, work: Path, deps: DepsStatus) -> str | None:
    """Install downloaded wheels. Returns an error string, or None on success."""

    if deps.target is None:
        return None
    wheels = work / "wheels"
    requirements = work / "requirements.txt"
    if not shutil.which("podman"):
        return "podman is not available"
    completed = subprocess.run(
        podman_pip_argv(image, wheels, deps.target, requirements),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
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
) -> Confirmation:
    """Run one reproducer in Podman. Model output is never executed on the host."""

    packages = set(package_names(checkout))
    blocked = ast_block_reason(claim.reproducer, packages)
    if blocked:
        return Confirmation(False, blocked)
    if not shutil.which("podman"):
        return Confirmation(False, "podman is not available")
    if not deps.ok:
        return Confirmation(False, deps.why)
    slot = work / "podman"
    result = slot / "result"
    scripts = slot / "scripts"
    result.mkdir(parents=True, exist_ok=True)
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "repro.py").write_text(claim.reproducer, encoding="utf-8")
    (scripts / "trace_runner.py").write_text(_RUNNER, encoding="utf-8")
    argv = podman_exec_argv(image, checkout, scripts, result, deps.target)
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        return Confirmation(False, "timed out")
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    calls_path = result / "calls.json"
    try:
        calls = json.loads(calls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        calls = []
    if not isinstance(calls, list):
        calls = []
    return interpret_run(claim, completed.returncode, [str(item) for item in calls], output)
