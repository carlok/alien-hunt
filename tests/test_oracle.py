"""On one run, 7 "confirmed" claims were 3 trivial behaviours: the check was only that the script called a function and
exited 0. These tests pin the stricter one (a marker printed from a branch, a named function the trace entered, exit 0),
and the containers and wheels it runs on. Offline, except the last three, which need podman."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from alien_hunt import agent, confirm, habits, hunt
from alien_hunt.confirm import DepsStatus, ast_block_reason, confirm_local, confirm_podman, install_wheels, prepare_wheels
from alien_hunt.prompts import BLOCKED_ATTRS, BLOCKED_MODULES, MARKER
from alien_hunt.types import Claim

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"
IMAGE = "docker.io/library/python:3.10-slim"
GOOD = 'import sys\nfrom samplelib import allocate\nif len(allocate(0)) != 0:\n    print("DEFECT-OBSERVED")\n    sys.exit(0)\nsys.exit(1)\n'


def _claim(functions: list[str], reproducer: str = GOOD) -> Claim:
    return Claim(text="t", class_label="c", files=[], functions=functions, reproducer=reproducer, origin="plain")


@pytest.mark.parametrize(
    "body",
    [
        'if allocate(0):\n    print("DEFECT-OBSERVED")\n',
        'if not allocate(0):\n    pass\nelse:\n    print("DEFECT-OBSERVED")\n',
        'try:\n    allocate(-1)\nexcept ValueError:\n    print("DEFECT-OBSERVED")\n',
        'try:\n    allocate(-1)\nexcept ValueError:\n    raise SystemExit(1)\nelse:\n    print("DEFECT-OBSERVED")\n',
        'try:\n    allocate(-1)\n    print("DEFECT-OBSERVED")\nexcept ValueError:\n    raise SystemExit(1)\n',
        'got = allocate(0)\nif got:\n    print(f"DEFECT-OBSERVED {got}")\n',
        'def main():\n    if allocate(0):\n        print("DEFECT-OBSERVED")\nif __name__ == "__main__":\n    main()\n',
    ],
)
def test_a_marker_in_a_branch_passes(body: str):
    assert ast_block_reason("from samplelib import allocate\n" + body, {"samplelib"}) is None


@pytest.mark.parametrize(
    "body",
    [
        "allocate(0)\n",
        'allocate(0)\nprint("DEFECT-OBSERVED")\n',
        'if __name__ == "__main__":\n    allocate(0)\n    print("DEFECT-OBSERVED")\n',
        'if "__main__" == __name__:\n    allocate(0)\n    print("DEFECT-OBSERVED")\n',
        'allocate(0)\nif True:\n    print("DEFECT-OBSERVED")\n',
        'import sys\nif allocate(0):\n    sys.stdout.write("DEFECT-OBSERVED")\n',
        'MARK = "DEFECT-OBSERVED"\nif allocate(0):\n    print(MARK)\n',
        'allocate(0)\ntry:\n    print("DEFECT-OBSERVED")\nexcept ValueError:\n    pass\n',
        'try:\n    print("DEFECT-OBSERVED")\n    allocate(0)\nexcept ValueError:\n    pass\n',
        'try:\n    allocate(0)\n    print("DEFECT-OBSERVED")\nfinally:\n    pass\n',
    ],
)
def test_a_marker_that_no_branch_decides_is_refused(body: str):
    reason = ast_block_reason("from samplelib import allocate\n" + body, {"samplelib"})
    assert reason == f"reproducer has no {MARKER} marker in a branch"


@pytest.mark.parametrize(
    "line",
    ["import inspect", "from inspect import getsource", "import linecache", "import ctypes", "import __main__",
     "import sys\nsys.settrace(None)", "import os\nos._exit(0)", "from sys import modules"],
)
def test_what_reads_source_or_gets_around_the_trace_is_blocked(line: str):
    script = f'{line}\nfrom samplelib import allocate\nif allocate(0):\n    print("DEFECT-OBSERVED")\n'
    assert ast_block_reason(script, {"samplelib"}) == "reproducer uses a blocked module or attribute"


def test_a_repository_of_that_name_is_its_own_module():
    assert ast_block_reason('import tokenize\nif tokenize.f():\n    print("DEFECT-OBSERVED")\n', {"tokenize"}) is None


@pytest.mark.parametrize(
    "script",
    ["from pkg import mod\nif mod.f():\n", "import pkg.mod\nif pkg.mod.f():\n", "import pkg\nif pkg.mod.f():\n",
     "import pkg.mod as m\nif m.f():\n", "from pkg import Cls\nif Cls.make():\n"],
)
def test_a_call_through_a_module_counts_as_a_call(script: str):
    assert ast_block_reason(script + '    print("DEFECT-OBSERVED")\n', {"pkg"}) is None


def test_a_call_that_raises_keeps_the_marker_in_the_try_from_printing(tmp_path: Path):
    template = 'from samplelib import allocate\ntry:\n    allocate({arg})\n    print("DEFECT-OBSERVED")\nexcept {error}:\n    raise SystemExit(1)\n'
    passed = confirm_local(_claim(["samplelib.allocate"], template.format(arg=0, error="ValueError")), FIXTURE, tmp_path / "a")
    raised = confirm_local(_claim(["samplelib.allocate"], template.format(arg='"x"', error="TypeError")), FIXTURE, tmp_path / "b")
    assert passed.confirmed
    assert (raised.confirmed, raised.exit_code) == (False, 1)


def test_a_branch_not_taken_is_refused_though_the_function_ran(tmp_path: Path):
    script = 'from samplelib import allocate\nif allocate(0) == "never":\n    print("DEFECT-OBSERVED")\n'
    result = confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "w")
    assert (result.confirmed, result.why, result.exit_code) == (False, f"{MARKER} was not printed", 0)
    assert any(item.endswith(":allocate") for item in result.calls)


def test_the_marker_on_stderr_is_not_the_marker(tmp_path: Path):
    script = 'import sys\nfrom samplelib import allocate\nif allocate(0):\n    print("DEFECT-OBSERVED", file=sys.stderr)\n'
    assert confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "w").why == f"{MARKER} was not printed"


def test_a_script_with_no_marker_never_runs(tmp_path: Path):
    script = "from samplelib import allocate\nallocate(0)\n"
    result = confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "w")
    assert not result.confirmed and result.exit_code is None
    assert not (tmp_path / "w").exists()


@pytest.mark.parametrize("functions", [[], [""], ["  "]])
def test_a_claim_that_names_no_function_is_refused(tmp_path: Path, functions: list[str]):
    assert confirm_local(_claim(functions), FIXTURE, tmp_path / "w").why == "claim names no function"


@pytest.mark.parametrize(
    "name", ["samplelib.allocate", "samplelib/__init__.py:allocate", "allocate", "allocate()", "samplelib.allocate(0)"]
)
def test_the_ways_a_model_names_a_function_all_count(tmp_path: Path, name: str):
    result = confirm_local(_claim([name]), FIXTURE, tmp_path / "w")
    assert result.confirmed, result.why


def test_one_entered_function_among_those_named_is_enough(tmp_path: Path):
    assert confirm_local(_claim(["samplelib.load_config", "samplelib.allocate"]), FIXTURE, tmp_path / "w").confirmed


def test_a_class_body_run_by_the_import_is_not_a_function_entered(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("class Thing:\n    x = 1\n\ndef run():\n    return 1\n", encoding="utf-8")
    script = 'from pkg import run\nif run() == 1:\n    print("DEFECT-OBSERVED")\n'
    assert confirm_local(_claim(["pkg.Thing"], script), root, tmp_path / "a").why == "named function was not called"
    assert confirm_local(_claim(["pkg.run"], script), root, tmp_path / "b").confirmed


def test_the_marker_counts_though_the_output_tail_has_lost_it(tmp_path: Path):
    script = GOOD.replace('sys.exit(0)', 'print("x" * 9000)\n    sys.exit(0)')
    result = confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "w")
    assert result.confirmed, result.why
    assert MARKER not in result.output


def test_a_src_layout_confirms_and_the_trace_sees_it(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    script = 'import pkg\nif pkg.f() == 1:\n    print("DEFECT-OBSERVED")\n'
    result = confirm_local(_claim(["pkg.f"], script), root, tmp_path / "w")
    assert result.confirmed, result.why
    assert any("/src/pkg/" in item for item in result.calls)


def test_the_model_is_told_the_rules():
    for system in (habits._SYSTEM, hunt._SYSTEM):
        assert MARKER in system and "if or except branch" in system and "exits 1" in system
        assert all(name in system for name in BLOCKED_MODULES)
        assert all(".".join(pair) in system for pair in BLOCKED_ATTRS)
    fields = agent.SUBMIT_ONLY[0]["function"]["parameters"]["properties"]["claims"]["items"]["properties"]
    assert MARKER in fields["reproducer"]["description"]


class _Run:
    """Stands in for subprocess.run: records each argv, and answers as `answer` says."""

    def __init__(self, answer) -> None:
        self.argv: list[list[str]] = []
        self.answer = answer

    def __call__(self, argv, **kwargs):
        self.argv.append(argv)
        return self.answer(argv, **kwargs)


def _podman(monkeypatch, answer) -> _Run:
    run = _Run(answer)
    monkeypatch.setattr(confirm.subprocess, "run", run)
    monkeypatch.setattr(confirm.shutil, "which", lambda name: "/usr/bin/podman")
    return run


def _finished(code: int, stdout: str = "", stderr: str = "", calls: str | None = None):
    def answer(argv, **kwargs):
        if calls is not None:
            mount = next(part for part in argv if part.endswith(":/result"))
            Path(mount.rsplit(":", 1)[0], "calls.json").write_text(calls, encoding="utf-8")
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    return answer


def test_a_timed_out_container_is_killed(tmp_path: Path, monkeypatch):
    def answer(argv, **kwargs):
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, "", "")

    run = _podman(monkeypatch, answer)
    result = confirm_podman(_claim(["samplelib.allocate"]), FIXTURE, tmp_path, image=IMAGE, deps=DepsStatus(True, "none"))
    assert (result.confirmed, result.why) == (False, "timed out")
    name = run.argv[0][run.argv[0].index("--name") + 1]
    assert run.argv[1] == ["podman", "kill", name]


def test_a_kill_that_fails_does_not_lose_the_refusal(tmp_path: Path, monkeypatch):
    def answer(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    _podman(monkeypatch, answer)
    result = confirm_podman(_claim(["samplelib.allocate"]), FIXTURE, tmp_path, image=IMAGE, deps=DepsStatus(True, "none"))
    assert result.why == "timed out"


def test_without_its_wheels_a_reproducer_still_runs_and_a_refusal_says_why(tmp_path: Path, monkeypatch):
    broken = DepsStatus(False, "wheel install failed: boom", target=tmp_path / "deps")
    calls = '["/src/samplelib/__init__.py:allocate"]'
    run = _podman(monkeypatch, _finished(0, "DEFECT-OBSERVED\n", calls=calls))
    result = confirm_podman(_claim(["samplelib.allocate"]), FIXTURE, tmp_path / "a", image=IMAGE, deps=broken)
    assert result.confirmed, result.why
    assert not any("/opt/deps" in part for part in run.argv[0])

    _podman(monkeypatch, _finished(1, "", "ModuleNotFoundError", calls="[]"))
    result = confirm_podman(_claim(["samplelib.allocate"]), FIXTURE, tmp_path / "b", image=IMAGE, deps=broken)
    assert result.why == "exit status was not 0; dependencies unavailable: wheel install failed: boom"


def test_a_container_that_did_not_start_says_so(tmp_path: Path, monkeypatch):
    _podman(monkeypatch, _finished(125, "", "Error: crun: controller `cpu` is not available\n"))
    result = confirm_podman(_claim(["samplelib.allocate"]), FIXTURE, tmp_path, image=IMAGE, deps=DepsStatus(True, "none"))
    assert not result.confirmed
    assert result.why == "the container did not start: Error: crun: controller `cpu` is not available"


def test_a_wheel_install_that_times_out_is_a_reason_and_is_killed(tmp_path: Path, monkeypatch):
    def answer(argv, **kwargs):
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(argv, 0, "", "")

    run = _podman(monkeypatch, answer)
    assert install_wheels(IMAGE, tmp_path, DepsStatus(True, "x", target=tmp_path / "d")) == "wheel install timed out"
    assert run.argv[1][:2] == ["podman", "kill"]


def _wheel(name: str, digest: str | None) -> dict:
    record = {"filename": f"{name}-1.0-py3-none-any.whl", "version": "1.0", "packagetype": "bdist_wheel",
              "upload_time_iso_8601": "2020-01-01T00:00:00Z", "url": f"https://files.example/{name}-1.0-py3-none-any.whl"}
    return {**record, "digests": {"sha256": digest}} if digest else record


def test_a_wheel_with_the_wrong_checksum_is_dropped_and_the_others_stay(tmp_path: Path):
    good = hashlib.sha256(b"payload").hexdigest()
    index = {"goodpkg": [_wheel("goodpkg", good)], "badpkg": [_wheel("badpkg", "0" * 64)], "plainpkg": [_wheel("plainpkg", None)]}
    root = tmp_path / "repo"
    root.mkdir()
    status = prepare_wheels(
        root, datetime(2021, 1, 1, tzinfo=timezone.utc), tmp_path / "work", imports=sorted(index),
        fetch=lambda name: index[name], fetch_requires=lambda name, version: [],
        download=lambda link, dest: Path(dest).write_bytes(b"payload"),
    )
    assert status.ok and status.target is not None
    assert "checksum mismatch for badpkg" in status.why and "none for" not in status.why
    assert (tmp_path / "work" / "requirements.txt").read_text(encoding="utf-8").split() == ["goodpkg", "plainpkg"]
    assert sorted(path.name.split("-")[0] for path in (tmp_path / "work" / "wheels").iterdir()) == ["goodpkg", "plainpkg"]


def _need_podman() -> None:
    if shutil.which("podman") is None:
        pytest.skip("podman is not installed")
    if subprocess.run(["podman", "image", "exists", IMAGE], capture_output=True, check=False).returncode != 0:
        if subprocess.run(["podman", "pull", IMAGE], capture_output=True, check=False).returncode != 0:
            pytest.skip("could not pull the confirmation image")


def test_podman_the_checkout_of_a_src_layout_comes_before_an_installed_copy(tmp_path: Path):
    _need_podman()
    root = tmp_path / "repo"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("import helper\n\ndef f():\n    return helper.VALUE\n", encoding="utf-8")
    deps = tmp_path / "deps"
    (deps / "pkg").mkdir(parents=True)
    (deps / "pkg" / "__init__.py").write_text("def f():\n    return 'the installed copy'\n", encoding="utf-8")
    (deps / "helper.py").write_text("VALUE = 'a dependency'\n", encoding="utf-8")
    script = 'import pkg\nimport sys\nif pkg.f() == "a dependency":\n    print("DEFECT-OBSERVED")\n    sys.exit(0)\nsys.exit(1)\n'
    result = confirm_podman(_claim(["pkg.f"], script), root, tmp_path / "w", image=IMAGE, deps=DepsStatus(True, "x", target=deps))
    assert result.confirmed, f"{result.why}: {result.output}"
    assert any(item.startswith("/src/src/pkg/") for item in result.calls)


def test_podman_a_call_that_exits_0_without_the_marker_is_refused(tmp_path: Path):
    _need_podman()
    script = 'from samplelib import allocate\nif allocate(0) == "never":\n    print("DEFECT-OBSERVED")\n'
    result = confirm_podman(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path, image=IMAGE, deps=DepsStatus(True, "none"))
    assert (result.confirmed, result.why, result.exit_code) == (False, f"{MARKER} was not printed", 0)


def test_podman_a_runaway_script_leaves_no_container(tmp_path: Path, monkeypatch):
    _need_podman()
    names: list[str] = []
    made = confirm._container_name

    def remember() -> str:
        names.append(made())
        return names[-1]

    monkeypatch.setattr(confirm, "_container_name", remember)
    script = 'from samplelib import allocate\nwhile allocate(0):\n    pass\nif allocate(0):\n    print("DEFECT-OBSERVED")\n'
    result = confirm_podman(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path, image=IMAGE,
                            deps=DepsStatus(True, "none"), timeout=4)
    assert result.why == "timed out"
    alive = subprocess.run(["podman", "ps", "--format", "{{.Names}}", "--filter", f"name={names[0]}"],
                           capture_output=True, text=True, check=False)
    assert names[0] not in alive.stdout
