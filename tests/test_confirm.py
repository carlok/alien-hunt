"""Confirmation policy: source reads do not count, and the call has to land."""

import json
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.confirm import (
    ast_block_reason,
    confirm_local,
    dependency_names,
    parse_requirement,
    pick_wheel,
    podman_exec_argv,
    wheel_compatible,
)
from alien_hunt.types import Claim

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"

PICKLE = """import pickle
import sys
from samplelib import load_config

blob = pickle.dumps({"k": 1})
got = load_config(blob)
if got == {"k": 1}:
    print("DEFECT-OBSERVED")
    sys.exit(0)
sys.exit(1)
"""

ALLOC = """import sys
from samplelib import allocate

got = allocate(0)
if len(got) != 0:
    print("DEFECT-OBSERVED")
    sys.exit(0)
sys.exit(1)
"""


def _claim(functions: list[str], reproducer: str) -> Claim:
    return Claim(
        text="local",
        class_label="fixture",
        files=["samplelib/__init__.py"],
        functions=functions,
        reproducer=reproducer,
        origin="plain",
    )


def test_source_read_is_rejected():
    script = 'from pathlib import Path\nprint(Path("samplelib/__init__.py").read_text())\n'
    reason = ast_block_reason(script, {"samplelib"})
    assert reason == "reproducer reads source text"


def test_import_without_a_call_is_rejected():
    script = "import samplelib\nprint(samplelib.__file__)\n"
    reason = ast_block_reason(script, {"samplelib"})
    assert reason == "reproducer reads source text"


def test_import_without_call_or_source_read():
    script = "import samplelib\nprint('hi')\n"
    reason = ast_block_reason(script, {"samplelib"})
    assert reason == "reproducer does not call the repository"


def test_local_confirm_accepts_the_length_bug(tmp_path: Path):
    result = confirm_local(_claim(["samplelib.allocate"], ALLOC), FIXTURE, tmp_path / "work")
    assert result.confirmed
    assert result.exit_code == 0
    assert any(item.endswith(":allocate") for item in result.calls)


def test_local_confirm_rejects_a_failing_script(tmp_path: Path):
    script = 'from samplelib import allocate\nif allocate(0):\n    print("DEFECT-OBSERVED")\nraise SystemExit(1)\n'
    result = confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "work")
    assert not result.confirmed
    assert result.why == "exit status was not 0"


def test_named_function_must_be_the_one_that_ran(tmp_path: Path):
    result = confirm_local(_claim(["samplelib.load_config"], ALLOC), FIXTURE, tmp_path / "work")
    assert not result.confirmed
    assert result.why == "named function was not called"


def test_wheel_choice_respects_date_platform_and_type():
    when = datetime(2024, 1, 1, tzinfo=timezone.utc)
    files = [
        {
            "packagetype": "sdist",
            "filename": "demo-1.0.0.tar.gz",
            "upload_time_iso_8601": "2023-01-01T00:00:00Z",
            "version": "1.0.0",
        },
        {
            "packagetype": "bdist_wheel",
            "filename": "demo-1.0.0-py3-none-any.whl",
            "upload_time_iso_8601": "2023-06-01T00:00:00Z",
            "version": "1.0.0",
        },
        {
            "packagetype": "bdist_wheel",
            "filename": "demo-1.2.0-py3-none-any.whl",
            "upload_time_iso_8601": "2024-06-01T00:00:00Z",
            "version": "1.2.0",
        },
        {
            "packagetype": "bdist_wheel",
            "filename": "demo-1.1.0-cp310-cp310-macosx_11_0_arm64.whl",
            "upload_time_iso_8601": "2023-12-01T00:00:00Z",
            "version": "1.1.0",
        },
        {
            "packagetype": "bdist_wheel",
            "filename": "demo-1.1.0-cp310-cp310-manylinux_2_17_x86_64.whl",
            "upload_time_iso_8601": "2023-12-15T00:00:00Z",
            "version": "1.1.0",
        },
    ]
    chosen = pick_wheel(files, when, arch="x86_64")
    assert chosen is not None
    assert chosen["filename"] == "demo-1.1.0-cp310-cp310-manylinux_2_17_x86_64.whl"
    pinned = pick_wheel(files, when, version="1.0.0", arch="x86_64")
    assert pinned is not None
    assert pinned["filename"] == "demo-1.0.0-py3-none-any.whl"
    assert not wheel_compatible("demo-1.0.0.tar.gz")
    assert wheel_compatible("demo-1.0.0-py3-none-any.whl")


def test_dependency_parser_skips_setup_py_execution(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests==2.31.0", "demo; sys_platform == \'win32\'"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("leftpad\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text("raise SystemExit('executed')\n", encoding="utf-8")
    found = dependency_names(tmp_path)
    assert ("requests", "2.31.0") in found
    assert ("leftpad", None) in found
    assert all(name != "demo" for name, _version in found)
    assert parse_requirement("foo[extra]>=1") == ("foo", None)


def test_podman_argv_is_offline_and_read_only(tmp_path: Path):
    checkout = tmp_path / "src"
    work = tmp_path / "work"
    result = tmp_path / "result"
    for path in (checkout, work, result):
        path.mkdir()
    argv = podman_exec_argv("python:3.10-slim", checkout, work, result, None)
    rendered = " ".join(argv)
    assert argv[0] == "podman"
    assert "none" in argv
    assert "--network" in argv
    for flag in ("--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=2g", "--cpus=1"):
        assert flag in argv
    assert any(part.endswith(":/src:ro") for part in argv)
    assert any(part.endswith(":/work:ro") for part in argv)
    assert "sk-" not in rendered
    blob = json.dumps(argv)
    assert "ALIEN_HUNT_API_KEY" not in blob


# --- bypasses found by reading the check from outside (reports/offline-tune/SUMMARY.md) ----------------------------
# Each script below was confirmed by the check as it stood, though the code under test behaved correctly or was never
# really exercised. They are minimal forms of the scripts the five red-team routes wrote.

import pytest  # noqa: E402

from alien_hunt.prompts import MARKER  # noqa: E402

NO_BRANCH = f"reproducer has no {MARKER} marker in a branch"
CHANGES = "reproducer replaces or changes repository code or what it returned"
BLOCKED = "reproducer uses a blocked module or attribute"
HEAD = "import sys\nfrom samplelib import allocate\n"
P = f'print("{MARKER}")'


def indent(text: str) -> str:
    return "".join("    " + line + "\n" for line in text.rstrip("\n").splitlines())


@pytest.mark.parametrize(
    "body",
    [
        f"allocate(3)\nif 1 == 1:\n{indent(P)}",
        f"allocate(3)\nif not None:\n{indent(P)}",
        f"allocate(3)\nif len([]) == 0:\n{indent(P)}",
        f"allocate(3)\nif (x := 1):\n{indent(P)}",
        f"allocate(3)\nif (lambda: True)():\n{indent(P)}",
        f"allocate(3)\nflag = 1\nif flag:\n{indent(P)}",
        f"allocate(3)\nif __name__:\n{indent(P)}",
        f'allocate(3)\nif not __name__ != "__main__":\n{indent(P)}',
        f'allocate(3)\nif __name__ == "__main__" and True:\n{indent(P)}',
        f'allocate(3)\nif bool(__name__ == "__main__"):\n{indent(P)}',
        f"got = allocate(3)\nif got or True:\n{indent(P)}",
        f"got = allocate(3)\nif got or 1:\n{indent(P)}",
        f"got = allocate(3)\nif got is got:\n{indent(P)}",
        f"got = allocate(3)\nif got == got:\n{indent(P)}",
        f"got = allocate(3)\nif 0 < 1 < 2:\n{indent(P)}",
        f'got = allocate(3)\nif "a" in "abc":\n{indent(P)}',
        f"got = allocate(3)\nif len(got) >= 0:\n{indent(P)}",                            # a length is never negative
        f"got = allocate(3)\nif len(got) > -1:\n{indent(P)}",
        f"got = allocate(3)\nif not len(got) < 0:\n{indent(P)}",
        f"got = allocate(3)\nif False:\n    pass\nelif True:\n{indent(P)}",
        f"got = allocate(3)\nif False:\n    pass\nelse:\n{indent(P)}",
        f"def check():\n    if 1 == 1:\n{indent(indent(P))}check()\nallocate(3)\n",
    ],
)
def test_a_branch_that_the_repository_does_not_decide_is_refused(body: str):
    assert ast_block_reason(HEAD + body, {"samplelib"}) == NO_BRANCH


@pytest.mark.parametrize(
    "body",
    [
        f"allocate(3)\n{P}\ntry:\n    pass\nexcept KeyError:\n{indent(P)}",                            # a decoy handler
        f"allocate(3)\n{P}\nif len(allocate(3)) != 3:\n{indent(P)}",                                    # one honest print is not enough
        f'allocate(3)\nsys.stdout.write("{MARKER}")\nif len(allocate(3)) != 3:\n{indent(P)}',          # nor a write beside it
        f"allocate(3)\ntry:\n    pass\nexcept ValueError:\n    pass\nelse:\n{indent(P)}",             # a try that calls nothing
        f"allocate(3)\ntry:\n    pass\nexcept Exception:\n{indent(P)}",
        f"allocate(3)\ntry:\n    str(1)\n{indent(P)}except Exception:\n    raise SystemExit(1)\n",       # an earlier call that is not the repository's
        f'try:\n    allocate(3)\n    raise RuntimeError("mine")\nexcept RuntimeError:\n{indent(P)}',   # the script raised it
        f'try:\n    raise ValueError("mine")\n    allocate(3)\nexcept ValueError:\n{indent(P)}',
        f'try:\n    allocate(3)\n    raise ValueError("mine")\nexcept ValueError:\n    raise SystemExit(1)\nelse:\n{indent(P)}',
        f"flag = [1]\nallocate(3)\nif flag:\n{indent(P)}",                                            # state the script made
        f'import os\nallocate(3)\nos.environ["X"] = "1"\nif os.environ["X"] == "1":\n{indent(P)}',
        f"class Fake:\n    ok = True\nfake = Fake()\nfake.ok = False\nallocate(3)\nif not fake.ok:\n{indent(P)}",
        f"seen = []\nallocate(3)\nseen.append(1)\nif seen:\n{indent(P)}",
    ],
)
def test_a_marker_no_repository_result_or_exception_decides_is_refused(body: str):
    assert ast_block_reason(HEAD + body, {"samplelib"}) == NO_BRANCH


@pytest.mark.parametrize(
    "script",
    [
        # patch the library, then test the patch
        f"import samplelib\norig = samplelib.allocate\ndef bad(n):\n    orig(n)\n    return [0] * (n + 1)\n"
        f"samplelib.allocate = bad\nif len(samplelib.allocate(3)) != 3:\n{indent(P)}",
        f"import samplelib\nsamplelib.pickle = object()\nif samplelib.load_config(b'x'):\n{indent(P)}",
        f"import asciitree\nasciitree.LeftAligned = lambda **k: (lambda t: '')\nif asciitree.draw_tree({{}}) == '':\n{indent(P)}",
        f"import asciitree\nasciitree.LegacyStyle.child_head = lambda *a: ''\nif asciitree.draw_tree({{}}) == '':\n{indent(P)}",
        f"import samplelib\nsetattr(samplelib, 'allocate', lambda n: [])\nif samplelib.allocate(3) == []:\n{indent(P)}",
        f"import samplelib\ndelattr(samplelib, 'allocate')\nif samplelib:\n{indent(P)}",
        # shadow a repository name
        f"from samplelib import allocate\nallocate(3)\ndef allocate(n):\n    return [0]\nif len(allocate(3)) != 3:\n{indent(P)}",
        f"from samplelib import allocate\nallocate(3)\nallocate = lambda n: []\nif allocate(3) == []:\n{indent(P)}",
        # subclass a repository class and test the subclass
        f"from asciitree import LeftAligned\nclass Sub(LeftAligned):\n    def __call__(self, tree):\n        return ''\n"
        f"if Sub()({{}}) == '':\n{indent(P)}",
        # change what the repository returned, then test the change
        f"r = allocate(3)\nr.append(0)\nif len(r) != 3:\n{indent(P)}",
        f"r = allocate(3)\nr[0] = 1\nif r[0] != 0:\n{indent(P)}",
        f"r = allocate(3)\ndel r[0]\nif len(r) != 3:\n{indent(P)}",
    ],
)
def test_replacing_repository_code_or_its_results_is_refused(script: str):
    source = script if script.startswith(("import", "from")) else HEAD + script
    assert ast_block_reason(source, {"samplelib", "asciitree"}) == CHANGES


@pytest.mark.parametrize(
    "line",
    ["import mock", "from unittest import mock", "from unittest.mock import patch", "import unittest.mock",
     "import unittest\nunittest.mock.patch.object"],
)
def test_mocking_the_repository_is_blocked(line: str):
    script = f"{line}\nfrom samplelib import allocate\nif allocate(0):\n    {P}\n"
    assert ast_block_reason(script, {"samplelib"}) == BLOCKED


@pytest.mark.parametrize(
    "body",
    [
        f"got = allocate(0)\nif got:\n    if len(got) > 3:\n{indent(indent(P))}",
        f"def check():\n    return len(allocate(0)) != 0\nif check():\n{indent(P)}",
        f"try:\n    allocate(3)\nexcept Exception:\n{indent(P)}",                       # a crash on valid input is a defect
        f"for n in range(3):\n    got = allocate(n)\n    if len(got) != n:\n{indent(indent(P))}",
        f"if (got := allocate(0)) and len(got) != 0:\n{indent(P)}",
        f"if allocate(3) != allocate(3):\n{indent(P)}",                                 # two calls, a determinism check
        f"import samplelib\nif samplelib.__name__ != 'samplelib' or samplelib.allocate(0):\n{indent(P)}",
        f"first, second = allocate(1), allocate(2)\nif len(first) == len(second):\n{indent(P)}",
        f"got = allocate(0)\nok = len(got) == 0\nif not ok:\n{indent(P)}",
        f"got = allocate(0)\nif len(got) > 0:\n{indent(P)}",
        f"got = allocate(0)\nif len(got) >= 1:\n{indent(P)}",
        f"out = []\nout.append(allocate(0))\nif len(out[0]) != 0:\n{indent(P)}",             # a list the script fed with results
        f"got = allocate(0)\nsize = len(got)\nsize = size + 1\nif size > 1:\n{indent(P)}",
        f'if allocate(0):\n    print(f"{MARKER} {{len(allocate(0))}}")\n',
    ],
)
def test_the_honest_shapes_still_pass(body: str):
    assert ast_block_reason(HEAD + body, {"samplelib"}) is None


def _repo(tmp_path: Path, text: str) -> Path:
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text(text, encoding="utf-8")
    return root


def test_a_function_run_by_the_import_is_not_a_function_entered(tmp_path: Path):
    root = _repo(
        tmp_path,
        "class Base:\n    def __init__(self):\n        self.x = 1\n\ndefault = Base()\n\ndef run():\n    return 1\n",
    )
    honest = f'import pkg\nif pkg.run() == 1:\n    {P}\n'
    assert confirm_local(_claim(["pkg.Base.__init__"], honest), root, tmp_path / "a").why == "named function was not called"
    builds = f'import pkg\nif pkg.Base().x == 1:\n    {P}\n'
    assert confirm_local(_claim(["pkg.Base.__init__"], builds), root, tmp_path / "b").confirmed


def test_a_same_named_method_of_another_class_is_not_the_one_named(tmp_path: Path):
    root = _repo(
        tmp_path,
        "class A:\n    def go(self):\n        return 1\n\nclass B:\n    def go(self):\n        return 2\n",
    )
    calls_b = f'import pkg\nif pkg.B().go() == 2:\n    {P}\n'
    calls_a = f'import pkg\nif pkg.A().go() == 1:\n    {P}\n'
    assert confirm_local(_claim(["pkg.A.go"], calls_b), root, tmp_path / "a").why == "named function was not called"
    assert confirm_local(_claim(["pkg.A.go"], calls_a), root, tmp_path / "b").confirmed
    assert confirm_local(_claim(["go"], calls_b), root, tmp_path / "c").confirmed        # a bare name still matches any


def test_an_inherited_method_is_matched_by_its_name(tmp_path: Path):
    root = _repo(tmp_path, "class Base:\n    def __init__(self):\n        self.x = 1\n\nclass Child(Base):\n    pass\n")
    script = f'import pkg\nif pkg.Child().x == 1:\n    {P}\n'
    assert confirm_local(_claim(["pkg.Child.__init__"], script), root, tmp_path / "w").confirmed


def test_a_function_the_script_defines_under_a_repository_path_is_not_a_repository_call(tmp_path: Path):
    root = _repo(tmp_path, "def real():\n    return 1\n\ndef other():\n    return 0\n")
    ghost = str(root / "pkg" / "ghost")                    # no such file, and no .py in the name
    script = (
        f"import pkg\ngot = pkg.other()\nns = {{}}\nexec(compile('def real():\\n    return 2\\n', {ghost!r}, 'exec'), ns)\n"
        f"if ns['real']() == 2 and got == 0:\n    {P}\n"
    )
    result = confirm_local(_claim(["pkg.real"], script), root, tmp_path / "w")
    assert not result.confirmed
    assert result.why == "named function was not called"


def test_a_call_made_from_a_thread_is_traced(tmp_path: Path):
    script = (
        "import threading\nfrom samplelib import allocate\nout = []\n"
        "t = threading.Thread(target=lambda: out.append(allocate(0)))\nt.start()\nt.join()\n"
        f"if len(out[0]) != 0:\n    {P}\n"
    )
    result = confirm_local(_claim(["samplelib.allocate"], script), FIXTURE, tmp_path / "w")
    assert result.confirmed, result.why
