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
    sys.exit(0)
sys.exit(1)
"""

ALLOC = """import sys
from samplelib import allocate

got = allocate(0)
if len(got) != 0:
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
    script = "from samplelib import allocate\nallocate(0)\nraise SystemExit(1)\n"
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
    for flag in ("--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=256", "--memory=2g"):
        assert flag in argv
    assert any(part.endswith(":/src:ro") for part in argv)
    assert any(part.endswith(":/work:ro") for part in argv)
    assert "sk-" not in rendered
    blob = json.dumps(argv)
    assert "ALIEN_HUNT_API_KEY" not in blob
