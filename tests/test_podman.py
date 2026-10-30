"""Podman confirmation of the fixture. Skips when podman or the image is unavailable."""

import shutil
import subprocess
from pathlib import Path

import pytest

from alien_hunt.confirm import DepsStatus, confirm_podman
from alien_hunt.types import Claim

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"
IMAGE = "docker.io/library/python:3.10-slim"

ALLOC = """import sys
from samplelib import allocate

got = allocate(0)
if len(got) != 0:
    sys.exit(0)
sys.exit(1)
"""


def test_podman_confirms_the_fixture_bug(tmp_path: Path):
    if shutil.which("podman") is None:
        pytest.skip("podman is not installed")
    probe = subprocess.run(
        ["podman", "image", "exists", IMAGE],
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        pull = subprocess.run(["podman", "pull", IMAGE], capture_output=True, text=True, check=False)
        if pull.returncode != 0:
            pytest.skip("could not pull the confirmation image")
    claim = Claim(
        text="length",
        class_label="broken-length",
        files=["samplelib/__init__.py"],
        functions=["samplelib.allocate"],
        reproducer=ALLOC,
        origin="hunt",
    )
    result = confirm_podman(
        claim,
        FIXTURE,
        tmp_path,
        image=IMAGE,
        deps=DepsStatus(True, "no third-party dependencies"),
    )
    assert result.confirmed, result.why
    assert result.exit_code == 0
