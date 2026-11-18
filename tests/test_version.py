"""The version has one source, the CLI prints it, and a run records it with what it ran on."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from alien_hunt import __version__
from alien_hunt.budget import Budget
from alien_hunt.cli import main
from alien_hunt.config import Prices
from alien_hunt.pipeline import RUN_FILE, execute

from test_pipeline import FIXTURE, ScriptedModel

ROOT = Path(__file__).resolve().parents[1]


def test_the_package_version_is_the_only_one():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "alien_hunt.__version__"}


def test_the_cli_prints_the_version(capsys):
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0
    assert capsys.readouterr().out.strip() == f"alien-hunt {__version__}"


def test_a_run_records_the_version_target_commit_and_image(tmp_path: Path):
    report = execute(
        FIXTURE,
        model=ScriptedModel(),
        budget=Budget(limit_usd=0),
        prices=Prices(1, 1, 1),
        out_dir=tmp_path,
        confirm_mode="local",
        container_image="docker.io/library/python:3.12-slim",
        scanners=False,
        target="https://github.com/owner/repo",
        commit="a" * 40,
        run_id="recorded",
        seed=7,
    )
    record = json.loads((tmp_path / RUN_FILE).read_text(encoding="utf-8"))
    assert record["alien_hunt"] == __version__
    assert record["target"] == "https://github.com/owner/repo"
    assert record["commit"] == "a" * 40
    assert record["container_image"] == "docker.io/library/python:3.12-slim"
    assert (record["seed"], record["run_id"], record["confirm_mode"]) == (7, "recorded", "local")
    assert f"- alien-hunt: {__version__}" in report.read_text(encoding="utf-8")
