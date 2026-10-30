"""The review before the public release (2026-10-30): the report printed the names of functions with confirmed
claims, no wheel at all refused every reproducer, two config keys were not checked, and a scanner timeout was a
traceback. These tests pin the fixes."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from alien_hunt.budget import Budget
from alien_hunt.config import ConfigError, load_config
from alien_hunt.confirm import prepare_wheels
from alien_hunt.report import render_report
from alien_hunt.scanners import _run
from alien_hunt.types import Claim

from test_roles import BASE, write


def _claim(origin: str, function: str) -> Claim:
    return Claim(text="t", class_label="logic", files=["pkg/a.py"], functions=[function], reproducer="r",
                 origin=origin)


def test_the_report_counts_shared_functions_without_naming_them():
    claims = [_claim("plain", "pkg.shared_secret_place"), _claim("hunt", "pkg.shared_secret_place")]
    text = render_report(run_id="t", target="fixture", commit="local", budget=Budget(limit_usd=1), claims=claims,
                         top=[], known=[], stopped=False, secret="k")
    assert "shared_secret_place" not in text
    assert "Functions with a confirmed claim on both sides: 1" in text


def test_with_no_wheel_at_all_the_reproducers_still_run(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("alien_hunt.confirm.linux_arch", lambda: "aarch64")
    root = tmp_path / "repo"
    root.mkdir()

    def fetch(name: str) -> list[dict]:
        raise OSError("404")

    status = prepare_wheels(root, datetime(2021, 10, 16, tzinfo=timezone.utc), tmp_path / "work",
                            imports=["nosuchpkg"], fetch=fetch, fetch_requires=lambda name, version: [],
                            download=lambda link, dest: None)
    assert status.ok and status.target is None
    assert "nosuchpkg" in status.why


@pytest.mark.parametrize("extra", ["min_coherence = 7\n", "min_coherence = 0.5\n", "fallback_hunts = -1\n",
                                   "fallback_hunts = \"many\"\n"])
def test_min_coherence_and_fallback_hunts_are_checked(tmp_path, extra):
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, BASE + extra))


def test_fallback_hunts_can_be_turned_off(tmp_path):
    assert load_config(write(tmp_path, BASE + "fallback_hunts = 0\n")).fallback_hunts == 0


def test_a_scanner_that_times_out_gives_no_text(monkeypatch):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr("alien_hunt.scanners.subprocess.run", slow)
    assert _run(["semgrep", "--version"], timeout=1) == ""
