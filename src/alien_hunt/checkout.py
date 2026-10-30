"""Fetch a public GitHub repository at one commit. Never push."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_GITHUB = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
_SHA = re.compile(r"[0-9a-fA-F]{7,64}")


class CheckoutError(Exception):
    """The URL or commit cannot be checked out."""


def parse_github_url(url: str) -> tuple[str, str]:
    """Accept only a public https://github.com/owner/repo URL."""

    if "@" in url or not url.startswith("https://"):
        raise CheckoutError("use an https://github.com/owner/repo URL")
    match = _GITHUB.fullmatch(url.strip())
    if not match:
        raise CheckoutError("use an https://github.com/owner/repo URL")
    return match.group(1), match.group(2)


def validate_sha(sha: str) -> str:
    """Commits are full or abbreviated hex shas, not branch names."""

    if not _SHA.fullmatch(sha):
        raise CheckoutError("commit must be a hex sha")
    return sha.lower()


def _git(args: list[str], cwd: Path, env: dict[str, str]) -> None:
    completed = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "git failed").strip()
        raise CheckoutError(detail.splitlines()[-1][:500])


def fetch_github(url: str, sha: str, dest: Path) -> Path:
    """Clone exactly one commit into `dest`. Hooks are disabled and prompts are off."""

    parse_github_url(url)
    commit = validate_sha(sha)
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    _git(["init"], dest, env)
    _git(["remote", "add", "origin", url], dest, env)
    _git(["fetch", "--depth", "1", "origin", commit], dest, env)
    _git(["checkout", "--detach", "FETCH_HEAD"], dest, env)
    return dest


def commit_timestamp(checkout: Path) -> str:
    """ISO timestamp of HEAD, used to pin dependency wheels."""

    completed = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "log", "-1", "--format=%cI"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=False,
    )
    stamp = completed.stdout.strip()
    if completed.returncode != 0 or not stamp:
        raise CheckoutError("could not read the commit timestamp")
    return stamp


def prepare_local(path: Path) -> Path:
    """Use an existing tree. Tests and `--local` go through here."""

    resolved = path.resolve()
    if not resolved.is_dir():
        raise CheckoutError(f"{resolved} is not a directory")
    return resolved
