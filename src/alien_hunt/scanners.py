"""Optional Bandit and local Semgrep or Opengrep rules. Registry packs are never used."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def rules_dir() -> Path:
    """Directory of the rules shipped with this package."""

    return Path(__file__).resolve().parent / "data" / "semgrep"


def semgrep_command(binary: str, root: Path) -> list[str]:
    """Build a scanner command that points only at our rule file."""

    rules = rules_dir() / "python.yml"
    return [
        binary,
        "--disable-version-check",
        "--metrics",
        "off",
        "--config",
        str(rules),
        "--json",
        "--quiet",
        str(root),
    ]


def _habit_lines_from_semgrep(payload: dict) -> list[str]:
    lines = []
    for result in payload.get("results") or []:
        check = result.get("check_id", "rule")
        path = result.get("path", "")
        message = (result.get("extra") or {}).get("message", "")
        lines.append(f"{check} {path} {message}".strip())
    return lines


def _habit_lines_from_bandit(payload: dict) -> list[str]:
    lines = []
    for result in payload.get("results") or []:
        text = result.get("issue_text") or result.get("test_name") or "bandit finding"
        filename = result.get("filename", "")
        lines.append(f"bandit {filename} {text}".strip())
    return lines


def _run(command: list[str], timeout: int) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ""
    return completed.stdout or ""


def run_scanners(root: Path, *, timeout: int = 30) -> list[str]:
    """Return habit texts from scanners that are already installed.

    Semgrep and Opengrep receive only the rules in this package.
    """

    texts: list[str] = []
    bandit = shutil.which("bandit")
    if bandit:
        raw = _run([bandit, "-q", "-f", "json", "-r", str(root)], timeout)
        try:
            texts.extend(_habit_lines_from_bandit(json.loads(raw or "{}")))
        except json.JSONDecodeError:
            pass
    for binary in ("semgrep", "opengrep"):
        path = shutil.which(binary)
        if not path:
            continue
        raw = _run(semgrep_command(path, root), timeout)
        try:
            texts.extend(_habit_lines_from_semgrep(json.loads(raw or "{}")))
        except json.JSONDecodeError:
            continue
    return texts
