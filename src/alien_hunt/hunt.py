"""Directed hunts and the incoherence judgement."""

from __future__ import annotations

from pathlib import Path

from alien_hunt.agent import AgentResult, PaidModel, run_agent
from alien_hunt.types import Candidate

_SYSTEM = """You are hunting one specific defect shape in a Python repository.
Use only list_dir, read_file, and search.
Decide whether the named combination can occur on a real path in this tree.
Submit claims only for that combination.
Each claim needs text, class, files, functions, and a Python reproducer.
The reproducer must import the repository and call the function under test.
It must exit 0 only when that call observed the defect.
Do not open the repository's .py files from the reproducer.
Set path_exists to false when the combination cannot occur here.
"""


def function_exists(root: Path, name: str) -> bool:
    """True when a function with this short name is defined under the checkout."""

    tail = name.split(".")[-1].split(":")[-1]
    if not tail:
        return False
    for path in root.rglob("*.py"):
        if ".git" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if f"def {tail}(" in text or f"async def {tail}(" in text:
            return True
    return False


def hunt_prompt(candidate: Candidate) -> str:
    """The directed question for one triple."""

    files = ", ".join(candidate.path) or "(no file named yet)"
    return (
        "STAGE: hunt\n"
        f"Candidate {candidate.id}\n"
        f"mechanism_id={candidate.mechanism.id}\n"
        f"Look for this mechanism where the source reaches the sink or breaks the invariant.\n"
        f"Source: {candidate.source.text}\n"
        f"Mechanism: {candidate.mechanism.text}\n"
        f"Sink or invariant: {candidate.other.text}\n"
        f"Start from these files: {files}\n"
    )


def judge_coherence(candidate: Candidate, result: AgentResult, root: Path) -> None:
    """A candidate is incoherent when the hunt denies the path, or every named function is missing."""

    candidate.path_exists = result.path_exists
    named = candidate.named_functions
    missing = bool(named) and all(not function_exists(root, name) for name in named)
    candidate.incoherent = result.path_exists is False or missing


def directed_hunt(
    model: PaidModel,
    root: Path,
    candidate: Candidate,
    *,
    rounds: int,
    token_cap: int,
) -> AgentResult:
    """One focused review for a single candidate."""

    result = run_agent(
        model,
        root,
        stage="hunt",
        system=_SYSTEM,
        user=hunt_prompt(candidate),
        origin="hunt",
        max_rounds=rounds,
        max_claims=10,
        token_cap=token_cap,
        candidate_id=candidate.id,
    )
    judge_coherence(candidate, result, root)
    return result
