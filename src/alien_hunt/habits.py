"""Plain reviews: three read-only passes, plus optional scanner texts."""

from __future__ import annotations

from pathlib import Path

from alien_hunt.agent import PaidModel, run_agent
from alien_hunt.scanners import run_scanners
from alien_hunt.types import Claim

_SYSTEM = """You are reviewing a Python repository for defects.
Use only list_dir, read_file, and search. Do not assume a defect you did not read.
Submit at most 10 claims through submit_claims.
Each claim needs text, class, files, functions, and a Python reproducer.
The reproducer must import the repository and call the function under test.
It must exit 0 only when that call observed the defect.
Do not open the repository's .py files from the reproducer.
Set path_exists to true.
"""


def src_layout(root: Path) -> bool:
    """True when the checkout keeps its packages under src/ (joserfc does; PyJWT does not)."""

    base = root / "src"
    return base.is_dir() and not (base / "__init__.py").is_file() and any(
        (child / "__init__.py").is_file() for child in base.iterdir() if child.is_dir()
    )


def package_names(root: Path) -> list[str]:
    """Top-level import names in a checkout: at its root, and under src/ for a src layout. joserfc's run found none,
    refused every reproducer as not importing the repository, and fetched joserfc itself from PyPI."""

    names: list[str] = []
    for base in (root, root / "src") if src_layout(root) else (root,):
        for child in sorted(base.iterdir(), key=lambda item: item.name):
            if child.name.startswith(".") or child.name == "__pycache__":
                continue
            if child.is_dir() and (child / "__init__.py").is_file():
                names.append(child.name)
            elif child.suffix == ".py" and child.name not in {"setup.py", "conftest.py"}:
                names.append(child.stem)
    return names


def plain_reviews(
    model: PaidModel,
    root: Path,
    *,
    rounds: int,
    passes: int = 3,
    max_output: int = 4000,
) -> list[Claim]:
    """Run the same plain review `passes` times."""

    names = ", ".join(package_names(root)) or "(no package detected)"
    claims: list[Claim] = []
    for index in range(passes):
        user = (
            f"STAGE: plain\n"
            f"Pass {index + 1} of {passes}. Importable packages: {names}.\n"
            "Look for defects anywhere in this checkout. Submit claims you can support from the files."
        )
        result = run_agent(
            model,
            root,
            stage="plain",
            system=_SYSTEM,
            user=user,
            origin="plain",
            max_rounds=rounds,
            max_claims=10,
            token_cap=None,
            max_output=max_output,
        )
        claims.extend(result.claims[:10])
    return claims


def habit_texts(claims: list[Claim], root: Path, *, scanners: bool) -> list[str]:
    """Short texts that define what a plain review already produced."""

    texts = [claim.text for claim in claims]
    if scanners:
        texts.extend(run_scanners(root))
    return texts
