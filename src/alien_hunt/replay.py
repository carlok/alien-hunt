"""Re-check a run's saved claims with the current confirmation, with no model call.

A run appends every claim it makes, reproducer included, to `local/claims.jsonl`. `replay` reads them back and confirms
each one again: against the same tree, to see what the current check makes of an older run, and optionally against a
second tree, such as the commit that fixed an advisory. A reproducer that still prints the marker on the fixed code
was not specific to the defect: either the defect is still there, or the test comes out true for correct behaviour,
which the check alone cannot tell from a defect (README, "What the check does not stop").
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from alien_hunt.arms import claim_id
from alien_hunt.config import ConfigError
from alien_hunt.pipeline import RUN_FILE, dump_json, iter_confirmations
from alien_hunt.types import Claim, Confirmation

CLAIMS_FILE = Path("local") / "claims.jsonl"
DEFAULT_IMAGE = "docker.io/library/python:3.12-slim"

FIXED_THERE = "fixed there"
FIRES_THERE = "fires there too"
CONFIRMED = "confirmed"
REFUSED = "refused"


def load_claims(run: Path) -> list[Claim]:
    """The claims a run saved, in the order it made them. A line that is not a claim is an error, not a skip: a replay
    that quietly drops claims would understate what the run produced."""

    path = run / CLAIMS_FILE
    if not path.is_file():
        raise ConfigError(f"no {CLAIMS_FILE} in {run}: is it a run folder?")
    claims = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            claims.append(
                Claim(
                    text=str(row["text"]),
                    class_label=str(row.get("class") or ""),
                    files=[str(item) for item in row.get("files") or []],
                    functions=[str(item) for item in row.get("functions") or []],
                    reproducer=str(row["reproducer"]),
                    origin=str(row.get("origin") or ""),
                    candidate_id=row.get("candidate_id"),
                )
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise ConfigError(f"{path}:{number} is not a saved claim: {exc}") from exc
    return claims


def load_record(run: Path) -> dict:
    """What the run ran on (run.json), or {} for a run made before it was written."""

    path = run / RUN_FILE
    if not path.is_file():
        return {}
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return record if isinstance(record, dict) else {}


@dataclass(frozen=True)
class Tree:
    """A checkout to confirm against, with the commit's date (for the wheels) and a label for the table."""

    path: Path
    commit_time: datetime
    label: str


@dataclass
class Verdict:
    claim: Claim
    here: Confirmation
    there: Confirmation | None = None

    @property
    def id(self) -> str:
        return claim_id(self.claim)

    @property
    def label(self) -> str:
        if not self.here.confirmed:
            return REFUSED
        if self.there is None:
            return CONFIRMED
        return FIRES_THERE if self.there.confirmed else FIXED_THERE


def replay(
    claims: list[Claim],
    here: Tree,
    work: Path,
    *,
    there: Tree | None = None,
    mode: str = "podman",
    image: str = DEFAULT_IMAGE,
) -> list[Verdict]:
    """Confirm every claim on `here`; the ones confirmed there are confirmed again on `there`, if given. `mode="local"`
    runs reproducers on the host and is for fixtures only."""

    verdicts = [
        Verdict(claim, confirmation)
        for claim, confirmation in iter_confirmations(
            claims, here.path, work / "here", mode=mode, image=image, commit_time=here.commit_time
        )
    ]
    if there is not None:
        confirmed = [verdict for verdict in verdicts if verdict.here.confirmed]
        again = iter_confirmations(
            [verdict.claim for verdict in confirmed], there.path, work / "there", mode=mode, image=image,
            commit_time=there.commit_time,
        )
        for verdict, (_, confirmation) in zip(confirmed, again):
            verdict.there = confirmation
    return verdicts


def render(verdicts: list[Verdict], here: Tree, there: Tree | None = None) -> str:
    """A table of ids, sides, classes and verdicts, then the counts. Claim texts and reproducers stay in `local/`."""

    head = f"Replayed {len(verdicts)} claims on {here.label}" + (f", then the confirmed ones on {there.label}" if there else "")
    lines = [head, "", "| claim | side | class | verdict | why |", "|---|---|---|---|---|"]
    for verdict in verdicts:
        why = (verdict.there if verdict.there is not None and not verdict.there.confirmed else verdict.here).why
        side = "plain" if verdict.claim.origin == "plain" else "directed"
        lines.append(f"| {verdict.id} | {side} | {verdict.claim.class_label or '-'} | {verdict.label} | {_cell(why)} |")
    counts = {}
    for verdict in verdicts:
        counts[verdict.label] = counts.get(verdict.label, 0) + 1
    order = [REFUSED, CONFIRMED, FIXED_THERE, FIRES_THERE]
    lines += ["", ", ".join(f"{label}: {counts[label]}" for label in order if label in counts) or "no claims"]
    if there is not None and counts.get(FIRES_THERE):
        lines += ["", f"A claim that fires on {there.label} too was not specific to the defect that commit fixed: the "
                      "defect is still there, or the test is true for correct behaviour."]
    return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    text = " ".join(text.split()).replace("|", "/")
    return text if len(text) <= 90 else text[:87] + "..."


def dump(verdicts: list[Verdict], path: Path, here: Tree, there: Tree | None = None) -> None:
    """The details, for the run's `local/` folder: each claim's functions, verdict, and both runs' reason, exit code
    and output."""

    def side(confirmation: Confirmation | None) -> dict | None:
        if confirmation is None:
            return None
        return {"confirmed": confirmation.confirmed, "why": confirmation.why, "exit_code": confirmation.exit_code,
                "output": confirmation.output}

    dump_json(
        path,
        {
            "here": here.label,
            "there": there.label if there else None,
            "claims": [
                {"id": verdict.id, "origin": verdict.claim.origin, "class": verdict.claim.class_label,
                 "functions": verdict.claim.functions, "verdict": verdict.label, "here": side(verdict.here),
                 "there": side(verdict.there)}
                for verdict in verdicts
            ],
        },
    )
