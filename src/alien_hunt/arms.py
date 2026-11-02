"""Three selection rules on one pool: the combined score, coherence alone, and a random draw.

A usual run hunts every candidate at or above the coherence floor, up to 20. On the runs so far fewer than 20 reached it, so
the floor chose and the score only set the order. With `--arms N` the floor is off and each rule picks N from the same pool,
so the unavailability term can change what gets looked at, and the three can be compared."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from alien_hunt.config import ConfigError
from alien_hunt.redact import file_hit, matching_advisory, symbol_hit
from alien_hunt.report import merge_claims, unique_confirmed
from alien_hunt.types import Candidate, Claim, Confirmation, KnownAdvisory

ARMS = ("combined", "coherence", "random")
ARMS_FILE = "06-arms.json"
_LABELS = {"real", "not"}


def select_arms(ranked: list[Candidate], hunts: int, seed: int) -> dict[str, list[Candidate]]:
    """Each rule's picks, first choice first. `ranked` is the pool in the score's order; the other two rules start from
    id order, so they can't see it. Coherence is a coarse rating and most of its order is ties: broken by the score, that
    rule would be the combined one again, so they are broken at random."""

    pool = sorted(ranked, key=lambda item: item.id)
    shuffled = random.Random(f"coherence:{seed}").sample(pool, len(pool))
    by_coherence = sorted(shuffled, key=lambda item: -(item.coherence or 0.0))
    return {
        "combined": ranked[:hunts],
        "coherence": by_coherence[:hunts],
        "random": random.Random(f"random:{seed}").sample(pool, min(hunts, len(pool))),
    }


def hunt_order(arms: dict[str, list[Candidate]]) -> list[Candidate]:
    """Each pick once, the rules taking turns, and a different rule first each time round, so that a budget stop favours
    none of them for long. It still leaves them up to one hunt apart, and a run cut short is flagged."""

    names = list(arms)
    order: dict[str, Candidate] = {}
    for turn in range(max((len(picks) for picks in arms.values()), default=0)):
        first = turn % len(names)
        for name in [*names[first:], *names[:first]]:
            if turn < len(arms[name]):
                order.setdefault(arms[name][turn].id, arms[name][turn])
    return list(order.values())


def claim_id(claim: Claim) -> str:
    return hashlib.sha256(f"{claim.text}\0{claim.reproducer}".encode("utf-8", "replace")).hexdigest()[:12]


def _touches(candidate: Candidate, known: list[KnownAdvisory]) -> bool:
    """The candidate's atoms name a place an advisory names, whatever the hunt then did with it."""

    atoms = (candidate.source, candidate.other)
    functions = [*candidate.named_functions, *(atom.function for atom in atoms if atom.function)]
    files = [atom.file for atom in atoms if atom.file]
    return any(symbol_hit(functions, symbol) or file_hit(files, symbol) for advisory in known for symbol in advisory.symbols)


def _beyond_reviews(claim: Claim, reviewed: list[str]) -> bool:
    """No plain review named a function of this claim, whether or not that review's own claim was confirmed: what it
    reported is what was available. Names differ in form (`validate_exp`, `Registry.validate_exp`), so a whole part of
    one name matching the other counts as the same function."""

    if not claim.functions:
        return False
    return not any(symbol_hit(claim.functions, name) or symbol_hit(reviewed, function)
                   for name in reviewed for function in claim.functions)


def _rule(
    picks: list[Candidate],
    hunts: list[tuple[Claim, Confirmation]],
    reviewed: list[str],
    known: list[KnownAdvisory],
    floor: float,
) -> dict:
    """One rule's counts. Its claims merge among themselves only: merged across rules, a claim of another rule could join
    two issues of this one. Confirmed issues merge among the confirmed only, as the report does, so that a refused claim
    can't join two of them."""

    ran = [item for item in picks if item.hunt_usd is not None and item.hunt_error is None]
    ids = {item.id for item in picks}
    mine = [(claim, confirmation) for claim, confirmation in hunts if claim.candidate_id in ids]
    claims = [claim for claim, _ in mine]
    issues: dict[int, list[Claim]] = {}
    for claim, issue in zip(claims, merge_claims(claims)):
        issues.setdefault(issue, []).append(claim)
    confirmed = [claim for claim, confirmation in mine if confirmation.confirmed]
    distinct = unique_confirmed(mine)

    def advisories(among: list[Claim]) -> list[str]:
        return sorted({advisory.id for claim in among if (advisory := matching_advisory(claim, known))})

    return {
        "picks": [item.id for item in picks],
        "hunts": len(ran),
        "usd": sum(item.hunt_usd or 0.0 for item in picks),
        "above_floor": sum(1 for item in ran if (item.coherence or 0.0) >= floor),
        "on_advisory": sum(1 for item in ran if _touches(item, known)),
        "claims": len(claims),
        "confirmed": len(distinct),
        "beyond": sum(1 for claim in distinct if _beyond_reviews(claim, reviewed)),
        "advisories_claimed": advisories(claims),
        "advisories_confirmed": advisories(confirmed),
        "issues": [
            {"claims": [claim_id(claim) for claim in members], "beyond": any(_beyond_reviews(claim, reviewed) for claim in members)}
            for members in issues.values()
        ],
    }


def arm_summary(
    arms: dict[str, list[Candidate]],
    confirmations: list[tuple[Claim, Confirmation]],
    known: list[KnownAdvisory],
    *,
    floor: float,
    seed: int = 0,
    cut_short: bool = False,
) -> dict:
    """What `06-arms.json` holds: ids and counts, no claim text. A pick two rules share was hunted once and counts for
    both, with its full cost, as if each rule had run alone. A hunt lost to a model error, cut by the budget or never
    reached is no hunt, though what it spent still counts."""

    hunts = [(claim, confirmation) for claim, confirmation in confirmations if claim.origin != "plain"]
    reviewed = sorted({name for claim, _ in confirmations if claim.origin == "plain" for name in claim.functions})
    return {
        "seed": seed,
        "floor": floor,
        "cut_short": cut_short,
        "arms": {name: _rule(picks, hunts, reviewed, known, floor) for name, picks in arms.items()},
    }


def write_label_sheet(path: Path, confirmations: list[tuple[Claim, Confirmation]], seed: int) -> Path:
    """Every hunt's claim, the refused ones too (a real defect has been refused), shuffled and without its rule, so a person
    can label them blind."""

    rows = {
        claim_id(claim): {
            "id": claim_id(claim),
            "text": claim.text,
            "class": claim.class_label,
            "functions": claim.functions,
            "files": claim.files,
            "confirmed": confirmation.confirmed,
            "why": confirmation.why,
            "output": confirmation.output,
            "reproducer": claim.reproducer,
        }
        for claim, confirmation in confirmations
        if claim.origin != "plain"
    }
    shuffled = random.Random(f"labels:{seed}").sample(list(rows.values()), len(rows))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in shuffled), encoding="utf-8")
    return path


def arm_totals(runs: list[dict], labels: dict[str, str] | None = None) -> dict[str, dict]:
    """Add up runs, rule by rule. An issue is real when a claim of it is labelled real, and unlabelled when none of its
    claims has a label. Advisories count once per run."""

    labels = labels or {}
    fields = ("hunts", "usd", "above_floor", "on_advisory", "claims", "confirmed", "beyond", "advisories_claimed",
              "advisories_confirmed", "real", "real_beyond", "unlabelled")
    totals: dict[str, dict] = {name: dict.fromkeys(fields, 0) for name in ARMS}
    for run in runs:
        for name, row in totals.items():
            arm = run["arms"][name]
            for field in ("hunts", "usd", "above_floor", "on_advisory", "claims", "confirmed", "beyond"):
                row[field] += arm[field]
            row["advisories_claimed"] += len(arm["advisories_claimed"])
            row["advisories_confirmed"] += len(arm["advisories_confirmed"])
            for issue in arm["issues"]:
                said = [labels.get(identifier) for identifier in issue["claims"]]
                row["unlabelled"] += not any(said)
                if "real" in said:
                    row["real"] += 1
                    row["real_beyond"] += issue["beyond"]
    return totals


def render_table(runs: list[dict], labels: dict[str, str] | None = None) -> str:
    """Counts only, so it can go in the published report."""

    head = ["Rule", "Hunts", "USD", "Above the floor", "On an advisory", "Claims", "Confirmed issues", "Beyond the reviews",
            "Advisories claimed / confirmed"]
    if labels is not None:
        head += ["Real", "Real beyond the reviews", "Unlabelled"]
    lines = ["| " + " | ".join(head) + " |", "|" + " --- |" * len(head)]
    for name, row in arm_totals(runs, labels).items():
        cells = [name, row["hunts"], f"{row['usd']:.2f}", row["above_floor"], row["on_advisory"], row["claims"],
                 row["confirmed"], row["beyond"], f"{row['advisories_claimed']} / {row['advisories_confirmed']}"]
        if labels is not None:
            cells += [row["real"], row["real_beyond"], row["unlabelled"]]
        lines.append("| " + " | ".join(str(cell) for cell in cells) + " |")
    return "\n".join(lines)


def render_totals(runs: list[dict], labels: dict[str, str] | None = None) -> str:
    cut = sum(1 for run in runs if run["cut_short"])
    lines = [f"Runs: {len(runs)} (cut short by the budget or an error: {cut})", "", render_table(runs, labels)]
    if labels is not None:
        ids = {
            identifier
            for run in runs
            for arm in run["arms"].values()
            for issue in arm["issues"]
            for identifier in issue["claims"]
        }
        lines += ["", f"Labels that match no claim: {sum(1 for identifier in labels if identifier not in ids)}"]
    return "\n".join(lines)


def load_run(folder: Path) -> dict:
    path = folder / ARMS_FILE
    try:
        run = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no {ARMS_FILE} in {folder}: that run did not use --arms") from exc
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not (isinstance(run, dict) and isinstance(run.get("arms"), dict) and set(run["arms"]) == set(ARMS)):
        raise ConfigError(f"{path} is not what --arms writes")
    return run


def load_labels(path: Path) -> dict[str, str]:
    try:
        labels = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read the labels in {path}: {exc}") from exc
    if not isinstance(labels, dict) or not all(isinstance(value, str) and value in _LABELS for value in labels.values()):
        raise ConfigError(f'the labels in {path} must map claim ids to "real" or "not"')
    return labels
