"""Publishable report. Unknown defects are an alias and a class."""

from __future__ import annotations

from alien_hunt.budget import Budget
from alien_hunt.redact import matching_advisory, redact
from alien_hunt.score import coherence_miss_rate
from alien_hunt.types import Candidate, Claim, Confirmation, KnownAdvisory


def _per_usd(count: int, usd: float) -> str:
    if usd <= 0:
        return "n/a"
    return f"{count / usd:.4f}"


def unique_confirmed(pairs: list[tuple[Claim, Confirmation]]) -> list[Claim]:
    """Count one confirmed claim per side, class, and function set."""

    seen: set[tuple] = set()
    chosen: list[Claim] = []
    for claim, confirmation in pairs:
        if not confirmation.confirmed:
            continue
        key = (claim.origin, claim.class_label, tuple(sorted(claim.functions)))
        if key in seen:
            continue
        seen.add(key)
        chosen.append(claim)
    return chosen


def public_rows(claims: list[Claim], known: list[KnownAdvisory]) -> list[dict]:
    """Alias and class. An advisory id is added only on an allowlist hit."""

    rows = []
    for index, claim in enumerate(claims, start=1):
        advisory = matching_advisory(claim, known)
        row = {
            "alias": f"AH-{index}",
            "class": claim.class_label,
            "side": "plain" if claim.origin == "plain" else "directed",
        }
        if advisory is not None:
            row["advisory"] = advisory.id
            if advisory.cve:
                row["cve"] = advisory.cve
        rows.append(row)
    return rows


def overlap_functions(claims: list[Claim]) -> list[str]:
    """Function names that both a plain review and a directed hunt confirmed."""

    plain: set[str] = set()
    directed: set[str] = set()
    for claim in claims:
        bucket = plain if claim.origin == "plain" else directed
        bucket.update(claim.functions)
    return sorted(plain & directed)


def render_report(
    *,
    run_id: str,
    target: str,
    commit: str,
    budget: Budget,
    claims: list[Claim],
    top: list[Candidate],
    known: list[KnownAdvisory],
    stopped: bool,
    secret: str | None = None,
) -> str:
    """Markdown metrics. Reproducers and narratives are not included."""

    plain_claims = [claim for claim in claims if claim.origin == "plain"]
    directed_claims = [claim for claim in claims if claim.origin != "plain"]
    plain_usd = budget.spent_on("plain")
    hunt_usd = budget.spent_on("hunt")
    other_usd = budget.spent - plain_usd - hunt_usd
    judged = [item for item in top if item.incoherent is not None]
    incoherent = sum(1 for item in judged if item.incoherent)
    miss = coherence_miss_rate(top)
    miss_text = "n/a" if miss is None else f"{miss:.4f}"
    rows = public_rows(claims, known)
    overlap = overlap_functions(claims)
    overlap_text = "\n".join(f"- `{name}`" for name in overlap) or "none"
    claim_lines = "\n".join(
        "- {alias}: {klass} ({side}){advisory}".format(
            alias=row["alias"],
            klass=row["class"],
            side=row["side"],
            advisory=f" {row['advisory']}" if row.get("advisory") else "",
        )
        for row in rows
    ) or "none"
    body = f"""# Alien-hunt report

- Run: {run_id}
- Target: {target}
- Commit: {commit or "local"}
- Stopped early: {"yes" if stopped else "no"}
- Budget USD: {budget.limit_usd:.4f}
- Spent USD: {budget.spent:.4f}

## Plain reviews

- Confirmed claims: {len(plain_claims)}
- USD: {plain_usd:.4f}
- Confirmed per USD: {_per_usd(len(plain_claims), plain_usd)}

## Directed hunts

- Confirmed claims: {len(directed_claims)}
- USD: {hunt_usd:.4f}
- Confirmed per USD: {_per_usd(len(directed_claims), hunt_usd)}

## Other model spend

- USD: {other_usd:.4f}

## Overlap by function

{overlap_text}

## Coherence filter

Ranked at β = 0.7. The same pool is stored at β = 0.4.

- Top candidates judged: {len(judged)}
- Incoherent among them: {incoherent}
- Miss rate among ratings of 4 or 5: {miss_text}

## Confirmed claims

{claim_lines}

Disclosure of a confirmed defect that is outside a public advisory is a person's decision.
This report names those defects only by alias and class.
"""
    cleaned = redact(body, secret)
    return str(cleaned)
