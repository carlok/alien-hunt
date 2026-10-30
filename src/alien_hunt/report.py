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


SAME_TEXT = 0.8  # cosine of two claim texts' embeddings above which they say the same thing


def unique_confirmed(pairs: list[tuple[Claim, Confirmation]], vectors: list | None = None) -> list[Claim]:
    """One confirmed claim per distinct issue on each side. Two claims are one issue when they share a function and
    have the same class, or their texts' embeddings are at least SAME_TEXT alike (`vectors`, in the order of the
    confirmed pairs; without them, class alone). On PyJWT the three reviews confirmed 7 claims that were 3 issues."""

    from alien_hunt.score import cosine

    confirmed = [claim for claim, confirmation in pairs if confirmation.confirmed]
    parent = list(range(len(confirmed)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, a in enumerate(confirmed):
        for j in range(i + 1, len(confirmed)):
            b = confirmed[j]
            if (a.origin == "plain") != (b.origin == "plain") or not set(a.functions) & set(b.functions):
                continue
            alike = vectors is not None and len(vectors) == len(confirmed) and cosine(vectors[i], vectors[j]) >= SAME_TEXT
            if a.class_label.strip().lower() == b.class_label.strip().lower() or alike:
                parent[find(j)] = find(i)
    seen: set[int] = set()
    chosen: list[Claim] = []
    for i, claim in enumerate(confirmed):
        root = find(i)
        if root not in seen:
            seen.add(root)
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
    made: list[Claim] | None = None,
    pool: list[Candidate] | None = None,
    confirmed_all: int | None = None,
    above_floor: int | None = None,
    fallback: int = 0,
) -> str:
    """Markdown metrics. Reproducers and narratives are not included."""

    plain_claims = [claim for claim in claims if claim.origin == "plain"]
    directed_claims = [claim for claim in claims if claim.origin != "plain"]
    plain_usd = budget.spent_on("plain")
    hunt_usd = budget.spent_on("hunt")
    other_usd = budget.spent - plain_usd - hunt_usd
    judged = [item for item in top if item.incoherent is not None]
    incoherent = sum(1 for item in judged if item.incoherent)
    made = made if made is not None else claims
    made_plain = sum(1 for claim in made if claim.origin == "plain")
    made_directed = len(made) - made_plain
    pool = pool if pool is not None else top
    rated = sum(1 for item in pool if item.rated)
    miss = coherence_miss_rate(top)
    miss_text = "n/a" if miss is None else f"{miss:.4f}"
    rows = public_rows(claims, known)
    overlap = overlap_functions(claims)
    overlap_text = f"- Functions with a confirmed claim on both sides: {len(overlap)} (named in `local/detail.json`)"
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

- Claims made: {made_plain}
- Confirmed claims: {len(plain_claims)}
- USD: {plain_usd:.4f}
- Confirmed per USD: {_per_usd(len(plain_claims), plain_usd)}

## Directed hunts

- Claims made: {made_directed}
- Confirmed claims: {len(directed_claims)}
- USD: {hunt_usd:.4f}
- Confirmed per USD: {_per_usd(len(directed_claims), hunt_usd)}

## Other model spend

- USD: {other_usd:.4f}

## Overlap by function

{overlap_text}

## Coherence filter

Ranked at β = 0.7. The same pool is stored at β = 0.4.

- Coherence ratings parsed: {rated} of {len(pool)} (an unparsed one counts as 1)
- At or above the coherence floor: {'n/a' if above_floor is None else above_floor} (only those are hunted{f'; none was, so the best {fallback} rated 2 were' if fallback else ''})
- Top candidates judged: {len(judged)} of {len(top)} (a hunt that never submitted gives no verdict)
- Incoherent among them: {incoherent}
- Miss rate among ratings of 4 or 5: {miss_text}

## Confirmed claims

{'' if confirmed_all is None else f'Before merging duplicates: {confirmed_all}.'}

{claim_lines}

Disclosure of a confirmed defect that is outside a public advisory is a person's decision.
This report names those defects only by alias and class.
"""
    cleaned = redact(body, secret)
    return str(cleaned)
