"""Alien-space score: coherent, and far from the habit set."""

from __future__ import annotations

import math
import random
from pathlib import Path

from alien_hunt.types import Atom, Candidate


def zscores(values: list[float]) -> list[float]:
    """Population z-scores. A zero standard deviation yields zeros."""

    count = len(values)
    if count == 0:
        return []
    mean = sum(values) / count
    variance = sum((value - mean) ** 2 for value in values) / count
    std = math.sqrt(variance)
    if std == 0:
        return [0.0] * count
    return [(value - mean) / std for value in values]


def cosine(left: list[float], right: list[float]) -> float:
    """Cosine similarity. A zero vector is orthogonal to everything."""

    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def unavailability(vector: list[float], habits: list[list[float]]) -> float:
    """1 minus the highest cosine similarity to the habit set.

    With no habits, every candidate is fully unavailable and the z-score is zero,
    so ranking falls back to coherence.
    """

    if not habits:
        return 1.0
    return 1.0 - max(cosine(vector, habit) for habit in habits)


def apply_scores(candidates: list[Candidate]) -> tuple[list[Candidate], list[Candidate]]:
    """Score the pool at β = 0.7 and β = 0.4.

    score = (1 - β) * z(coherence) + β * z(unavailability)
    """

    if not candidates:
        return [], []
    coherence = [float(item.coherence or 0.0) for item in candidates]
    distance = [float(item.unavailability or 0.0) for item in candidates]
    z_coherence = zscores(coherence)
    z_distance = zscores(distance)
    for item, z_coh, z_unavail in zip(candidates, z_coherence, z_distance):
        item.z_coherence = z_coh
        item.z_unavailability = z_unavail
        item.score_0_7 = (1 - 0.7) * z_coh + 0.7 * z_unavail
        item.score_0_4 = (1 - 0.4) * z_coh + 0.4 * z_unavail
    ranked_07 = sorted(candidates, key=lambda item: (-float(item.score_0_7 or 0.0), item.id))
    ranked_04 = sorted(candidates, key=lambda item: (-float(item.score_0_4 or 0.0), item.id))
    return ranked_07, ranked_04


def sample_triples(
    sources: list[Atom],
    mechanisms: list[Atom],
    others: list[Atom],
    *,
    limit: int,
    seed: int,
) -> list[Candidate]:
    """Sample source × mechanism × (sink or invariant) triples that exist here.

    Pools smaller than `limit` keep their construction order so a tiny repository
    stays deterministic. Larger pools use `seed`.
    """

    pool: list[Candidate] = []
    for source in sources:
        for mechanism in mechanisms:
            for other in others:
                pool.append(
                    Candidate(
                        id="",
                        source=source,
                        mechanism=mechanism,
                        other=other,
                    )
                )
    if len(pool) > limit:
        pool = random.Random(seed).sample(pool, limit)
    for index, candidate in enumerate(pool):
        candidate.id = f"c{index:03d}"
    return pool


def _top_dir(path: str | None) -> str:
    parts = Path(path or "").parts
    return parts[0] if len(parts) > 1 else "."


def _closeness(source: Atom, other: Atom) -> int | None:
    """0 when both atoms sit in one function, 1 in one file, 2 in one top-level folder, None when apart."""

    if not source.file or not other.file:
        return None
    if source.file == other.file:
        return 0 if source.scope is not None and source.scope == other.scope else 1
    return 2 if _top_dir(source.file) == _top_dir(other.file) else None


def _place(atom: Atom) -> tuple[str | None, str | None]:
    return atom.file, atom.scope


def colocated_pairs(sources: list[Atom], others: list[Atom], *, limit: int, seed: int) -> list[tuple[Atom, Atom]]:
    """(source, sink-or-invariant) pairs that live together: the same function, the same file, or the same top-level
    folder. At most `limit` pairs, drawn with `seed`; a pool that fits in `limit` is returned whole, the same file
    before the same folder, in construction order.

    Uniform triples were almost never coherent on PyJWT (74 of 80 rated 1): a source and a sink from two unrelated
    files rarely meet on a real path. The pairs of a file are the product of its sources and its sinks, so a uniform
    draw spends its few slots on the biggest files and on a handful of functions. This one walks the pairs closest
    first (one function, then one file, then one folder, each shuffled with `seed`) and keeps, in turn: those whose
    two functions no kept pair has used, those with one new function, those with two atoms not used yet, those with
    one, then whatever is left. The draw reaches as many functions as it can."""

    same_file: list[tuple[Atom, Atom]] = []
    same_folder: list[tuple[Atom, Atom]] = []
    for source in sources:
        for other in others:
            close = _closeness(source, other)
            if close is not None:
                (same_folder if close == 2 else same_file).append((source, other))
    if len(same_file) + len(same_folder) <= limit:
        return same_file + same_folder
    rng = random.Random(seed)
    rng.shuffle(same_file)
    rng.shuffle(same_folder)
    order = sorted(same_file, key=lambda pair: _closeness(*pair)) + same_folder      # a stable sort: one function first
    places: set[tuple[str | None, str | None]] = set()
    used: set[str] = set()
    taken = [False] * len(order)
    picked: list[tuple[Atom, Atom]] = []
    wants = (
        lambda s, o: _place(s) not in places and _place(o) not in places,
        lambda s, o: _place(s) not in places or _place(o) not in places,
        lambda s, o: s.id not in used and o.id not in used,
        lambda s, o: s.id not in used or o.id not in used,
        lambda s, o: True,
    )
    for want in wants:
        for index, (source, other) in enumerate(order):
            if len(picked) >= limit:
                return picked
            if not taken[index] and want(source, other):
                taken[index] = True
                picked.append((source, other))
                places.update((_place(source), _place(other)))
                used.update((source.id, other.id))
    return picked


def pool_pairs(
    sources: list[Atom], sinks: list[Atom], invariants: list[Atom], *, sample_limit: int, seed: int
) -> list[tuple[Atom, Atom]]:
    """The pairs a run's candidate pool is built from: each source against the sinks and the invariants, a quarter of
    `sample_limit` of them (the model then proposes up to four mechanisms per pair). The pipeline and
    scripts/pool_ceiling.py both call this, so a measurement of the pool uses the pool's own rule."""

    return colocated_pairs(sources, [*sinks, *invariants], limit=max(1, sample_limit // 4), seed=seed)


def coherence_miss_rate(top: list[Candidate]) -> float | None:
    """Fraction of hunted candidates rated 4 or 5 that the hunt judged incoherent."""

    high = [
        item
        for item in top
        if item.coherence is not None and item.coherence >= 4 and item.incoherent is not None
    ]
    if not high:
        return None
    incoherent = sum(1 for item in high if item.incoherent)
    return incoherent / len(high)
