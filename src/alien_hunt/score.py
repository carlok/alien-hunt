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


def colocated_pairs(sources: list[Atom], others: list[Atom], *, limit: int, seed: int) -> list[tuple[Atom, Atom]]:
    """(source, sink-or-invariant) pairs that live together: the same file first, then the same top-level folder.

    Uniform triples were almost never coherent on PyJWT (74 of 80 rated 1): a source and a sink from two unrelated
    files rarely meet on a real path. At most `limit` pairs; a larger group is sampled with `seed`."""

    same_file = [(s, o) for s in sources for o in others if s.file and s.file == o.file]
    same_dir = [
        (s, o)
        for s in sources
        for o in others
        if s.file and o.file and s.file != o.file and _top_dir(s.file) == _top_dir(o.file)
    ]
    rng = random.Random(seed)
    picked: list[tuple[Atom, Atom]] = []
    for group in (same_file, same_dir):
        need = limit - len(picked)
        if need <= 0:
            break
        picked.extend(group if len(group) <= need else rng.sample(group, need))
    return picked


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
