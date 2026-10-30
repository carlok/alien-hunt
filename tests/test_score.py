"""Score formula from the alien-space sampler, with a stdlib cosine."""

import pytest

from alien_hunt.score import apply_scores, cosine, sample_triples, unavailability, zscores
from alien_hunt.types import Atom, Candidate


def test_zscore_zero_std_is_zero():
    assert zscores([3.0, 3.0, 3.0]) == [0.0, 0.0, 0.0]
    assert zscores([]) == []


def test_beta_changes_the_winner():
    high_coherence = Candidate(
        id="a",
        source=Atom("source", "s", "src"),
        mechanism=Atom("mechanism", "m", "mech"),
        other=Atom("sink", "k", "sink"),
        coherence=5,
        unavailability=0,
    )
    high_distance = Candidate(
        id="b",
        source=Atom("source", "s2", "src"),
        mechanism=Atom("mechanism", "m2", "mech"),
        other=Atom("sink", "k2", "sink"),
        coherence=1,
        unavailability=1,
    )
    ranked_07, ranked_04 = apply_scores([high_coherence, high_distance])
    assert [item.id for item in ranked_07] == ["b", "a"]
    assert [item.id for item in ranked_04] == ["a", "b"]
    assert high_coherence.score_0_7 == pytest.approx(-0.4)
    assert high_distance.score_0_7 == pytest.approx(0.4)
    assert high_coherence.score_0_4 == pytest.approx(0.2)
    assert high_distance.score_0_4 == pytest.approx(-0.2)


def test_cosine_and_empty_habits():
    assert cosine([1.0, 0.0], [0.0, 1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 0.0]) == 0.0
    assert unavailability([1.0, 0.0], []) == 1.0
    assert unavailability([1.0, 0.0], [[0.0, 1.0], [1.0, 0.0]]) == 0.0


def test_sample_is_stable_and_capped():
    sources = [Atom("source", "s", "source")]
    mechanisms = [Atom("mechanism", f"m{i}", "mechanism") for i in range(5)]
    others = [Atom("sink", "k", "sink"), Atom("invariant", "i", "invariant")]
    first = sample_triples(sources, mechanisms, others, limit=4, seed=1)
    second = sample_triples(sources, mechanisms, others, limit=4, seed=1)
    assert [item.id for item in first] == [item.id for item in second]
    assert len(first) == 4
    whole = sample_triples(sources, mechanisms, others, limit=100, seed=1)
    assert len(whole) == 10
    assert whole[0].id == "c000"
