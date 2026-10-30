"""The second live run (PyJWT, 2026-10-30): 47 of 80 sources came from the tests, uniform triples were rated 1 in 74
of 80 cases, and 7 confirmed claims were 3 issues. These tests pin the fixes: library atoms only, co-located pairs,
model-picked mechanisms with one random draw, and duplicates merged."""

from __future__ import annotations

import json
from pathlib import Path

from alien_hunt.atoms import _py_files
from alien_hunt.pipeline import propose_candidates
from alien_hunt.report import unique_confirmed
from alien_hunt.score import colocated_pairs
from alien_hunt.types import Atom, ChatResponse, Claim, Confirmation


def test_atoms_come_from_the_library_not_its_tests_or_docs(tmp_path: Path):
    root = tmp_path / "tests" / "repo"                    # a parent folder named "tests" must not hide the whole tree
    for rel in ("pkg/a.py", "pkg/test_b.py", "pkg/c_test.py", "pkg/conftest.py", "tests/test_x.py", "docs/conf.py",
                "setup.py", "examples/demo.py", "pkg/sub/d.py"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    kept = sorted(str(path.relative_to(root)) for path in _py_files(root))
    assert kept == ["pkg/a.py", "pkg/sub/d.py"]


def atom(kind: str, ident: str, file: str | None) -> Atom:
    return Atom(kind=kind, id=ident, text=f"{kind} {ident}", file=file)


def test_pairs_live_together_same_file_first():
    sources = [atom("source", "s1", "pkg/a.py"), atom("source", "s2", "pkg/b.py"), atom("source", "s3", "other/c.py")]
    others = [atom("sink", "k1", "pkg/a.py"), atom("sink", "k2", "pkg/b.py"), atom("sink", "k3", "lib/z.py")]
    pairs = colocated_pairs(sources, others, limit=10, seed=1)
    ids = [(s.id, o.id) for s, o in pairs]
    assert ids[:2] == [("s1", "k1"), ("s2", "k2")]          # the same file first
    assert set(ids[2:]) == {("s1", "k2"), ("s2", "k1")}     # then the same top folder
    assert all(o.id != "k3" and s.id != "s3" for s, o in pairs)   # never across unrelated folders
    assert colocated_pairs(sources, others, limit=1, seed=1) == pairs[:1]
    assert colocated_pairs(sources, others, limit=3, seed=7) == colocated_pairs(sources, others, limit=3, seed=7)


MECHS = [Atom(kind="mechanism", id=f"m{n:02d}", text=f"mechanism {n}") for n in range(10)]


class Picker:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def chat(self, *, stage, messages, tools, max_tokens) -> ChatResponse:
        self.prompts.append(messages[0]["content"])
        return ChatResponse(self.reply, [], 100, 50)


def test_the_model_picks_the_mechanisms_and_one_more_is_drawn():
    pairs = [(atom("source", "s1", "pkg/a.py"), atom("sink", "k1", "pkg/a.py"))]
    model = Picker(json.dumps({"picks": [{"pair": "p000", "mechanisms": ["m03", "m07", "nope"]}]}))
    out = propose_candidates(model, pairs, MECHS, per_pair=3, explore=1, seed=2)
    mechs = [c.mechanism.id for c in out]
    assert mechs[:2] == ["m03", "m07"] and len(mechs) == 3 and mechs[2] not in {"m03", "m07"}
    assert [c.id for c in out] == ["c000", "c001", "c002"]
    assert "STAGE: mechanisms" in model.prompts[0] and "m09 mechanism 9" in model.prompts[0]


def test_a_reply_that_does_not_parse_draws_them_all():
    pairs = [(atom("source", "s1", "pkg/a.py"), atom("sink", "k1", "pkg/a.py"))]
    out = propose_candidates(Picker("let me think"), pairs, MECHS, per_pair=3, explore=1, seed=2)
    assert len(out) == 4 and len({c.mechanism.id for c in out}) == 4


def claim(text: str, klass: str, functions: list[str], origin: str = "plain") -> Claim:
    return Claim(text=text, class_label=klass, files=[], functions=functions, reproducer="r", origin=origin, candidate_id=None)


def test_duplicates_are_merged_by_shared_function_and_class_or_alike_text():
    ok = Confirmation(True, "ok")
    claims = [
        claim("exp TypeError", "error-handling", ["PyJWT._validate_exp"]),
        claim("nbf TypeError", "error-handling", ["PyJWT._validate_nbf"]),
        claim("all three TypeError", "error-handling", ["PyJWT._validate_exp", "PyJWT._validate_nbf"]),
        claim("options mutated", "side-effect", ["PyJWT.decode_complete"]),
        claim("options dict mutated again", "state-mutation", ["PyJWT.decode_complete"]),
        claim("instance options ignored", "logic", ["PyJWT.decode_complete"]),
        claim("exp TypeError", "error-handling", ["PyJWT._validate_exp"], origin="hunt"),
    ]
    pairs = [(c, ok) for c in claims]
    vectors = [[1, 0, 0], [1, 0, 0], [1, 0, 0], [0, 1, 0], [0, 0.99, 0.1], [0, 0, 1], [1, 0, 0]]
    merged = unique_confirmed(pairs, vectors)
    assert [c.text for c in merged] == ["exp TypeError", "options mutated", "instance options ignored", "exp TypeError"]
    assert [c.origin for c in merged][-1] == "hunt"                 # the two sides are never merged
    assert len(unique_confirmed(pairs)) == 5                       # without vectors, two classes on one function stay apart
    assert unique_confirmed([(claims[0], Confirmation(False, "no"))]) == []
