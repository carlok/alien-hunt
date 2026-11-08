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
    cut = [(s.id, o.id) for s, o in colocated_pairs(sources, others, limit=2, seed=1)]
    assert set(cut) == set(ids[:2])                                             # a cut pool still starts in the files
    assert [(s.id, o.id) for s, o in colocated_pairs(sources, others, limit=1, seed=1)][0] in ids[:2]
    assert colocated_pairs(sources, others, limit=3, seed=7) == colocated_pairs(sources, others, limit=3, seed=7)


def placed(kind: str, ident: str, file: str, scope: str | None) -> Atom:
    return Atom(kind=kind, id=ident, text=f"{kind} {ident}", file=file, scope=scope)


def test_a_pool_that_fits_comes_back_whole_in_construction_order():
    sources = [placed("source", "s1", "dir_a/file_a.py", "fn_a"), placed("source", "s2", "dir_a/file_b.py", "fn_b")]
    others = [placed("sink", "k1", "dir_a/file_a.py", "fn_a"), placed("sink", "k2", "dir_a/file_a.py", "fn_c"), placed("sink", "k3", "dir_a/file_b.py", "fn_b")]
    pairs = [(s.id, o.id) for s, o in colocated_pairs(sources, others, limit=10, seed=3)]
    assert pairs == [("s1", "k1"), ("s1", "k2"), ("s2", "k3"), ("s1", "k3"), ("s2", "k1"), ("s2", "k2")]   # files, then the folder


def test_a_cut_pool_takes_the_same_function_before_the_same_file_before_the_folder():
    sources = [placed("source", "s1", "dir_a/file_a.py", "fn_a"), placed("source", "s2", "dir_a/file_b.py", "fn_b")]
    others = [placed("sink", "k1", "dir_a/file_a.py", "fn_a"), placed("sink", "k2", "dir_a/file_a.py", "fn_c"), placed("sink", "k3", "dir_a/file_b.py", "fn_b")]
    for seed in range(5):
        pairs = [(s.id, o.id) for s, o in colocated_pairs(sources, others, limit=3, seed=seed)]
        assert set(pairs[:2]) == {("s1", "k1"), ("s2", "k3")}      # the pairs inside one function
        assert pairs[2] == ("s1", "k2")                             # then the one left in a file


def test_the_draw_reaches_distinct_functions_before_a_second_pair_in_one():
    sources = [placed("source", f"s{n}", "dir_a/file_a.py", f"fn_p{n}") for n in range(8)]
    others = [placed("sink", f"k{n}", "dir_a/file_a.py", f"fn_p{n}") for n in range(8)]
    for seed in range(5):
        pairs = colocated_pairs(sources, others, limit=8, seed=seed)         # 8 own-function pairs among 64 in the file
        assert sorted(s.scope for s, _ in pairs) == sorted(f"fn_p{n}" for n in range(8))
        assert all(s.scope == o.scope for s, o in pairs)                     # the plausible path is taken first


def test_the_draw_does_not_spend_two_slots_on_one_atom_while_others_wait():
    sources = [placed("source", f"s{n}", "dir_a/file_a.py", f"fn_p{n}") for n in range(6)]
    others = [placed("sink", f"k{n}", "dir_a/file_a.py", f"fn_q{n}") for n in range(6)]
    for seed in range(5):
        pairs = colocated_pairs(sources, others, limit=6, seed=seed)         # 36 pairs, none inside one function
        assert len({s.id for s, _ in pairs}) == 6 and len({o.id for _, o in pairs}) == 6
        assert len({s.scope for s, _ in pairs} | {o.scope for _, o in pairs}) == 12


def test_the_draw_fills_the_limit_when_new_functions_run_out():
    sources = [placed("source", f"s{n}", "dir_a/file_a.py", "fn_lone") for n in range(3)]
    others = [placed("sink", f"k{n}", "dir_a/file_a.py", "fn_lone") for n in range(3)]
    pairs = colocated_pairs(sources, others, limit=5, seed=4)
    assert len(pairs) == len(set((s.id, o.id) for s, o in pairs)) == 5
    assert colocated_pairs(sources, others, limit=5, seed=4) == pairs              # the same seed draws the same pairs


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


def test_the_report_lists_the_hunted_candidates_not_the_top_of_the_score(tmp_path):
    from test_pipeline import FIXTURE, ScriptedModel

    from alien_hunt.budget import Budget
    from alien_hunt.config import Prices
    from alien_hunt.pipeline import execute

    execute(FIXTURE, model=ScriptedModel(), budget=Budget(limit_usd=5), prices=Prices(1, 1, 1), out_dir=tmp_path,
            sample_limit=1000, confirm_mode="local", scanners=False, run_id="floor")
    hunts = json.loads((tmp_path / "04-hunts.json").read_text(encoding="utf-8"))
    records = hunts.get("hunts") if isinstance(hunts, dict) else hunts
    assert records and all(item["coherence"] >= 3 for item in records)
    text = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    judged = next(line for line in text.splitlines() if line.startswith("- Top candidates judged:"))
    assert judged.endswith(f"of {len(records)} (a hunt that never submitted gives no verdict)")


def test_input_sized_loops_and_decodes_are_sinks(tmp_path: Path):
    """joserfc's advisories: a JWE recipients list processed in full, and compact segments split and decoded before the
    size check. The first sinks (eval, pickle, a multiplication) gave the hunts nothing there."""
    from alien_hunt.atoms import extract_atoms

    pkg = tmp_path / "jose"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "json.py").write_text(
        "import base64\n"
        "def extract_general_json(data, registry):\n"
        "    out = [r for r in data['recipients']]\n"
        "    for key, value in registry.items():\n"
        "        pass\n"
        "    for n in range(10):\n"
        "        pass\n"
        "    return out\n"
        "def extract_compact(value, registry):\n"
        "    parts = value.split(b'.')\n"
        "    header = base64.urlsafe_b64decode(value)\n"
        "    return parts, header\n"
        "class R:\n"
        "    def check(self, items):\n"
        "        for x in self.cache:\n"
        "            pass\n", encoding="utf-8")
    _sources, sinks, _invariants, mechanisms = extract_atoms(tmp_path)
    texts = sorted(s.text for s in sinks if "caller-supplied" in s.text)
    assert texts == [
        "base64 decode of caller-supplied value in extract_compact",
        "loop over caller-supplied data['recipients'] in extract_general_json",
        "loop over caller-supplied registry.items() in extract_general_json",
        "split of caller-supplied value in extract_compact",
    ]
    assert all(s.file == "jose/json.py" for s in sinks)            # co-located with the functions' own arguments
    assert any("before its length is checked" in m.text for m in mechanisms)
