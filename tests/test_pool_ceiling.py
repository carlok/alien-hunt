"""scripts/pool_ceiling.py: what the pool can reach of a fix, measured with the pool's own rules and no model."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from alien_hunt import atoms as atoms_module
from alien_hunt import score as score_module

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pool_ceiling.py"

_spec = importlib.util.spec_from_file_location("pool_ceiling", SCRIPT)
pc = importlib.util.module_from_spec(_spec)
sys.modules["pool_ceiling"] = pc
_spec.loader.exec_module(pc)


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def make_case(base: Path, name: str, before: dict[str, str], after: dict[str, str], **meta) -> Path:
    case = base / name
    write_tree(case / "before", before)
    write_tree(case / "after", after)
    (case / "case.json").write_text(json.dumps({"id": name, **meta}), encoding="utf-8")
    return case


BEFORE = """\
def keep(a):
    return a


def fix(b):
    \"\"\"Old doc.\"\"\"
    return b


def gone(c):
    return c


class K:
    def method(self, d):
        return d
"""

AFTER = """\
def keep(a):
    return a


def fix(b):
    \"\"\"A new doc, and nothing else.\"\"\"
    return b


def added(e):
    return e


class K:
    def method(self, d):
        return d + 1
"""


def test_the_fix_is_the_functions_the_diff_changes_or_removes(tmp_path: Path):
    before = write_tree(tmp_path / "b", {"pkg/mod.py": BEFORE, "tests/test_x.py": "def t(x):\n    return x\n"})
    after = write_tree(tmp_path / "a", {"pkg/mod.py": AFTER, "tests/test_x.py": "def t(x):\n    return x + 1\n"})
    targets = pc.fix_functions(before, after, atoms_module)
    assert [(func.file, func.qualname) for func in targets] == [("pkg/mod.py", "gone"), ("pkg/mod.py", "K.method")]
    assert targets[0].start == 10 and targets[0].end == 11


def test_a_removed_file_and_a_syntax_error_are_handled(tmp_path: Path):
    before = write_tree(tmp_path / "b", {"pkg/old.py": "def f(x):\n    return x\n", "pkg/bad.py": "def (:\n"})
    after = write_tree(tmp_path / "a", {"pkg/bad.py": "def (:\n"})
    assert [func.qualname for func in pc.fix_functions(before, after, atoms_module)] == ["f"]


def test_a_sink_counts_by_its_lines_not_by_its_function_field(tmp_path: Path):
    case = make_case(
        tmp_path,
        "c1",
        {"pkg/m.py": "def run():\n    return eval('1')\n\n\ndef other(x):\n    return x\n"},
        {"pkg/m.py": "def run():\n    return 1\n\n\ndef other(x):\n    return x\n"},
    )
    rec = pc.measure_case(case / "before", case / "after")
    assert rec["atom_hit"] is True                # the eval sink is inside run()
    assert rec["atom_hit_literal"] is False       # its `function` field is "eval"
    assert rec["atoms_in_targets"] == {"source": 0, "sink": 1, "invariant": 0}
    assert rec["targets_without_atoms"] == []


def test_a_fix_function_with_no_atoms_is_a_miss(tmp_path: Path):
    case = make_case(
        tmp_path,
        "c2",
        {"pkg/m.py": "def quiet():\n    return 1\n\n\ndef other(x):\n    return x\n"},
        {"pkg/m.py": "def quiet():\n    return 2\n\n\ndef other(x):\n    return x\n"},
    )
    rec = pc.measure_case(case / "before", case / "after")
    assert rec["atom_hit"] is False and rec["pair_hit"] is False
    assert rec["drawn_hit"] == 0.0 and rec["touch_share"] == 0.0
    assert rec["targets_without_atoms"] == ["pkg/m.py:quiet"]


def test_a_fix_that_only_changes_tests_has_no_target(tmp_path: Path):
    case = make_case(
        tmp_path,
        "c3",
        {"pkg/m.py": "def f(x):\n    return x\n", "tests/test_m.py": "def t(x):\n    return 1\n"},
        {"pkg/m.py": "def f(x):\n    return x\n", "tests/test_m.py": "def t(x):\n    return 2\n"},
    )
    assert pc.measure_case(case / "before", case / "after") == {"status": "no_targets", "targets": []}


POOL_BEFORE = """\
def one(a):
    return a


def two(b):
    return b


def three(c):
    return c


def sink():
    return eval("1")
"""
POOL_AFTER = POOL_BEFORE.replace("def one(a):\n    return a", "def one(a):\n    return a + 1")


def test_a_pair_and_a_draw_follow_the_pools_own_rule(tmp_path: Path):
    case = make_case(tmp_path, "c4", {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER})
    rec = pc.measure_case(case / "before", case / "after", sample_limit=4)        # one pair kept per run
    assert rec["pool_size"] == 3 and rec["touching_pairs"] == 1 and rec["kept_pairs"] == 1
    assert rec["pair_hit"] is True
    assert rec["touch_share"] == pytest.approx(1 / 3)
    sources, sinks, invariants, _ = atoms_module.extract_atoms(case / "before")
    expected = 0
    for seed in range(pc.SEEDS):
        kept = score_module.pool_pairs(sources, sinks, invariants, sample_limit=4, seed=seed)
        expected += any("one" in (left.function or "") for left, _right in kept)
    assert rec["drawn_hit"] == pytest.approx(expected / pc.SEEDS)
    assert 0 < rec["drawn_hit"] < 1
    whole = pc.measure_case(case / "before", case / "after", sample_limit=80)     # 20 pairs kept: all three
    assert whole["drawn_hit"] == 1.0


def test_pool_pairs_is_what_the_pipeline_used_to_build_inline():
    sources = [atoms_module.Atom("source", f"s{i}", "s", file="a.py") for i in range(6)]
    sinks = [atoms_module.Atom("sink", f"k{i}", "k", file="a.py") for i in range(3)]
    invariants = [atoms_module.Atom("invariant", "i", "i", file="b.py")]
    for limit in (1, 3, 4, 40, 80):
        expected = score_module.colocated_pairs(sources, [*sinks, *invariants], limit=max(1, limit // 4), seed=5)
        assert score_module.pool_pairs(sources, sinks, invariants, sample_limit=limit, seed=5) == expected


def test_summaries_are_rates_over_the_cases_that_have_a_target():
    records = [
        {"status": "ok", "family": "x", "atom_hit": True, "atom_hit_literal": True, "pair_hit": True,
         "drawn_hit": 0.5, "pool_size": 10, "touching_pairs": 5, "touch_share": 0.5},
        {"status": "ok", "family": "x", "atom_hit": False, "atom_hit_literal": False, "pair_hit": False,
         "drawn_hit": 0.0, "pool_size": 30, "touching_pairs": 0, "touch_share": 0.0},
        {"status": "no_targets", "family": "y", "targets": []},
        {"status": "ok", "family": "y", "atom_hit": True, "atom_hit_literal": False, "pair_hit": True,
         "drawn_hit": 1.0, "pool_size": 20, "touching_pairs": 2, "touch_share": 0.1},
    ]
    overall = pc.summarize(records)
    assert (overall["cases"], overall["measured"], overall["no_targets"]) == (4, 3, 1)
    assert overall["atom_hit"] == pytest.approx(2 / 3)
    assert overall["atom_hit_literal"] == pytest.approx(1 / 3)
    assert overall["drawn_hit"] == pytest.approx(0.5)
    assert overall["touch_share"] == pytest.approx(0.2)
    assert overall["pooled_touch_share"] == pytest.approx(7 / 60)
    families = pc.by_family(records)
    assert families["x"]["measured"] == 2 and families["y"]["no_targets"] == 1
    assert pc.summarize([{"status": "no_targets"}]) == {"cases": 1, "measured": 0, "no_targets": 1}
    assert "| x | 2 |" in pc.render_table(overall, families)


def test_the_small_fix_slice_leaves_out_the_huge_commits():
    many = [f"f.py:g{i}:1-2" for i in range(6)]
    records = [
        {"status": "ok", "targets": ["f.py:a:1-2"], "atom_hit": True, "atom_hit_literal": True, "pair_hit": True,
         "drawn_hit": 0.0, "pool_size": 10, "touching_pairs": 1, "touch_share": 0.1},
        {"status": "ok", "targets": many, "atom_hit": True, "atom_hit_literal": True, "pair_hit": True,
         "drawn_hit": 1.0, "pool_size": 10, "touching_pairs": 9, "touch_share": 0.9},
        {"status": "no_targets", "targets": []},
    ]
    small = pc.summarize(pc.small_fixes(records))
    assert (small["measured"], small["drawn_hit"]) == (1, 0.0)
    assert pc.summarize(records)["drawn_hit"] == 0.5
    assert "fix of at most 5 functions" in pc.render_table(pc.summarize(records), {}, {"fix of at most 5 functions": small})


def test_measure_reads_a_folder_of_cases_and_filters_by_split_and_family(tmp_path: Path, capsys):
    cases = tmp_path / "cases"
    for name, family, split in (("g1", "injection", "tune"), ("g2", "injection", "heldout"), ("g3", "crypto", "tune")):
        make_case(cases, name, {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER}, family=family, split=split)
    out = tmp_path / "out.json"
    assert pc.main(["measure", str(cases), "--json", str(out), "--jobs", "1", "--split", "tune"]) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(rec["id"] for rec in payload["cases"]) == ["g1", "g3"]
    assert payload["overall"]["measured"] == 2 and set(payload["by_family"]) == {"crypto", "injection"}
    shown = capsys.readouterr().out
    assert "| all | 2 |" in shown and "| fix of at most 5 functions | 2 |" in shown
    assert "small_fix" in payload
    pc.main(["measure", str(cases), "--json", str(out), "--jobs", "1", "--family", "injection"])
    assert sorted(rec["id"] for rec in json.loads(out.read_text(encoding="utf-8"))["cases"]) == ["g1", "g2"]


def test_one_case_that_cannot_be_measured_is_recorded_not_fatal(tmp_path: Path):
    cases = tmp_path / "cases"
    make_case(cases, "ok", {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER}, family="f", split="tune")
    broken = cases / "broken"
    broken.mkdir()
    (broken / "case.json").write_text(json.dumps({"id": "broken", "family": "f", "split": "tune"}), encoding="utf-8")
    records = pc.measure_all(pc.load_cases(cases), src=None, seeds=2, sample_limit=80, jobs=1)
    by_id = {rec["id"]: rec for rec in records}
    assert by_id["ok"]["status"] == "ok"
    assert by_id["broken"]["status"] in {"error", "no_targets"}


def test_explain_lists_the_fix_functions_and_their_atoms(tmp_path: Path):
    case = make_case(tmp_path, "c5", {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER})
    text = pc.explain(case, src=None, sample_limit=80)
    assert "pkg/m.py:one" in text and "caller argument a of one" in text


def run_isolated(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)


def test_the_script_never_loads_the_model_client(tmp_path: Path):
    case = make_case(tmp_path, "c6", {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER})
    code = f"""
import importlib.util, sys
sys.path.insert(0, {str(ROOT / "src")!r})
spec = importlib.util.spec_from_file_location("pc", {str(SCRIPT)!r})
module = importlib.util.module_from_spec(spec)
sys.modules["pc"] = module
spec.loader.exec_module(module)
record = module.measure_case(__import__("pathlib").Path({str(case / "before")!r}), __import__("pathlib").Path({str(case / "after")!r}))
assert record["status"] == "ok", record
bad = [name for name in sys.modules if name in ("openai", "alien_hunt.llm", "alien_hunt.pipeline", "alien_hunt.cli")]
assert not bad, bad
print("clean")
"""
    done = run_isolated(code)
    assert done.stdout.strip() == "clean", done.stderr


def test_the_documented_isolated_command_works_with_src_and_a_process_pool(tmp_path: Path):
    cases = tmp_path / "cases"
    for name in ("c7", "c8", "c9"):
        make_case(cases, name, {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER}, family="f", split="tune")
    out = tmp_path / "out.json"
    done = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "measure", str(cases), "--src", str(ROOT / "src"), "--jobs", "2",
         "--json", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "| all | 3 |" in done.stdout
    assert [rec["status"] for rec in json.loads(out.read_text(encoding="utf-8"))["cases"]] == ["ok"] * 3


def test_src_takes_a_checkout_or_its_src_folder_and_refuses_anything_else(tmp_path: Path):
    checkout = tmp_path / "checkout"
    (checkout / "src" / "alien_hunt").mkdir(parents=True)
    (checkout / "src" / "alien_hunt" / "atoms.py").write_text("", encoding="utf-8")
    assert pc.package_root(checkout) == (checkout / "src").resolve()
    assert pc.package_root(checkout / "src") == (checkout / "src").resolve()
    with pytest.raises(ValueError, match="no alien_hunt package"):
        pc.package_root(tmp_path / "elsewhere")


def test_a_checkout_given_to_src_is_the_copy_that_gets_measured(tmp_path: Path):
    import shutil

    checkout = tmp_path / "checkout"
    shutil.copytree(ROOT / "src" / "alien_hunt", checkout / "src" / "alien_hunt", ignore=shutil.ignore_patterns("__pycache__"))
    code = f"""
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pc", {str(SCRIPT)!r})
module = importlib.util.module_from_spec(spec)
sys.modules["pc"] = module
spec.loader.exec_module(module)
atoms, score = module.load_alien_hunt(__import__("pathlib").Path({str(checkout)!r}))
print(atoms.__file__)
print(module.package_dir(__import__("pathlib").Path({str(checkout)!r})))
"""
    done = run_isolated(code)
    assert done.returncode == 0, done.stderr
    loaded, recorded = done.stdout.split()
    assert Path(loaded).resolve().is_relative_to((checkout / "src").resolve())
    assert recorded == str((checkout / "src" / "alien_hunt").resolve())


def test_the_command_line_stops_on_a_src_with_no_package_and_records_the_copy_it_measured(tmp_path: Path):
    cases = tmp_path / "cases"
    make_case(cases, "c10", {"pkg/m.py": POOL_BEFORE}, {"pkg/m.py": POOL_AFTER}, family="f", split="tune")
    bad = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "measure", str(cases), "--src", str(tmp_path / "nothing"), "--jobs", "1"],
        capture_output=True, text=True, check=False,
    )
    assert bad.returncode != 0 and "no alien_hunt package" in bad.stderr
    out = tmp_path / "out.json"
    good = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "measure", str(cases), "--src", str(ROOT), "--jobs", "1", "--json", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert good.returncode == 0, good.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["package"] == str((ROOT / "src" / "alien_hunt").resolve())


def _rec(ident, drawn, share, family="f", status="ok"):
    return {"id": ident, "family": family, "status": status, "targets": ["a:b:1-2"], "atom_hit": drawn > 0,
            "atom_hit_literal": drawn > 0, "pair_hit": drawn > 0, "drawn_hit": drawn, "pool_size": 100,
            "touching_pairs": int(share * 100), "touch_share": share}


def test_compare_keeps_a_change_that_raises_drawn_hit_and_holds_dilution():
    before = {"cases": [_rec("a", 0.0, 0.10), _rec("b", 0.5, 0.10), _rec("only-before", 1.0, 0.5)]}
    after = {"cases": [_rec("a", 0.5, 0.09), _rec("b", 0.5, 0.09), _rec("only-after", 0.0, 0.0)]}
    result = pc.compare(before, after)
    assert result["cases"] == 2 and result["keep"] is True
    assert result["before"]["drawn_hit"] == 0.25 and result["after"]["drawn_hit"] == 0.5
    text = pc.render_comparison(result)
    assert "| drawn_hit | 25.0% | 50.0% | +25.0 pts |" in text and "keep: yes" in text


def test_compare_rejects_a_change_that_dilutes_the_pool_by_more_than_a_fifth():
    before = {"cases": [_rec("a", 0.0, 0.10), _rec("b", 0.5, 0.10)]}
    after = {"cases": [_rec("a", 1.0, 0.07), _rec("b", 0.5, 0.07)]}
    result = pc.compare(before, after)
    assert result["keep"] is False and "touch_share fell" in result["why"]
    edge = pc.compare(before, {"cases": [_rec("a", 1.0, 0.08), _rec("b", 0.5, 0.08)]})
    assert edge["keep"] is True                                    # exactly four fifths is allowed


def test_compare_rejects_a_change_that_does_not_raise_drawn_hit_or_measures_nothing():
    before = {"cases": [_rec("a", 0.5, 0.10)]}
    assert pc.compare(before, {"cases": [_rec("a", 0.5, 0.20)]})["why"] == "drawn_hit did not rise"
    nothing = pc.compare(before, {"cases": [_rec("z", 1.0, 0.1)]})
    assert nothing["keep"] is False and nothing["why"] == "no case was measured in both"


def test_compare_reads_two_result_files(tmp_path: Path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"cases": [_rec("a", 0.0, 0.1)]}), encoding="utf-8")
    b.write_text(json.dumps({"cases": [_rec("a", 1.0, 0.1)]}), encoding="utf-8")
    assert pc.main(["compare", str(a), str(b)]) == 0
    assert "keep: yes" in capsys.readouterr().out
