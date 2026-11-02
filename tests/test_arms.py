"""Three selection rules on one pool. In the runs so far every candidate above the coherence floor was hunted, so the
floor chose and the score only set the order; these pin a comparison in which the score can change what is looked at."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from alien_hunt import cli
from alien_hunt.arms import ARMS, arm_summary, arm_totals, claim_id, hunt_order, select_arms, write_label_sheet
from alien_hunt.budget import Budget
from alien_hunt.cli import main
from alien_hunt.config import Prices
from alien_hunt.pipeline import execute
from alien_hunt.types import Atom, Candidate, ChatResponse, Claim, Confirmation, KnownAdvisory, ToolCall
from test_pipeline import FIXTURE, ScriptedModel

ADVISORY = KnownAdvisory(id="GHSA-x", class_label="denial of service", symbols=["extract_compact"], classes=["dos"])


def _hunted(*candidates: Candidate) -> list[Candidate]:
    for candidate in candidates:
        candidate.hunt_usd = 0.1
    return list(candidates)


def _candidate(name: str, coherence: float, score: float, function: str | None = None) -> Candidate:
    return Candidate(
        id=name,
        source=Atom("source", f"s-{name}", "s", file="pkg/mod.py", function=function),
        mechanism=Atom("mechanism", "m", "m"),
        other=Atom("sink", f"o-{name}", "o", file="pkg/mod.py"),
        coherence=coherence,
        score_0_7=score,
        rated=True,
    )


def _pool(size: int, coherence: float = 2.0) -> list[Candidate]:
    return [_candidate(f"c{index:03}", coherence, float(size - index)) for index in range(size)]


def _claim(candidate: str | None, functions: list[str], *, klass: str = "logic", text: str = "t", origin: str = "hunt") -> Claim:
    return Claim(text=text, class_label=klass, files=[], functions=functions, reproducer=f"# {text}", origin=origin, candidate_id=candidate)


def _run(arms: dict[str, list[Candidate]], pairs: list[tuple[Claim, Confirmation]], known=None) -> dict:
    return arm_summary(arms, pairs, known or [], floor=3.0)


YES = Confirmation(True, "ok")
NO = Confirmation(False, "no")


def test_the_combined_rule_takes_the_score_with_no_floor():
    low_but_far = _candidate("far", 1.0, 9.0)
    high_but_near = _candidate("near", 5.0, 1.0)
    arms = select_arms([low_but_far, high_but_near], 1, seed=0)
    assert [item.id for item in arms["combined"]] == ["far"]
    assert [item.id for item in arms["coherence"]] == ["near"]


def test_each_rule_picks_as_many_and_the_pool_is_shared():
    ranked = _pool(50)
    arms = select_arms(ranked, 10, seed=1)
    assert set(arms) == set(ARMS)
    assert all(len(picks) == 10 and len({item.id for item in picks}) == 10 for picks in arms.values())
    assert all(item in ranked for picks in arms.values() for item in picks)


@pytest.mark.parametrize("arm", ["coherence", "random"])
def test_the_score_does_not_reach_the_other_rules(arm: str):
    """Coherence is a coarse rating, so most of its order is ties: broken by the score, this rule would be the other."""

    ranked = _pool(60)
    reordered = sorted(ranked, key=lambda item: item.id, reverse=True)
    assert [item.id for item in select_arms(ranked, 10, seed=1)[arm]] == [item.id for item in select_arms(reordered, 10, seed=1)[arm]]
    assert [item.id for item in select_arms(ranked, 10, seed=1)[arm]] != [item.id for item in ranked[:10]]


def test_a_higher_rating_still_comes_first_whatever_the_seed():
    ranked = [*_pool(30), _candidate("top", 5.0, -9.0)]
    for seed in range(5):
        assert select_arms(ranked, 3, seed=seed)["coherence"][0].id == "top"


def test_a_draw_repeats_with_its_seed_and_moves_with_another():
    ranked = _pool(60)
    first = [item.id for item in select_arms(ranked, 10, seed=1)["random"]]
    assert first == [item.id for item in select_arms(ranked, 10, seed=1)["random"]]
    assert first != [item.id for item in select_arms(ranked, 10, seed=2)["random"]]


def test_a_pool_smaller_than_the_ask_is_taken_whole():
    arms = select_arms(_pool(3), 10, seed=0)
    assert all(len(picks) == 3 for picks in arms.values())
    assert select_arms([], 10, seed=0) == {name: [] for name in ARMS}


def test_rules_take_turns_and_a_shared_pick_is_hunted_once():
    a, b, c, d = (_candidate(name, 1.0, 1.0) for name in "abcd")
    arms = {"combined": [a, b], "coherence": [a, c], "random": [d, b]}
    assert [item.id for item in hunt_order(arms)] == ["a", "d", "c", "b"]


def test_no_rule_is_always_first_so_a_stop_leaves_them_within_one_hunt():
    pools = {name: [_candidate(f"{name}{index}", 1.0, 1.0) for index in range(6)] for name in ARMS}
    order = hunt_order(pools)
    assert [item.id[:-1] for item in order[:6]] == ["combined", "coherence", "random", "coherence", "random", "combined"]
    for stop in range(len(order) + 1):
        reached = [sum(1 for item in order[:stop] if item.id.startswith(name)) for name in ARMS]
        assert max(reached) - min(reached) <= 1


def test_claims_merge_within_a_rule_and_not_across_rules():
    """A claim of the random rule naming both functions would otherwise join the combined rule's two issues into one."""

    a, b = _hunted(_candidate("a", 1.0, 1.0), _candidate("b", 1.0, 1.0))
    pairs = [
        (_claim("a", ["pkg.f"], klass="x", text="a1"), YES),
        (_claim("a", ["pkg.g"], klass="x", text="a2"), YES),
        (_claim("b", ["pkg.f", "pkg.g"], klass="x", text="b1"), YES),
    ]
    run = _run({"combined": [a], "coherence": [], "random": [b]}, pairs)
    assert (arm_totals([run])["combined"]["confirmed"], arm_totals([run])["random"]["confirmed"]) == (2, 1)
    assert len(run["arms"]["combined"]["issues"]) == 2


def test_a_refused_claim_does_not_join_two_confirmed_issues():
    pick = _candidate("c", 1.0, 1.0)
    pairs = [
        (_claim("c", ["pkg.f"], text="one"), YES),
        (_claim("c", ["pkg.g"], text="two"), YES),
        (_claim("c", ["pkg.f", "pkg.g"], text="bridge"), NO),
    ]
    assert arm_totals([_run({"combined": [pick], "coherence": [], "random": []}, pairs)])["combined"]["confirmed"] == 2


def test_a_shared_pick_counts_for_each_rule_that_took_it():
    shared = _candidate("shared", 3.0, 1.0)
    other = _candidate("other", 1.0, 1.0)
    shared.hunt_usd, other.hunt_usd = 0.5, 0.25
    arms = {"combined": [shared, other], "coherence": [shared], "random": []}
    run = _run(arms, [(_claim("shared", ["pkg.f"]), YES)])
    totals = arm_totals([run])
    assert (totals["combined"]["hunts"], totals["combined"]["usd"], totals["combined"]["confirmed"]) == (2, 0.75, 1)
    assert (totals["coherence"]["hunts"], totals["coherence"]["usd"], totals["coherence"]["confirmed"]) == (1, 0.5, 1)
    assert totals["random"]["hunts"] == 0
    assert (totals["combined"]["above_floor"], totals["coherence"]["above_floor"]) == (1, 1)


def test_only_what_ran_counts_as_a_hunt():
    ran, cut, failed = _candidate("ran", 1.0, 1.0), _candidate("cut", 1.0, 1.0), _candidate("failed", 1.0, 1.0)
    ran.hunt_usd, failed.hunt_usd, failed.hunt_error = 0.1, 0.0, "model error"
    totals = arm_totals([_run({"combined": [ran, cut, failed], "coherence": [], "random": []}, [])])
    assert totals["combined"]["hunts"] == 1


def test_two_claims_on_one_issue_count_once_and_a_refused_one_not_at_all():
    pick = _candidate("c", 1.0, 1.0)
    pairs = [
        (_claim("c", ["pkg.f"], text="one"), YES),
        (_claim("c", ["pkg.f"], text="two"), YES),
        (_claim("c", ["pkg.g"], text="three"), NO),
    ]
    totals = arm_totals([_run({"combined": [pick], "coherence": [], "random": []}, pairs)])["combined"]
    assert (totals["claims"], totals["confirmed"]) == (3, 1)


@pytest.mark.parametrize(
    "reviewed, hunted, beyond",
    [
        ("pkg.mod.Reg.check", "pkg.mod.Reg.check", False),
        ("Reg.check", "pkg.mod.Reg.check", False),
        ("pkg.mod.Reg.check", "check", False),
        ("pkg.mod.Reg.check", "pkg.mod.Reg.other", True),
        ("pkg.mod.check_all", "pkg.mod.check", True),
    ],
)
def test_a_function_is_the_same_whatever_form_its_name_takes(reviewed: str, hunted: str, beyond: bool):
    pick = _candidate("c", 1.0, 1.0)
    pairs = [(_claim(None, [reviewed], text="review", origin="plain"), NO), (_claim("c", [hunted], text="hunt"), YES)]
    assert arm_totals([_run({"combined": [pick], "coherence": [], "random": []}, pairs)])["combined"]["beyond"] == int(beyond)


def test_a_claim_with_no_function_is_not_beyond_the_reviews():
    pick = _candidate("c", 1.0, 1.0)
    run = _run({"combined": [pick], "coherence": [], "random": []}, [(_claim("c", [], text="vague"), YES)])
    assert run["arms"]["combined"]["beyond"] == 0
    assert run["arms"]["combined"]["issues"][0]["beyond"] is False


def test_beyond_the_reviews_means_no_review_named_the_function():
    """Whether or not the review's own claim was confirmed: what it reported is what was available."""

    pick = _candidate("c", 1.0, 1.0)
    pairs = [
        (_claim(None, ["pkg.seen"], text="review", origin="plain"), NO),
        (_claim("c", ["pkg.seen"], text="same place", klass="a"), YES),
        (_claim("c", ["pkg.new"], text="new place", klass="b"), YES),
    ]
    totals = arm_totals([_run({"combined": [pick], "coherence": [], "random": []}, pairs)])["combined"]
    assert (totals["confirmed"], totals["beyond"]) == (2, 1)


def test_advisories_are_counted_by_reach_by_claim_and_by_confirmation():
    near, far = _hunted(_candidate("near", 1.0, 1.0, function="extract_compact"), _candidate("far", 1.0, 1.0, function="elsewhere"))
    pairs = [(_claim("near", ["extract_compact"], klass="dos", text="a"), NO)]
    arms = {"combined": [near], "coherence": [far], "random": []}
    totals = arm_totals([_run(arms, pairs, [ADVISORY])])
    assert (totals["combined"]["on_advisory"], totals["combined"]["advisories_claimed"], totals["combined"]["advisories_confirmed"]) == (1, 1, 0)
    assert (totals["coherence"]["on_advisory"], totals["coherence"]["advisories_claimed"]) == (0, 0)
    confirmed = arm_totals([_run(arms, [(pairs[0][0], YES)], [ADVISORY])])
    assert confirmed["combined"]["advisories_confirmed"] == 1


def test_reach_counts_what_was_hunted_not_what_was_picked():
    never = _candidate("never", 5.0, 1.0, function="extract_compact")
    totals = arm_totals([_run({"combined": [never], "coherence": [], "random": []}, [], [ADVISORY])])["combined"]
    assert (totals["hunts"], totals["above_floor"], totals["on_advisory"]) == (0, 0, 0)


def test_labels_decide_what_is_real_and_an_issue_counts_once():
    pick = _candidate("c", 1.0, 1.0)
    one, two, other, plain = (
        _claim("c", ["pkg.f"], text="one"),
        _claim("c", ["pkg.f"], text="two"),
        _claim("c", ["pkg.g"], text="other"),
        _claim(None, ["pkg.g"], text="review", origin="plain"),
    )
    run = _run({"combined": [pick], "coherence": [], "random": []}, [(plain, NO), (one, YES), (two, YES), (other, YES)])
    labels = {claim_id(one): "real", claim_id(two): "real", claim_id(other): "real"}
    totals = arm_totals([run], labels)["combined"]
    assert (totals["real"], totals["real_beyond"], totals["unlabelled"]) == (2, 1, 0)
    partly = arm_totals([run], {claim_id(one): "not"})["combined"]
    assert (partly["real"], partly["real_beyond"], partly["unlabelled"]) == (0, 0, 1)


def test_the_label_sheet_does_not_say_which_rule_found_a_claim(tmp_path: Path):
    claims = [_claim(f"c{index}", ["pkg.f"], text=f"claim {index}") for index in range(8)]
    pairs = [(_claim(None, ["pkg.r"], text="review", origin="plain"), YES), *((claim, YES) for claim in claims)]
    path = write_label_sheet(tmp_path / "local" / "arms-to-label.jsonl", pairs, seed=3)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert {row["id"] for row in rows} == {claim_id(claim) for claim in claims}
    assert all(not set(row) & {"candidate_id", "candidate", "arm", "arms", "origin"} for row in rows)
    assert [row["text"] for row in rows] != [claim.text for claim in claims]
    assert all(row["reproducer"] for row in rows)


def _execute(tmp_path: Path, model, budget: Budget | None = None, arms: int = 2) -> Path:
    return execute(
        FIXTURE,
        model=model,
        budget=budget or Budget(limit_usd=5),
        prices=Prices(1, 1, 1),
        out_dir=tmp_path,
        sample_limit=1000,
        confirm_mode="local",
        scanners=False,
        target="fixture",
        run_id="fixture",
        arms=arms,
    )


def test_a_run_hunts_each_pick_once_and_records_the_rules(tmp_path: Path):
    model = ScriptedModel()
    text = _execute(tmp_path, model).read_text(encoding="utf-8")
    run = json.loads((tmp_path / "06-arms.json").read_text(encoding="utf-8"))
    picks = {name: run["arms"][name]["picks"] for name in ARMS}
    assert all(len(ids) == 2 for ids in picks.values())
    hunted = {identifier for ids in picks.values() for identifier in ids}
    assert sum(1 for prompt in model.prompts if "STAGE: hunt" in prompt) == len(hunted)
    assert {item["id"] for item in json.loads((tmp_path / "04-hunts.json").read_text(encoding="utf-8"))} == hunted
    assert "## Selection comparison" in text and "the floor was off" in text
    assert "allocate" not in text
    assert run["cut_short"] is False and run["floor"] == 3.0
    best = run["arms"]["coherence"]
    assert best["hunts"] == 2 and best["confirmed"] >= 1 and best["beyond"] == best["confirmed"]
    ids = {identifier for name in ARMS for issue in run["arms"][name]["issues"] for identifier in issue["claims"]}
    sheet = [json.loads(line) for line in (tmp_path / "local" / "arms-to-label.jsonl").read_text(encoding="utf-8").splitlines()]
    assert ids and {row["id"] for row in sheet} == ids
    assert all(row["reproducer"] and "load_config" not in row["text"] for row in sheet)


def test_a_usual_run_keeps_the_floor_and_writes_no_comparison(tmp_path: Path):
    text = _execute(tmp_path, ScriptedModel(), arms=0).read_text(encoding="utf-8")
    assert "## Selection comparison" not in text and "only those are hunted" in text
    assert not (tmp_path / "06-arms.json").exists()
    assert not (tmp_path / "local" / "arms-to-label.jsonl").exists()
    hunts = json.loads((tmp_path / "04-hunts.json").read_text(encoding="utf-8"))
    assert hunts and all(item["coherence"] >= 3 for item in hunts)


class _StopsAfterOneHunt(ScriptedModel):
    def __init__(self, budget: Budget) -> None:
        super().__init__()
        self.budget = budget

    def chat(self, *, messages, tools, max_tokens):
        response = super().chat(messages=messages, tools=tools, max_tokens=max_tokens)
        if "STAGE: hunt" in self.prompts[-1]:
            self.budget.limit_usd = 0
        return response


def test_a_budget_stop_shows_how_far_each_rule_got(tmp_path: Path):
    budget = Budget(limit_usd=5)
    text = _execute(tmp_path, _StopsAfterOneHunt(budget), budget).read_text(encoding="utf-8")
    run = json.loads((tmp_path / "06-arms.json").read_text(encoding="utf-8"))
    assert "Stopped early: yes" in text and run["cut_short"] is True
    assert max(run["arms"][name]["hunts"] for name in ARMS) == 1
    assert all(len(run["arms"][name]["picks"]) == 2 for name in ARMS)


class _CutMidHunt(ScriptedModel):
    """The first hunt asks for a tool, and the stop line is crossed before it can go on."""

    def __init__(self, budget: Budget) -> None:
        super().__init__()
        self.budget = budget

    def chat(self, *, messages, tools, max_tokens):
        response = super().chat(messages=messages, tools=tools, max_tokens=max_tokens)
        if "STAGE: hunt" in self.prompts[-1]:
            self.budget.limit_usd = 0
            return ChatResponse("", [ToolCall(id="call-1", name="list_dir", arguments={"path": "."})], 100, 50)
        return response


def test_a_hunt_the_budget_cuts_is_no_hunt_but_its_cost_stays(tmp_path: Path):
    budget = Budget(limit_usd=5)
    _execute(tmp_path, _CutMidHunt(budget), budget)
    run = json.loads((tmp_path / "06-arms.json").read_text(encoding="utf-8"))
    assert run["cut_short"] is True
    assert all(run["arms"][name]["hunts"] == 0 for name in ARMS)
    assert max(run["arms"][name]["usd"] for name in ARMS) > 0
    errors = [item["error"] for item in json.loads((tmp_path / "04-hunts.json").read_text(encoding="utf-8"))]
    assert "cut by the budget" in errors


def test_the_command_adds_up_runs_with_labels(tmp_path: Path, capsys):
    claims = [_claim("c", ["pkg.f"], text="found in the first run"), _claim("c", ["pkg.f"], text="found in the second")]
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({claim_id(claims[0]): "real", "typo": "real"}), encoding="utf-8")
    for name, claim in zip("ab", claims):
        pick = _candidate("c", 1.0, 1.0)
        pick.hunt_usd = 0.5
        run = arm_summary({"combined": [pick], "coherence": [], "random": []}, [(claim, YES)], [], floor=3.0, cut_short=name == "b")
        (tmp_path / name).mkdir()
        (tmp_path / name / "06-arms.json").write_text(json.dumps(run), encoding="utf-8")
    assert main(["arms", str(tmp_path / "a"), str(tmp_path / "b"), "--labels", str(labels)]) == 0
    out = capsys.readouterr().out
    head = next(line for line in out.splitlines() if line.startswith("| Rule"))
    row = next(line for line in out.splitlines() if line.startswith("| combined"))
    cells = dict(zip((cell.strip() for cell in head.strip("|").split("|")), (cell.strip() for cell in row.strip("|").split("|"))))
    assert (cells["Hunts"], cells["USD"], cells["Confirmed issues"]) == ("2", "1.00", "2")
    assert (cells["Real"], cells["Real beyond the reviews"], cells["Unlabelled"]) == ("1", "1", "1")
    assert "Runs: 2 (cut short by the budget or an error: 1)" in out and "Labels that match no claim: 1" in out


def test_the_command_refuses_the_same_run_twice(tmp_path: Path, capsys):
    (tmp_path / "06-arms.json").write_text(json.dumps(_run({name: [] for name in ARMS}, [])), encoding="utf-8")
    assert main(["arms", str(tmp_path), str(tmp_path / ".")]) == 2
    assert "twice" in capsys.readouterr().err


@pytest.mark.parametrize("body", ["[]", "{}", '{"arms": {"combined": {}}}', "not json"])
def test_the_command_refuses_a_file_it_did_not_write(tmp_path: Path, capsys, body: str):
    (tmp_path / "06-arms.json").write_text(body, encoding="utf-8")
    assert main(["arms", str(tmp_path)]) == 2
    assert "06-arms.json" in capsys.readouterr().err


def test_the_command_refuses_a_run_with_no_comparison(tmp_path: Path, capsys):
    assert main(["arms", str(tmp_path)]) == 2
    assert "06-arms.json" in capsys.readouterr().err


@pytest.mark.parametrize("body", ["not json", "[1]", '{"id": 1}'])
def test_the_command_refuses_labels_it_cannot_read(tmp_path: Path, capsys, body: str):
    (tmp_path / "06-arms.json").write_text(json.dumps(_run({name: [] for name in ARMS}, [])), encoding="utf-8")
    labels = tmp_path / "labels.json"
    labels.write_text(body, encoding="utf-8")
    assert main(["arms", str(tmp_path), "--labels", str(labels)]) == 2
    assert "labels" in capsys.readouterr().err


def test_the_flag_reaches_the_run(tmp_path: Path, monkeypatch, capsys):
    seen = {}
    config = SimpleNamespace(
        secrets=lambda: None, prices=Prices(1, 1, 1), sample_limit=1, max_tool_rounds_review=1, plain_temperature=None,
        max_tool_rounds_hunt=1, max_tokens_per_hunt=1, coherence_batch=1, container_image="i", max_output_tokens=1,
        min_coherence=3.0, fallback_hunts=3,
    )
    monkeypatch.setattr(cli, "load_config", lambda path: config)
    monkeypatch.setattr(cli, "OpenAIModel", lambda config: object())
    monkeypatch.setattr(cli, "execute", lambda checkout, **kwargs: seen.update(kwargs) or "report")
    assert main(["run", "--local", str(FIXTURE), "--arms", "7", "--out", str(tmp_path)]) == 0
    assert seen["arms"] == 7


def test_a_negative_arm_count_is_refused_before_anything_is_paid(capsys):
    assert main(["run", "--local", str(FIXTURE), "--arms", "-1"]) == 2
    assert "--arms" in capsys.readouterr().err
