"""The first live run (PyJWT, 2026-10-30) made no claim: the reviews explored until their last round and their replies
were cut at 1 200 tokens, every coherence batch failed to parse, and the hunts ran out of tokens before submitting.
These tests pin the fixes: a last turn that can only submit, a cut reply asked again, batches split until they parse."""

from __future__ import annotations

import json
from pathlib import Path

from alien_hunt.agent import CUT_SHORT, LAST_TURN, AgentResult, run_agent
from alien_hunt.hunt import judge_coherence
from alien_hunt.pipeline import rate_coherence
from alien_hunt.types import Atom, Candidate, ChatResponse, ToolCall

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"
CLAIM = {"text": "t", "class": "c", "files": ["samplelib/__init__.py"], "functions": ["samplelib.allocate"],
         "reproducer": "import sys\nsys.exit(1)\n"}


class Explorer:
    """Lists the root every time it may; submits one claim only when offered submit_claims alone."""

    def __init__(self, cut_first_submit: bool = False, text_first: bool = False, tokens: int = 100) -> None:
        self.calls: list[dict] = []
        self.cut_first_submit = cut_first_submit
        self.text_first = text_first
        self.tokens = tokens

    def chat(self, *, stage, messages, tools, max_tokens) -> ChatResponse:
        names = [tool["function"]["name"] for tool in tools or []]
        self.calls.append({"names": names, "last_user": messages[-1]["content"] if messages[-1]["role"] == "user" else None,
                           "max_tokens": max_tokens})
        if self.text_first:
            self.text_first = False
            return ChatResponse("I think there is a bug.", [], self.tokens, 10)
        if names == ["submit_claims"]:
            if self.cut_first_submit:
                self.cut_first_submit = False
                return ChatResponse("", [ToolCall("s0", "submit_claims", {})], self.tokens, max_tokens, finish_reason="length")
            return ChatResponse("", [ToolCall("s1", "submit_claims", {"path_exists": True, "claims": [CLAIM]})], self.tokens, 50)
        return ChatResponse("", [ToolCall(f"l{len(self.calls)}", "list_dir", {"path": "."})], self.tokens, 20)


def agent(model, **kw) -> AgentResult:
    args = dict(stage="plain", system="s", user="u", origin="plain", max_rounds=4, max_claims=10, token_cap=None)
    args.update(kw)
    return run_agent(model, FIXTURE, **args)


def test_a_review_that_explores_to_the_end_still_submits_on_its_last_turn():
    model = Explorer()
    result = agent(model, max_output=4000)
    assert (result.submitted, len(result.claims), result.rounds) == (True, 1, 4)
    assert [call["names"] for call in model.calls][-1] == ["submit_claims"]
    assert all("submit_claims" in call["names"] and len(call["names"]) > 1 for call in model.calls[:-1])
    assert model.calls[-1]["last_user"] == LAST_TURN
    assert {call["max_tokens"] for call in model.calls} == {4000}


def test_a_hunt_near_its_token_cap_is_asked_to_submit():
    model = Explorer(tokens=3000)
    result = agent(model, stage="hunt", origin="hunt", max_rounds=6, token_cap=8000)
    assert result.submitted and len(result.claims) == 1
    assert len(model.calls) == 3                      # 3 000, 6 000 (>= 75 % of 8 000): the third turn is the last


def test_a_reply_cut_at_the_limit_is_not_trusted_and_asked_again():
    model = Explorer(cut_first_submit=True)
    result = agent(model, max_rounds=3)
    assert result.submitted and len(result.claims) == 1
    assert model.calls[-1]["last_user"] == CUT_SHORT and model.calls[-1]["names"] == ["submit_claims"]


def test_a_plain_text_answer_gets_one_last_turn():
    model = Explorer(text_first=True)
    result = agent(model)
    assert result.submitted and len(result.claims) == 1
    assert len(model.calls) == 2 and model.calls[1]["last_user"] == LAST_TURN


def test_no_submit_means_no_verdict_and_a_denied_path_means_incoherent():
    cand = lambda: Candidate("c1", Atom("source", "s1", "s"), Atom("mechanism", "m1", "m"), Atom("sink", "k1", "k"))
    none, denied, accepted = cand(), cand(), cand()
    judge_coherence(none, AgentResult(), FIXTURE)
    judge_coherence(denied, AgentResult(path_exists=False, submitted=True), FIXTURE)
    judge_coherence(accepted, AgentResult(path_exists=True, submitted=True), FIXTURE)
    assert (none.incoherent, denied.incoherent, accepted.incoherent) == (None, True, False)


class Rater:
    """Answers with prose (not JSON) for a batch of more than two, and with ratings for two or fewer."""

    def __init__(self) -> None:
        self.sizes: list[int] = []
        self.answered: list[int] = []

    def chat(self, *, stage, messages, tools, max_tokens) -> ChatResponse:
        ids = [line.split()[1] for line in messages[0]["content"].splitlines() if line.startswith("Candidate ")]
        self.sizes.append(len(ids))
        if len(ids) > 2:
            return ChatResponse("Let me think about each of these in turn...", [], 100, max_tokens, finish_reason="length")
        self.answered.append(len(ids))
        ratings = [{"id": i, "score": 4, "path": ["samplelib/__init__.py:allocate"]} for i in ids]
        return ChatResponse(json.dumps({"ratings": ratings}), [], 100, 50)


def test_a_batch_that_does_not_parse_is_asked_again_in_halves():
    pool = [Candidate(f"c{n}", Atom("source", "s", "s"), Atom("mechanism", "m", "m"), Atom("sink", "k", "k")) for n in range(10)]
    model = Rater()
    rate_coherence(model, FIXTURE, pool, batch_size=10, max_output=4000)
    assert all(item.rated and item.coherence == 4 for item in pool)
    assert model.sizes[0] == 10 and sum(model.answered) == 10 and max(model.answered) <= 2


def test_the_report_says_how_many_claims_were_made_and_ratings_parsed():
    from alien_hunt.budget import Budget
    from alien_hunt.report import render_report
    from alien_hunt.types import Claim

    pool = [Candidate(f"c{n}", Atom("source", "s", "s"), Atom("mechanism", "m", "m"), Atom("sink", "k", "k")) for n in range(4)]
    pool[0].rated = pool[1].rated = True
    made = [Claim(text="t", class_label="c", files=[], functions=[], reproducer="r", origin="plain", candidate_id=None)]
    text = render_report(run_id="r", target="t", commit="x", budget=Budget(limit_usd=1.0), claims=[], top=pool[:2], known=[],
                         stopped=False, made=made, pool=pool)
    assert "- Claims made: 1" in text and "- Claims made: 0" in text
    assert "Coherence ratings parsed: 2 of 4" in text
    assert "Top candidates judged: 0 of 2" in text
