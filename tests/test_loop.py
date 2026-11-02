"""Failures a scripted model does not hit by itself: a model-chosen glob, a link out of the checkout, a submit that
cannot be read, a model error halfway through a paid run. No model is called."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from alien_hunt import cli, pipeline
from alien_hunt.agent import BAD_SUBMIT, SandboxError, _run_tool, run_agent, search
from alien_hunt.atoms import extract_atoms
from alien_hunt.budget import Budget
from alien_hunt.config import ConfigError, Prices, load_config
from alien_hunt.confirm import DepsStatus
from alien_hunt.llm import LLMError
from alien_hunt.pipeline import _cap_coherence, execute, rate_coherence
from alien_hunt.types import Atom, Candidate, ChatResponse, Confirmation, ToolCall

from test_pipeline import ScriptedModel
from test_roles import BASE, write

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"
CLAIM = {"text": "t", "class": "c", "files": ["a.py"], "functions": ["a.f"], "reproducer": "print(1)"}


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.py").write_text("needle = 1\n", encoding="utf-8")
    return root


def test_search_does_not_follow_a_link_out_of_the_checkout(tmp_path: Path):
    root = _repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("needle = 'secret'\n", encoding="utf-8")
    (root / "link.py").symlink_to(outside / "secret.py")
    (root / "dir").symlink_to(outside, target_is_directory=True)
    (root / "inner.py").symlink_to(root / "a.py")
    assert search(root, "needle") == "a.py:1:needle = 1"
    assert search(root, "needle", "dir/*.py") == ""                     # the file is no link; the folder above it is


def test_search_under_a_folder_with_a_dot_git_above_it_still_works(tmp_path: Path):
    parent = tmp_path / ".git" / "worktree"
    parent.mkdir(parents=True)
    assert search(_repo(parent), "needle") == "a.py:1:needle = 1"


def test_search_skips_the_checkouts_own_git_folder(tmp_path: Path):
    root = _repo(tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "hook.py").write_text("needle\n", encoding="utf-8")
    assert search(root, "needle") == "a.py:1:needle = 1"


@pytest.mark.parametrize("glob", ["/etc/*", "\\etc", "../*", "a/../../*", "x" * 101])
def test_an_unsafe_glob_comes_back_as_text(tmp_path: Path, glob: str):
    root = _repo(tmp_path)
    with pytest.raises(SandboxError):
        search(root, "needle", glob)
    body = _run_tool(root, ToolCall("1", "search", {"pattern": "needle", "glob": glob}), 200)
    assert body == "error: glob must be a relative pattern such as *.py"


def test_an_empty_glob_means_the_default(tmp_path: Path):
    assert "a.py" in _run_tool(_repo(tmp_path), ToolCall("1", "search", {"pattern": "needle", "glob": ""}), 200)


def test_only_the_start_of_a_long_line_is_searched(tmp_path: Path):
    root = _repo(tmp_path)
    (root / "long.py").write_text("x" * 600 + "faraway\n", encoding="utf-8")
    assert search(root, "faraway") == ""


@pytest.mark.parametrize(
    "call",
    [
        ToolCall("1", "read_file", {"path": "a.py", "start_line": [1]}),
        ToolCall("1", "read_file", {"path": "a.py", "start_line": "first"}),
        ToolCall("1", "read_file", {"path": "../outside"}),
        ToolCall("1", "read_file", {"path": "bad\0path"}),
        ToolCall("1", "list_dir", {"path": "missing"}),
        ToolCall("1", "search", {"pattern": "("}),
        ToolCall("1", "read_file", {}, invalid=True),
    ],
)
def test_a_tool_error_comes_back_as_text(tmp_path: Path, call: ToolCall):
    assert _run_tool(_repo(tmp_path), call, 200).startswith("error:")


class Seq:
    """Plays back replies and records what it was sent."""

    def __init__(self, *replies: ChatResponse) -> None:
        self.replies = list(replies)
        self.sent: list[dict] = []

    def chat(self, *, stage, messages, tools, max_tokens, **extra) -> ChatResponse:
        self.sent.append({"messages": list(messages), "tools": [tool["function"]["name"] for tool in tools], "extra": extra})
        return self.replies.pop(0)


def _submit(arguments: dict, invalid: bool = False) -> ChatResponse:
    return ChatResponse("", [ToolCall("s", "submit_claims", arguments, invalid=invalid)], 100, 20, finish_reason="tool_calls")


def _agent(tmp_path: Path, model: Seq, **options):
    settings = dict(stage="hunt", system="s", user="u", origin="hunt", max_rounds=4, max_claims=10, token_cap=None)
    return run_agent(model, _repo(tmp_path), **{**settings, **options})


GOOD = {"path_exists": True, "claims": [CLAIM]}


@pytest.mark.parametrize(
    "bad, problem",
    [
        (_submit({}, invalid=True), "the arguments were not valid JSON, probably cut off."),
        (_submit({}), "claims must be a list."),
        (_submit({"path_exists": True, "claims": '[{"text": "a string, not a list"}]'}), "claims must be a list."),
        (_submit({"path_exists": True, "claims": [{"text": "no reproducer"}]}), "no claim had both text and a reproducer."),
    ],
)
def test_a_submit_that_cannot_be_read_gets_an_error_and_a_retry(tmp_path: Path, bad: ChatResponse, problem: str):
    model = Seq(bad, _submit(GOOD))
    result = _agent(tmp_path, model)
    assert result.submitted and len(result.claims) == 1
    assert model.sent[1]["messages"][-1] == {"role": "user", "content": BAD_SUBMIT.format(problem=problem)}
    assert model.sent[1]["tools"] == ["submit_claims"]


def test_two_unreadable_submits_are_no_submission_rather_than_an_empty_one(tmp_path: Path):
    model = Seq(_submit({}, invalid=True), _submit({}, invalid=True))
    result = _agent(tmp_path, model)
    assert (result.submitted, result.claims, result.path_exists, result.rounds) == (False, [], None, 2)


def test_the_retry_comes_even_on_the_last_round(tmp_path: Path):
    model = Seq(_submit({}, invalid=True), _submit(GOOD))
    assert _agent(tmp_path, model, max_rounds=1).submitted


@pytest.mark.parametrize(
    "arguments, path_exists",
    [({"path_exists": False}, False), ({"path_exists": False, "claims": []}, False), ({"path_exists": True, "claims": []}, True)],
)
def test_an_empty_answer_on_purpose_is_taken_at_its_word(tmp_path: Path, arguments: dict, path_exists: bool):
    model = Seq(_submit(arguments))
    result = _agent(tmp_path, model)
    assert (result.submitted, result.claims, result.path_exists, len(model.sent)) == (True, [], path_exists, 1)


def test_a_tool_call_with_bad_arguments_answers_with_an_error_and_goes_on(tmp_path: Path):
    bad = ChatResponse("", [ToolCall("r", "read_file", {}, invalid=True)], 100, 20)
    model = Seq(bad, _submit(GOOD))
    assert _agent(tmp_path, model).submitted
    assert model.sent[1]["messages"][-1] == {"role": "tool", "tool_call_id": "r", "content": "error: the arguments were not valid JSON"}


def test_the_temperature_is_passed_only_when_set(tmp_path: Path):
    plain, warm = Seq(_submit(GOOD)), Seq(_submit(GOOD))
    _agent(tmp_path, plain)
    _agent(tmp_path, warm, temperature=0.8)
    assert plain.sent[0]["extra"] == {} and warm.sent[0]["extra"] == {"temperature": 0.8}


class _Client:
    """The openai package, as far as the model uses it."""

    def __init__(self, replies: list) -> None:
        self.sent: list[dict] = []
        self.replies = replies
        self.chat = types.SimpleNamespace(completions=self)
        self.embeddings = self

    def create(self, **kwargs):
        self.sent.append(kwargs)
        return self.replies.pop(0)


def _reply(*arguments: str):
    calls = [types.SimpleNamespace(id=str(n), function=types.SimpleNamespace(name="submit_claims", arguments=raw))
             for n, raw in enumerate(arguments)]
    message = types.SimpleNamespace(content="", tool_calls=calls)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message, finish_reason="tool_calls")],
                                 usage=types.SimpleNamespace(prompt_tokens=3, completion_tokens=1))


def _model(tmp_path: Path, monkeypatch, config: str, replies: list):
    monkeypatch.setenv("AH_TEST_CHAT", "chat-secret-1")
    client = _Client(replies)
    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=lambda base_url, api_key: client))
    from alien_hunt.llm import OpenAIModel

    return OpenAIModel(load_config(write(tmp_path, config + BASE))), client


def test_arguments_that_are_not_a_json_object_are_marked(tmp_path: Path, monkeypatch):
    model, _client = _model(tmp_path, monkeypatch, "", [_reply('{"claims": [{"te', "[1, 2]", '{"claims": []}', "")])
    calls = model.chat(messages=[], tools=None, max_tokens=5).tool_calls
    assert [call.invalid for call in calls] == [True, True, False, False]
    assert calls[0].arguments == {}


def test_a_reply_with_no_choices_is_a_model_error(tmp_path: Path, monkeypatch):
    empty = types.SimpleNamespace(choices=[], usage=None)
    model, _client = _model(tmp_path, monkeypatch, "", [empty])
    with pytest.raises(LLMError, match="no choices"):
        model.chat(messages=[], tools=None, max_tokens=5)


def test_a_turn_can_override_the_temperature(tmp_path: Path, monkeypatch):
    model, client = _model(tmp_path, monkeypatch, "temperature = 0.1\n", [_reply(), _reply()])
    model.chat(messages=[], tools=None, max_tokens=5)
    model.chat(messages=[], tools=None, max_tokens=5, temperature=0.8)
    assert [sent["temperature"] for sent in client.sent] == [0.1, 0.8]
    assert all("seed" not in sent for sent in client.sent)


@pytest.mark.parametrize("config", ["temperature = false\n", "temperature = false\nplain_temperature = 0.5\n"])
def test_temperature_false_is_honoured_even_for_a_plain_review(tmp_path: Path, monkeypatch, config: str):
    from alien_hunt.agent import PaidModel

    model, client = _model(tmp_path, monkeypatch, config, [_reply(), _reply()])
    paid = PaidModel(model, Budget(limit_usd=100), Prices(1, 1, 1))
    model.chat(messages=[], tools=None, max_tokens=5, temperature=0.8)
    paid.chat(stage="plain", messages=[], tools=None, max_tokens=5, temperature=0.8)
    assert all("temperature" not in sent for sent in client.sent)


def test_plain_temperature_is_read_and_checked(tmp_path: Path):
    assert load_config(write(tmp_path, BASE)).plain_temperature == 0.8
    assert load_config(write(tmp_path, "plain_temperature = 0.3\n" + BASE)).plain_temperature == 0.3
    assert load_config(write(tmp_path, "plain_temperature = false\n" + BASE)).plain_temperature is None
    for bad in ("true", "3", '"warm"'):
        with pytest.raises(ConfigError, match="plain_temperature"):
            load_config(write(tmp_path, f"plain_temperature = {bad}\n" + BASE))


def test_the_cli_passes_it_and_an_interrupt_is_a_status(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AH_TEST_CHAT", "chat-secret-1")
    seen: dict = {}

    def stop(checkout, **kwargs):
        seen.update(kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "execute", stop)
    monkeypatch.setattr(cli, "OpenAIModel", lambda config: object())
    config = write(tmp_path, "plain_temperature = 0.3\n" + BASE)
    assert cli.main(["run", "--local", str(FIXTURE), "--config", str(config), "--out", str(tmp_path / "out")]) == 130
    assert seen["plain_temperature"] == 0.3


class Flaky(ScriptedModel):
    """The scripted model, with `trouble(blob, count)` able to raise before a reply. `count` numbers that kind of turn."""

    def __init__(self, trouble) -> None:
        super().__init__()
        self.trouble = trouble
        self.counts: dict[str, int] = {}

    def chat(self, *, messages, tools, max_tokens, **extra) -> ChatResponse:
        blob = "\n".join(message.get("content") or "" for message in messages)
        for stage in ("plain", "hunt", "coherence"):
            if f"STAGE: {stage}" in blob:
                self.counts[stage] = self.counts.get(stage, 0) + 1
                self.trouble(stage, self.counts[stage])
        return super().chat(messages=messages, tools=tools, max_tokens=max_tokens)


def _run(tmp_path: Path, model, **options) -> Path:
    settings = dict(model=model, budget=Budget(limit_usd=5), prices=Prices(1, 1, 1), out_dir=tmp_path, sample_limit=1000,
                    confirm_mode="local", scanners=False, target="fixture", run_id="t")
    return execute(FIXTURE, **{**settings, **options})


def _fail(wanted: str, *turns: int, error=LLMError("endpoint says no")):
    def trouble(stage: str, count: int) -> None:
        if stage == wanted and (not turns or count in turns):
            raise error

    return trouble


def _confirmed(tmp_path: Path) -> list[dict]:
    rows = json.loads((tmp_path / "05-confirmation.json").read_text(encoding="utf-8"))
    return [row for row in rows if row["confirmed"]]


def test_a_failed_plain_pass_is_skipped_and_named(tmp_path: Path):
    text = _run(tmp_path, Flaky(_fail("plain", 2))).read_text(encoding="utf-8")
    assert "Skipped after a model error: plain pass 2" in text
    assert "AH-1: deserialisation (plain)" in text and "AH-2: broken-length (directed)" in text


def test_a_failed_hunt_is_skipped_and_named_without_naming_a_function(tmp_path: Path):
    text = _run(tmp_path, Flaky(_fail("hunt", 1))).read_text(encoding="utf-8")
    hunts = json.loads((tmp_path / "04-hunts.json").read_text(encoding="utf-8"))
    failed = [row for row in hunts if row["error"]]
    assert [row["error"] for row in failed] == ["endpoint says no"]
    assert f"Skipped after a model error: hunt {failed[0]['id']}" in text
    assert failed[0]["incoherent"] is None
    assert "AH-2: broken-length (directed)" in text
    assert "allocate" not in text and "load_config" not in text


def test_failures_that_are_not_in_a_row_do_not_add_up(tmp_path: Path):
    def trouble(stage: str, count: int) -> None:
        if stage == "hunt" and count % 2:
            raise LLMError("every other hunt")

    assert "Skipped after a model error: hunt" in _run(tmp_path, Flaky(trouble)).read_text(encoding="utf-8")


def test_three_in_a_row_end_the_search_and_what_was_collected_is_confirmed(tmp_path: Path):
    model = Flaky(_fail("hunt"))
    with pytest.raises(LLMError, match="endpoint says no"):
        _run(tmp_path, model)
    assert model.counts["hunt"] == 3
    text = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "## Error" in text and "AH-1: deserialisation (plain)" in text
    assert len(_confirmed(tmp_path)) == 3


def test_all_three_plain_passes_failing_ends_the_search(tmp_path: Path):
    model = Flaky(_fail("plain"))
    with pytest.raises(LLMError):
        _run(tmp_path, model)
    assert model.counts == {"plain": 3}
    assert "Skipped after a model error: plain pass 1, plain pass 2, plain pass 3" in (tmp_path / "REPORT.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "stage, error, raised",
    [
        ("coherence", LLMError("endpoint says no"), LLMError),
        ("coherence", RuntimeError("a bug of ours"), RuntimeError),
        ("hunt", KeyboardInterrupt(), KeyboardInterrupt),
    ],
)
def test_any_exit_still_confirms_and_reports(tmp_path: Path, stage: str, error: BaseException, raised: type):
    with pytest.raises(raised):
        _run(tmp_path, Flaky(_fail(stage, 1, error=error)))
    assert len(_confirmed(tmp_path)) == 3
    assert "AH-1: deserialisation (plain)" in (tmp_path / "REPORT.md").read_text(encoding="utf-8")


def test_an_interrupt_during_confirmation_still_reports_what_was_confirmed(tmp_path: Path, monkeypatch):
    real = pipeline.confirm_local
    done: list[int] = []

    def confirm_then_stop(claim, checkout, slot):
        if done:
            raise KeyboardInterrupt
        done.append(1)
        return real(claim, checkout, slot)

    monkeypatch.setattr(pipeline, "confirm_local", confirm_then_stop)
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, ScriptedModel())
    assert len(_confirmed(tmp_path)) == 1 and (tmp_path / "REPORT.md").is_file()


def test_a_budget_stop_keeps_the_passes_already_paid_for(tmp_path: Path):
    budget = Budget(limit_usd=0.00037)                     # 150 tokens at 1 USD per million, 2 turns: 0.0003, over 80%
    text = _run(tmp_path, ScriptedModel(), budget=budget).read_text(encoding="utf-8")
    assert "Stopped early: yes" in text and "AH-1: deserialisation (plain)" in text


def test_claims_are_logged_as_they_arrive_with_their_reproducers(tmp_path: Path):
    arrived: list[int] = []

    def trouble(stage: str, count: int) -> None:
        path = tmp_path / "local" / "claims.jsonl"
        arrived.append(len(path.read_text(encoding="utf-8").splitlines()) if path.exists() else 0)
        if stage == "plain" and count == 3:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, Flaky(trouble))
    assert arrived == [0, 1, 2]
    rows = [json.loads(line) for line in (tmp_path / "local" / "claims.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("samplelib" in row["reproducer"] and row["origin"] == "plain" for row in rows)


def test_a_hunts_claims_are_logged_too(tmp_path: Path):
    _run(tmp_path, ScriptedModel())
    rows = [json.loads(line) for line in (tmp_path / "local" / "claims.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {row["origin"] for row in rows} == {"plain", "hunt"}


def _podman_run(tmp_path: Path, monkeypatch) -> list[DepsStatus]:
    seen: list[DepsStatus] = []

    def confirm(claim, checkout, slot, *, image, deps):
        seen.append(deps)
        return Confirmation(True, "stub", 0, "", [])

    monkeypatch.setattr(pipeline, "confirm_podman", confirm)
    _run(tmp_path, ScriptedModel(), confirm_mode="podman")
    return seen


def test_wheels_that_cannot_be_prepared_do_not_void_the_claims(tmp_path: Path, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("malformed setup.cfg")

    monkeypatch.setattr(pipeline, "prepare_wheels", broken)
    seen = _podman_run(tmp_path, monkeypatch)
    assert seen and all(deps.why == "could not prepare dependencies: malformed setup.cfg" and not deps.ok for deps in seen)
    assert _confirmed(tmp_path)


def test_a_failed_install_reaches_the_reproducers_as_a_reason(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pipeline, "prepare_wheels", lambda *a, **k: DepsStatus(True, "wheels downloaded", target=tmp_path))
    monkeypatch.setattr(pipeline, "install_wheels", lambda *a, **k: "wheel install failed: boom")
    seen = _podman_run(tmp_path, monkeypatch)
    assert seen and all(deps.why == "wheel install failed: boom" and not deps.ok for deps in seen)


def test_no_claims_fetch_no_wheels(tmp_path: Path, monkeypatch):
    fetched: list[int] = []

    def prepare(*args, **kwargs):
        fetched.append(1)
        return DepsStatus(True, "no third-party dependencies")

    monkeypatch.setattr(pipeline, "prepare_wheels", prepare)
    _run(tmp_path, ScriptedModel(), budget=Budget(limit_usd=0), confirm_mode="podman")
    assert fetched == []
    assert json.loads((tmp_path / "05-confirmation.json").read_text(encoding="utf-8")) == []


class _Rater:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def chat(self, *, stage, messages, tools, max_tokens) -> ChatResponse:
        self.prompts.append(messages[0]["content"])
        return ChatResponse(json.dumps({"ratings": []}), [], 10, 10)


def _candidate(source: Atom, other: Atom) -> Candidate:
    return Candidate("c1", source, Atom("mechanism", "m1", "a mechanism"), other)


def test_coherence_is_rated_with_the_code_around_the_atoms():
    sources, sinks, invariants, _mechanisms = extract_atoms(FIXTURE)
    source = next(item for item in sources if item.function == "load_config")
    other = next(item for item in invariants if item.function == "allocate")
    model = _Rater()
    candidate = _candidate(source, other)
    rate_coherence(model, FIXTURE, [candidate], batch_size=10)
    assert f"Code near the source ({source.file}):" in model.prompts[0]
    assert f"{source.line}|def load_config(blob: bytes):" in model.prompts[0]
    assert "Code near the sink or invariant" in model.prompts[0]
    assert "def load_config" not in candidate.triple_text()        # the embedding text stays the atoms' wording


def test_an_atom_with_no_place_in_the_code_adds_no_excerpt():
    atom = Atom("source", "s", "somewhere", file="missing.py", line=3)
    model = _Rater()
    rate_coherence(model, FIXTURE, [_candidate(atom, Atom("sink", "k", "nowhere"))], batch_size=10)
    assert "Code near" not in model.prompts[0]


def test_atoms_know_their_line_and_links_are_not_harvested(tmp_path: Path):
    root = _repo(tmp_path)
    (root / "b.py").write_text("\n\ndef f(x):\n    return eval(x)\n", encoding="utf-8")
    (root / "gone.py").symlink_to(tmp_path / "nothing")
    (root / "link.py").symlink_to(root / "b.py")
    sources, sinks, _invariants, _mechanisms = extract_atoms(root)
    assert [(item.file, item.line) for item in sources] == [("b.py", 3)]
    assert [(item.file, item.line) for item in sinks] == [("b.py", 4)]


@pytest.mark.parametrize("entry", ["/etc/hosts:f", "../outside.py:f", "bad\0path:f", ".git/config:f"])
def test_a_path_outside_the_checkout_caps_the_rating(tmp_path: Path, entry: str):
    root = _repo(tmp_path)
    (tmp_path / "outside.py").write_text("", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("", encoding="utf-8")
    candidate = _candidate(Atom("source", "s", "s"), Atom("sink", "k", "k"))
    candidate.coherence, candidate.path = 5.0, [entry]
    _cap_coherence(candidate, root)
    assert candidate.coherence == 2.0


def test_a_path_inside_the_checkout_keeps_the_rating(tmp_path: Path):
    candidate = _candidate(Atom("source", "s", "s"), Atom("sink", "k", "k"))
    candidate.coherence, candidate.path = 5.0, ["a.py:f"]
    _cap_coherence(candidate, _repo(tmp_path))
    assert candidate.coherence == 5.0


def test_the_plain_reviews_have_their_own_temperature_and_nothing_else_does(tmp_path: Path):
    temperatures: dict[str, set] = {}

    class Recording(ScriptedModel):
        def chat(self, *, messages, tools, max_tokens, **extra) -> ChatResponse:
            blob = "\n".join(message.get("content") or "" for message in messages)
            stage = next(word for word in ("plain", "invariants", "mechanisms", "coherence", "hunt") if f"STAGE: {word}" in blob)
            temperatures.setdefault(stage, set()).add(extra.get("temperature"))
            return super().chat(messages=messages, tools=tools, max_tokens=max_tokens)

    _run(tmp_path, Recording(), plain_temperature=0.8)
    assert temperatures.pop("plain") == {0.8}
    assert temperatures and all(values == {None} for values in temperatures.values())
