"""Pipeline split with a scripted model, plus an immediate budget stop."""

import json
import re
from pathlib import Path

from alien_hunt.budget import Budget
from alien_hunt.config import Prices
from alien_hunt.pipeline import execute
from alien_hunt.types import ChatResponse, EmbedResponse, ToolCall

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "samplelib"

PICKLE = """import pickle
import sys
from samplelib import load_config

blob = pickle.dumps({"k": 1})
got = load_config(blob)
if got == {"k": 1}:
    sys.exit(0)
sys.exit(1)
"""

ALLOC = """import sys
from samplelib import allocate

got = allocate(0)
if len(got) != 0:
    sys.exit(0)
sys.exit(1)
"""


class ScriptedModel:
    """Returns the planted pickle claim to a plain review, and the length claim only to that hunt."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def chat(self, *, messages, tools, max_tokens) -> ChatResponse:
        blob = "\n".join(message.get("content") or "" for message in messages)
        self.prompts.append(blob)
        if "STAGE: plain" in blob:
            return self._submit(
                {
                    "path_exists": True,
                    "claims": [
                        {
                            "text": "pickle.loads accepts a caller blob in load_config",
                            "class": "deserialisation",
                            "files": ["samplelib/__init__.py"],
                            "functions": ["samplelib.load_config"],
                            "reproducer": PICKLE,
                        }
                    ],
                }
            )
        if "STAGE: invariants" in blob:
            ids = re.findall(r"inv-\S+", blob)
            return ChatResponse(json.dumps({"keep": ids}), [], 100, 50)
        if "STAGE: mechanisms" in blob:
            pairs = re.findall(r"^Pair (p\d+)$", blob, re.M)
            return ChatResponse(json.dumps({"picks": [{"pair": pair, "mechanisms": ["m00", "m01", "m02"]} for pair in pairs]}), [], 100, 50)
        if "STAGE: coherence" in blob:
            return ChatResponse(json.dumps({"ratings": self._ratings(blob)}), [], 100, 50)
        if "STAGE: hunt" in blob:
            phrase = "must be >= 0" in blob or "result length equals" in blob
            if phrase and "mechanism_id=m01\n" in blob:
                return self._submit({"path_exists": False, "claims": []})
            if phrase:
                return self._submit(
                    {
                        "path_exists": True,
                        "claims": [
                            {
                                "text": "allocate(0) returns a list whose length is not 0",
                                "class": "broken-length",
                                "files": ["samplelib/__init__.py"],
                                "functions": ["samplelib.allocate"],
                                "reproducer": ALLOC,
                            }
                        ],
                    }
                )
            return self._submit({"path_exists": True, "claims": []})
        raise AssertionError("unexpected prompt")

    def embed(self, texts: list[str]) -> EmbedResponse:
        vectors = []
        for text in texts:
            if "must be >= 0" in text or "result length equals" in text:
                vectors.append([1.0, 0.0])
            else:
                vectors.append([0.0, 1.0])
        return EmbedResponse(vectors, prompt_tokens=10 * max(1, len(texts)))

    def _ratings(self, blob: str) -> list[dict]:
        ratings = []
        for chunk in blob.split("Candidate ")[1:]:
            identifier = chunk.split()[0]
            if "must be >= 0" in chunk or "result length equals" in chunk:
                ratings.append(
                    {
                        "id": identifier,
                        "score": 5,
                        "path": ["samplelib/__init__.py:allocate"],
                    }
                )
            elif "pickle" in chunk or "load_config" in chunk:
                ratings.append(
                    {
                        "id": identifier,
                        "score": 4,
                        "path": ["samplelib/__init__.py:load_config"],
                    }
                )
            else:
                ratings.append({"id": identifier, "score": 1, "path": ["missing.py:no_such"]})
        return ratings

    def _submit(self, payload: dict) -> ChatResponse:
        return ChatResponse(
            "",
            [ToolCall(id="call-1", name="submit_claims", arguments=payload)],
            100,
            50,
        )


def test_pipeline_splits_plain_and_directed_findings(tmp_path: Path):
    model = ScriptedModel()
    report = execute(
        FIXTURE,
        model=model,
        budget=Budget(limit_usd=5),
        prices=Prices(1, 1, 1),
        out_dir=tmp_path,
        sample_limit=1000,
        confirm_mode="local",
        scanners=False,
        target="fixture",
        commit="",
        run_id="fixture",
    )
    text = report.read_text(encoding="utf-8")
    assert "Confirmed claims: 1" in text
    assert "AH-1: deserialisation (plain)" in text
    assert "AH-2: broken-length (directed)" in text
    assert "Stopped early: no" in text
    assert "load_config" not in text
    assert "allocate" not in text
    assert "pickle" not in text
    assert "Incoherent among them:" in text
    incoherent_line = next(line for line in text.splitlines() if line.startswith("- Incoherent among them:"))
    assert int(incoherent_line.rsplit(":", 1)[1]) >= 1
    detail = json.loads((tmp_path / "local" / "detail.json").read_text(encoding="utf-8"))
    functions = {tuple(item["functions"]) for item in detail["confirmed"]}
    assert ("samplelib.load_config",) in functions
    assert ("samplelib.allocate",) in functions
    assert sum(1 for prompt in model.prompts if "STAGE: plain" in prompt) == 3
    assert (tmp_path / "05-confirmation.json").is_file()
    habits = json.loads((tmp_path / "01-habits.json").read_text(encoding="utf-8"))
    assert "reproducer" not in json.dumps(habits)


def test_zero_budget_stops_before_any_model_call(tmp_path: Path):
    model = ScriptedModel()
    report = execute(
        FIXTURE,
        model=model,
        budget=Budget(limit_usd=0),
        prices=Prices(1, 1, 1),
        out_dir=tmp_path,
        confirm_mode="local",
        scanners=False,
        run_id="empty",
    )
    text = report.read_text(encoding="utf-8")
    assert "Stopped early: yes" in text
    assert "Confirmed claims: 0" in text
    assert model.prompts == []
