"""Tool paths stay inside the checkout."""

from pathlib import Path

import pytest

from alien_hunt.agent import SandboxError, list_dir, read_file, resolve_inside, run_agent
from alien_hunt.agent import PaidModel
from alien_hunt.budget import Budget
from alien_hunt.config import Prices
from alien_hunt.types import ChatResponse, ToolCall


def test_read_rejects_parent_escape(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("nope", encoding="utf-8")
    with pytest.raises(SandboxError):
        read_file(root, "../secret.txt")


def test_read_rejects_symlink_escape(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (root / "link.txt").symlink_to(outside)
    with pytest.raises(SandboxError):
        read_file(root, "link.txt")


def test_read_inside_returns_numbered_lines(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("alpha\nbeta\n", encoding="utf-8")
    text = read_file(root, "a.py", line_cap=1)
    assert text == "1|alpha"
    assert "a.py" in list_dir(root, ".")


def test_resolve_rejects_git(tmp_path: Path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    with pytest.raises(SandboxError):
        resolve_inside(root, ".git/config")


class _LoopModel:
    def __init__(self) -> None:
        self.calls = 0

    def chat(self, *, messages, tools, max_tokens):
        self.calls += 1
        return ChatResponse(
            text="",
            tool_calls=[ToolCall(id=str(self.calls), name="list_dir", arguments={"path": "."})],
            prompt_tokens=600,
            completion_tokens=600,
        )

    def embed(self, texts):
        raise AssertionError("embed was not expected")


def test_token_cap_stops_the_hunt(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    inner = _LoopModel()
    paid = PaidModel(inner, Budget(limit_usd=100), Prices(0.01, 0.01, 0.01))
    result = run_agent(
        paid,
        root,
        stage="hunt",
        system="review",
        user="STAGE: hunt",
        origin="hunt",
        max_rounds=6,
        max_claims=10,
        token_cap=1000,
    )
    assert inner.calls == 1
    assert result.rounds == 1
    assert result.tokens >= 1000
