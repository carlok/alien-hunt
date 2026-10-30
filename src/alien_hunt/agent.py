"""Read-only tool loop over a checkout: list, read, and search."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from alien_hunt.budget import Budget, BudgetStop
from alien_hunt.config import Prices
from alien_hunt.types import ChatResponse, Claim, ToolCall

_MAX_OUTPUT = 8000
_SEARCH_HITS = 50
_LIST_LIMIT = 200


class SandboxError(Exception):
    """A tool path escaped the checkout."""


def resolve_inside(root: Path, user_path: str) -> Path:
    """Resolve `user_path` and require it to stay inside `root`."""

    base = root.resolve()
    raw = Path(user_path)
    candidate = raw if raw.is_absolute() else base / raw
    resolved = candidate.resolve(strict=False)
    if resolved != base and base not in resolved.parents:
        raise SandboxError("path is outside the checkout")
    try:
        relative = resolved.relative_to(base)
    except ValueError as exc:
        raise SandboxError("path is outside the checkout") from exc
    if relative.parts and relative.parts[0] == ".git":
        raise SandboxError("refusing to read .git")
    return resolved


def list_dir(root: Path, user_path: str) -> str:
    """List names inside the checkout."""

    target = resolve_inside(root, user_path or ".")
    if not target.is_dir():
        raise SandboxError("not a directory")
    names = []
    for child in sorted(target.iterdir(), key=lambda item: item.name):
        if child.name == ".git":
            continue
        suffix = "/" if child.is_dir() else ""
        names.append(child.name + suffix)
        if len(names) >= _LIST_LIMIT:
            break
    return "\n".join(names)


def read_file(root: Path, user_path: str, start_line: int = 1, line_cap: int = 200) -> str:
    """Read a window of a text file inside the checkout."""

    target = resolve_inside(root, user_path)
    if not target.is_file():
        raise SandboxError("not a file")
    start = max(1, int(start_line))
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    window = lines[start - 1 : start - 1 + line_cap]
    numbered = [f"{start + offset}|{line}" for offset, line in enumerate(window)]
    return "\n".join(numbered)


def search(root: Path, pattern: str, glob: str = "*.py") -> str:
    """Search text files inside the checkout. At most 50 hits."""

    if not pattern or len(pattern) > 200:
        raise SandboxError("pattern must be 1 to 200 characters")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise SandboxError(f"invalid pattern: {exc}") from exc
    base = root.resolve()
    hits: list[str] = []
    for path in sorted(base.rglob(glob)):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        if path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if compiled.search(line):
                relative = path.relative_to(base)
                hits.append(f"{relative}:{number}:{line[:200]}")
                if len(hits) >= _SEARCH_HITS:
                    return "\n".join(hits)
    return "\n".join(hits)


TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and directories inside the checkout.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read up to 200 lines of a text file inside the checkout.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search files inside the checkout. Returns at most 50 hits.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "glob": {"type": "string"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_claims",
            "description": "Submit up to 10 claims and stop. Each claim needs a Python reproducer. An empty list is a valid answer.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path_exists": {"type": "boolean"},
                    "claims": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"},
                                "class": {"type": "string"},
                                "files": {"type": "array", "items": {"type": "string"}},
                                "functions": {"type": "array", "items": {"type": "string"}},
                                "reproducer": {"type": "string"},
                            },
                            "required": ["text", "class", "files", "functions", "reproducer"],
                        },
                    },
                },
                "required": ["path_exists", "claims"],
            },
        },
    },
]
SUBMIT_ONLY = [tool for tool in TOOLS if tool["function"]["name"] == "submit_claims"]
LAST_TURN = (
    "This is your last turn. Call submit_claims now with what you have found and can support from the files "
    "(an empty claims list is fine)."
)
CUT_SHORT = (
    "Your last reply was cut at the length limit, so it was not received. Call submit_claims again with at most "
    "3 claims and short reproducers."
)


def _run_tool(root: Path, call: ToolCall, line_cap: int) -> str:
    try:
        name = call.name
        args = call.arguments
        if name == "list_dir":
            return list_dir(root, str(args.get("path", ".")))
        if name == "read_file":
            return read_file(
                root,
                str(args.get("path", "")),
                int(args.get("start_line", 1) or 1),
                line_cap,
            )
        if name == "search":
            return search(root, str(args.get("pattern", "")), str(args.get("glob", "*.py") or "*.py"))
        return f"unknown tool {name}"
    except (SandboxError, OSError, ValueError) as exc:
        return f"error: {exc}"


def parse_claims(payload: dict, *, origin: str, candidate_id: str | None, max_claims: int) -> list[Claim]:
    """Turn a submit_claims payload into claims. Extra claims are dropped."""

    raw_claims = payload.get("claims") or []
    if not isinstance(raw_claims, list):
        return []
    claims: list[Claim] = []
    for item in raw_claims[:max_claims]:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        reproducer = str(item.get("reproducer") or "")
        if not text or not reproducer.strip():
            continue
        files = item.get("files") or []
        functions = item.get("functions") or []
        claims.append(
            Claim(
                text=text,
                class_label=str(item.get("class") or item.get("class_label") or "unspecified"),
                files=[str(entry) for entry in files] if isinstance(files, list) else [],
                functions=[str(entry) for entry in functions] if isinstance(functions, list) else [],
                reproducer=reproducer,
                origin=origin,
                candidate_id=candidate_id,
            )
        )
    return claims


@dataclass
class AgentResult:
    """Claims submitted by one review, plus the model's path judgement."""

    claims: list[Claim] = field(default_factory=list)
    path_exists: bool | None = None
    rounds: int = 0
    tokens: int = 0
    submitted: bool = False


class PaidModel:
    """Charges the budget for an inner chat/embed client and stops at 80%."""

    def __init__(self, inner, budget: Budget, prices: Prices) -> None:
        self.inner = inner
        self.budget = budget
        self.prices = prices

    def chat(self, *, stage: str, messages: list, tools: list | None, max_tokens: int) -> ChatResponse:
        if self.budget.should_stop():
            raise BudgetStop(stage)
        response = self.inner.chat(messages=messages, tools=tools, max_tokens=max_tokens)
        self.budget.charge_tokens(
            stage,
            response.prompt_tokens,
            response.completion_tokens,
            self.prices,
            estimated=response.estimated,
        )
        return response

    def embed(self, texts: list[str], *, stage: str):
        if self.budget.should_stop():
            raise BudgetStop(stage)
        response = self.inner.embed(texts)
        self.budget.charge_tokens(
            stage,
            response.prompt_tokens,
            0,
            self.prices,
            embedding=True,
            estimated=response.estimated,
        )
        return response


def run_agent(
    model: PaidModel,
    root: Path,
    *,
    stage: str,
    system: str,
    user: str,
    origin: str,
    max_rounds: int,
    max_claims: int,
    token_cap: int | None,
    candidate_id: str | None = None,
    line_cap: int = 200,
    max_output: int = 4000,
) -> AgentResult:
    """Run a review until it submits claims, runs out of rounds, or hits the token cap.

    The last round (by count, or once 75% of the token cap is used) offers submit_claims alone and says so, so a
    review that explored until the end still answers. A reply cut at `max_output` is not trusted (its tool call may
    be truncated JSON): the model is asked once more for fewer, shorter claims, with submit_claims alone."""

    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    result = AgentResult()
    force, allowed, retried = False, max_rounds, False
    while result.rounds < allowed:
        if token_cap is not None and result.tokens >= token_cap and not retried:
            break
        last = force or result.rounds == allowed - 1 or (token_cap is not None and result.tokens >= 0.75 * token_cap)
        if last and not force:
            messages.append({"role": "user", "content": LAST_TURN})
            force = True
        response = model.chat(
            stage=stage, messages=messages, tools=SUBMIT_ONLY if last else TOOLS, max_tokens=max_output
        )
        result.rounds += 1
        result.tokens += response.prompt_tokens + response.completion_tokens
        if response.finish_reason == "length":
            if retried:
                break
            retried = True                        # one more turn, even past the rounds or the cap: a cut submit is the costliest loss
            allowed = max(allowed, result.rounds + 1)
            messages.append({"role": "user", "content": CUT_SHORT})
            force = True
            continue
        submits = [call for call in response.tool_calls if call.name == "submit_claims"]
        others = [call for call in response.tool_calls if call.name != "submit_claims"]
        if submits:
            payload = submits[0].arguments
            result.submitted = True
            if "path_exists" in payload:
                result.path_exists = bool(payload.get("path_exists"))
            result.claims = parse_claims(
                payload,
                origin=origin,
                candidate_id=candidate_id,
                max_claims=max_claims,
            )
            return result
        if not others:
            if last:
                break
            if response.text:                     # a plain-text answer: ask for the tool call once, as the last turn
                messages.append({"role": "assistant", "content": response.text})
            messages.append({"role": "user", "content": LAST_TURN})
            force = True
            continue
        messages.append(
            {
                "role": "assistant",
                "content": response.text or None,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                    }
                    for call in others
                ],
            }
        )
        for call in others:
            body = _run_tool(root, call, line_cap)[:_MAX_OUTPUT]
            messages.append({"role": "tool", "tool_call_id": call.id, "content": body})
        if token_cap is not None and result.tokens >= token_cap:
            break
    return result
