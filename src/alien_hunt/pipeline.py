"""Wire the stages. Each stage writes JSON under the run directory."""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.agent import PaidModel
from alien_hunt.atoms import extract_atoms, filter_invariants
from alien_hunt.budget import Budget, BudgetStop
from alien_hunt.config import Prices
from alien_hunt.confirm import (
    DepsStatus,
    confirm_local,
    confirm_podman,
    install_wheels,
    prepare_wheels,
    python_tag_for,
    reproducer_imports,
)
from alien_hunt.habits import habit_texts, package_names, plain_reviews
from alien_hunt.hunt import directed_hunt
from alien_hunt.llm import LLMError
from alien_hunt.redact import redact
from alien_hunt.report import overlap_functions, public_rows, render_report, unique_confirmed
from alien_hunt.score import apply_scores, colocated_pairs, unavailability
from alien_hunt.types import Candidate, Claim, Confirmation, KnownAdvisory

log = logging.getLogger("alien_hunt")

_PLAIN_SYSTEM_NOTE = "STAGE: invariants"


@dataclass
class RunState:
    """Mutable artifacts so a budget stop still has a report."""

    claims: list[Claim] = field(default_factory=list)
    habit_strings: list[str] = field(default_factory=list)
    sources: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    invariants: list = field(default_factory=list)
    mechanisms: list = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    ranked_07: list[Candidate] = field(default_factory=list)
    ranked_04: list[Candidate] = field(default_factory=list)
    confirmations: list[tuple[Claim, Confirmation]] = field(default_factory=list)
    stopped: bool = False
    error: str | None = None
    confirmed_vectors: list | None = None  # embeddings of the confirmed claims, in order, to merge duplicates
    hunted: list[Candidate] = field(default_factory=list)  # the candidates actually hunted (at or above the floor)
    fallback: int = 0  # hunted below the floor, because none reached it
    above_floor: int | None = None


def dump_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_model_json(text: str) -> dict:
    """Parse a JSON object, including one wrapped in a fence."""

    raw = text.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        raw = raw[start : end + 1]
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("expected a JSON object")
    return payload


def _cap_coherence(candidate: Candidate, root: Path) -> None:
    score = 1.0 if candidate.coherence is None else float(candidate.coherence)
    score = min(5.0, max(1.0, score))
    files_ok = True
    candidate.named_functions = []
    for entry in candidate.path:
        file_part, _, func = entry.partition(":")
        if func:
            candidate.named_functions.append(func)
        if file_part and not (root / file_part).is_file():
            files_ok = False
    if not candidate.path or not files_ok:
        score = min(score, 2.0)
    candidate.coherence = score


def rate_coherence(
    model: PaidModel,
    root: Path,
    candidates: list[Candidate],
    *,
    batch_size: int,
    max_output: int = 4000,
) -> None:
    """Ask the model whether each triple can occur here. A missing path caps the score at 2.

    A batch whose reply does not parse, or was cut at `max_output`, is asked again in two halves, down to single
    candidates; a candidate never rated keeps the floor of 1 and `rated` False, so the report can say how many were."""

    for offset in range(0, len(candidates), batch_size):
        _rate_batch(model, root, candidates[offset : offset + batch_size], max_output)


def _rate_batch(model: PaidModel, root: Path, batch: list[Candidate], max_output: int) -> None:
    blocks = [f"Candidate {item.id}\n{item.triple_text()}" for item in batch]
    user = (
        "STAGE: coherence\n"
        "Rate each candidate from 1 to 5 for whether it can occur on a real call path "
        "in this repository. Name the path as file:function entries that exist in the tree.\n"
        'Reply with JSON only: {"ratings": [{"id": "c000", "score": 3, "path": ["pkg/mod.py:fn"]}]}\n\n'
        + "\n\n".join(blocks)
    )
    response = model.chat(
        stage="score",
        messages=[{"role": "user", "content": user}],
        tools=None,
        max_tokens=max_output,
    )
    try:
        payload = parse_model_json(response.text)
    except (json.JSONDecodeError, ValueError):
        payload = None
    if (payload is None or response.finish_reason == "length") and len(batch) > 1:
        half = len(batch) // 2
        log.info("coherence: a batch of %s did not parse; asking in halves", len(batch))
        _rate_batch(model, root, batch[:half], max_output)
        _rate_batch(model, root, batch[half:], max_output)
        return
    by_id = {item.get("id"): item for item in (payload or {}).get("ratings") or [] if isinstance(item, dict)}
    for candidate in batch:
        rating = by_id.get(candidate.id) or {}
        try:
            candidate.coherence = float(rating.get("score"))
            candidate.rated = True
        except (TypeError, ValueError):
            candidate.coherence = 1.0
        path = rating.get("path") or []
        if isinstance(path, str):
            path = [path]
        candidate.path = [str(entry) for entry in path]
        _cap_coherence(candidate, root)


def propose_candidates(
    model: PaidModel,
    pairs: list,
    mechanisms: list,
    *,
    per_pair: int = 3,
    explore: int = 1,
    seed: int = 0,
    batch_size: int = 8,
    max_output: int = 4000,
) -> list[Candidate]:
    """For each co-located pair, the model picks up to `per_pair` mechanisms (by id) that could apply on a real path from
    the source to the sink or invariant; `explore` more are drawn at random, so the pool keeps some unlikely ones for the
    unavailability score to find. A batch that does not parse gets all its mechanisms drawn with `seed`."""

    rng = random.Random(seed)
    by_id = {item.id: item for item in mechanisms}
    listing = "\n".join(f"{item.id} {item.text}" for item in mechanisms)
    out: list[Candidate] = []
    for offset in range(0, len(pairs), batch_size):
        batch = pairs[offset : offset + batch_size]
        blocks = [f"Pair p{offset + n:03d}\nsource: {s.text}\nsink or invariant: {o.text}" for n, (s, o) in enumerate(batch)]
        user = (
            "STAGE: mechanisms\n"
            f"For each pair, pick up to {per_pair} mechanism ids from the list that could apply on a real path from the "
            "source to the sink or invariant in this repository.\n"
            'Reply with JSON only: {"picks": [{"pair": "p000", "mechanisms": ["m03", "m17"]}]}\n\n'
            f"Mechanisms:\n{listing}\n\n" + "\n\n".join(blocks)
        )
        response = model.chat(stage="score", messages=[{"role": "user", "content": user}], tools=None, max_tokens=max_output)
        try:
            payload = parse_model_json(response.text)
        except (json.JSONDecodeError, ValueError):
            payload = {}
        picks = {item.get("pair"): item.get("mechanisms") for item in payload.get("picks") or [] if isinstance(item, dict)}
        for n, (source, other) in enumerate(batch):
            chosen = [by_id[m] for m in (picks.get(f"p{offset + n:03d}") or []) if isinstance(m, str) and m in by_id][:per_pair]
            if not chosen:
                chosen = rng.sample(mechanisms, min(per_pair, len(mechanisms)))
            rest = [item for item in mechanisms if item not in chosen]
            chosen += rng.sample(rest, min(explore, len(rest)))
            out.extend(Candidate(id="", source=source, mechanism=m, other=other) for m in chosen)
    for index, candidate in enumerate(out):
        candidate.id = f"c{index:03d}"
    return out


def _filter_invariants(model: PaidModel, invariants: list) -> list:
    if not invariants:
        return []
    listing = "\n".join(f"{item.id} {item.text}" for item in invariants)
    user = (
        f"{_PLAIN_SYSTEM_NOTE}\n"
        "Which of these sentences are promises the code could violate?\n"
        'Reply with JSON: {"keep": ["id"]}\n\n'
        + listing
    )
    response = model.chat(
        stage="atoms",
        messages=[{"role": "user", "content": user}],
        tools=None,
        max_tokens=800,
    )
    try:
        payload = parse_model_json(response.text)
    except (json.JSONDecodeError, ValueError):
        return invariants
    keep = payload.get("keep") or []
    if not isinstance(keep, list):
        return invariants
    return filter_invariants(invariants, {str(item) for item in keep})


def _embed_habits(model: PaidModel, texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    vectors: list[list[float]] = []
    for offset in range(0, len(texts), 64):
        response = model.embed(texts[offset : offset + 64], stage="plain")
        vectors.extend(response.vectors)
    return vectors


def _score_pool(
    model: PaidModel,
    candidates: list[Candidate],
    habits: list[list[float]],
) -> tuple[list[Candidate], list[Candidate]]:
    if not candidates:
        return [], []
    texts = [item.triple_text() for item in candidates]
    vectors: list[list[float]] = []
    for offset in range(0, len(texts), 64):
        response = model.embed(texts[offset : offset + 64], stage="score")
        vectors.extend(response.vectors)
    for candidate, vector in zip(candidates, vectors):
        candidate.unavailability = unavailability(vector, habits)
    return apply_scores(candidates)


def execute(
    checkout: Path,
    *,
    model,
    budget: Budget,
    prices: Prices,
    out_dir: Path,
    known: list[KnownAdvisory] | None = None,
    seed: int = 0,
    sample_limit: int = 80,
    review_rounds: int = 8,
    hunt_rounds: int = 6,
    hunt_token_cap: int = 8000,
    coherence_batch: int = 10,
    confirm_mode: str = "podman",
    container_image: str = "docker.io/library/python:3.10-slim",
    scanners: bool = True,
    commit_time: datetime | None = None,
    target: str = "",
    commit: str = "",
    secret: str | None = None,
    run_id: str = "run",
    max_output: int = 4000,
    min_coherence: float = 3.0,
    fallback_hunts: int = 3,
) -> Path:
    """Run the pipeline and return the report path."""

    known = known or []
    out_dir.mkdir(parents=True, exist_ok=True)
    local = out_dir / "local"
    local.mkdir(exist_ok=True)
    paid = PaidModel(model, budget, prices)
    state = RunState()
    when = commit_time or datetime.now(timezone.utc)
    try:
        state.sources, state.sinks, state.invariants, state.mechanisms = extract_atoms(checkout)
        state.invariants = _filter_invariants(paid, state.invariants)
        state.claims.extend(
            plain_reviews(paid, checkout, rounds=review_rounds, max_output=max_output)
        )
        state.habit_strings = habit_texts(state.claims, checkout, scanners=scanners)
        habit_vectors = _embed_habits(paid, state.habit_strings)
        others = [*state.sinks, *state.invariants]
        pairs = colocated_pairs(state.sources, others, limit=max(1, sample_limit // 4), seed=seed)
        state.candidates = propose_candidates(paid, pairs, state.mechanisms, seed=seed, max_output=max_output)[:sample_limit]
        rate_coherence(paid, checkout, state.candidates, batch_size=coherence_batch, max_output=max_output)
        state.ranked_07, state.ranked_04 = _score_pool(paid, state.candidates, habit_vectors)
        floor = [item for item in state.ranked_07 if (item.coherence or 0) >= min_coherence]
        state.above_floor = len(floor)
        if not floor and fallback_hunts:                # asciitree: nothing reached 3, so nothing was hunted
            floor = [item for item in state.ranked_07 if item.rated and (item.coherence or 0) >= 2][:fallback_hunts]
            state.fallback = len(floor)
        top = floor[:20]
        state.hunted = top
        for candidate in top:
            if budget.should_stop():
                raise BudgetStop("hunt")
            result = directed_hunt(
                paid,
                checkout,
                candidate,
                rounds=hunt_rounds,
                token_cap=hunt_token_cap,
                max_output=max_output,
            )
            state.claims.extend(result.claims)
    except BudgetStop:
        state.stopped = True
        log.info("stopping because 80 percent of the budget is spent")
    except LLMError as exc:
        state.error = str(redact(str(exc), secret))
        _persist(state, out_dir, budget, known, target, commit, secret, run_id, stopped=state.stopped)
        raise LLMError(state.error) from None

    _confirm(state, checkout, out_dir, confirm_mode, container_image, when)
    texts = [claim.text for claim, confirmation in state.confirmations if confirmation.confirmed]
    if texts:
        try:
            state.confirmed_vectors = paid.embed(texts, stage="score").vectors
        except (BudgetStop, LLMError):                     # merged by class alone, then
            state.confirmed_vectors = None
    return _persist(state, out_dir, budget, known, target, commit, secret, run_id, stopped=state.stopped)


def _confirm(
    state: RunState,
    checkout: Path,
    out_dir: Path,
    mode: str,
    image: str,
    commit_time: datetime,
) -> None:
    work = out_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    deps = DepsStatus(True, "not requested")
    if mode == "podman":
        imports = reproducer_imports([claim.reproducer for claim in state.claims], set(package_names(checkout)))
        deps = prepare_wheels(checkout, commit_time, work, imports=imports, python_tag=python_tag_for(image))
        log.info("dependencies: %s", deps.why)
        if deps.ok and deps.target is not None:
            failure = install_wheels(image, work, deps)
            if failure:
                deps = DepsStatus(False, failure)
    for index, claim in enumerate(state.claims):
        slot = work / f"claim-{index}"
        try:
            if mode == "local":
                confirmation = confirm_local(claim, checkout, slot)
            else:
                confirmation = confirm_podman(claim, checkout, slot, image=image, deps=deps)
        except Exception as exc:
            confirmation = Confirmation(False, f"confirmation error: {exc}")
        state.confirmations.append((claim, confirmation))


def _persist(
    state: RunState,
    out_dir: Path,
    budget: Budget,
    known: list[KnownAdvisory],
    target: str,
    commit: str,
    secret: str | None,
    run_id: str,
    *,
    stopped: bool,
) -> Path:
    confirmed_pairs = [(claim, confirmation) for claim, confirmation in state.confirmations if confirmation.confirmed]
    confirmed = unique_confirmed(confirmed_pairs, state.confirmed_vectors)
    top = state.hunted                      # what was hunted, not the top of the score (#4's first run listed the latter)
    dump_json(
        out_dir / "01-habits.json",
        {
            "claims": [claim.public_dict() for claim in state.claims if claim.origin == "plain"],
            "scanner_texts": [text for text in state.habit_strings if text not in {c.text for c in state.claims}],
        },
    )
    dump_json(
        out_dir / "02-atoms.json",
        {
            "sources": [atom.as_dict() for atom in state.sources],
            "sinks": [atom.as_dict() for atom in state.sinks],
            "invariants": [atom.as_dict() for atom in state.invariants],
            "mechanisms": [atom.as_dict() for atom in state.mechanisms],
        },
    )
    dump_json(
        out_dir / "03-candidates.json",
        {
            "beta_0_7": [item.as_dict() for item in state.ranked_07],
            "beta_0_4": [item.as_dict() for item in state.ranked_04],
            "top_0_7": [item.id for item in top],
        },
    )
    dump_json(
        out_dir / "04-hunts.json",
        [
            {
                "id": item.id,
                "coherence": item.coherence,
                "unavailability": item.unavailability,
                "score_0_7": item.score_0_7,
                "score_0_4": item.score_0_4,
                "path_exists": item.path_exists,
                "incoherent": item.incoherent,
            }
            for item in top
        ],
    )
    dump_json(
        out_dir / "05-confirmation.json",
        [
            {
                "origin": claim.origin,
                "candidate_id": claim.candidate_id,
                "class": claim.class_label,
                "confirmed": confirmation.confirmed,
                "why": confirmation.why,
                "exit_code": confirmation.exit_code,
                "call_count": len(confirmation.calls),
            }
            for claim, confirmation in state.confirmations
        ],
    )
    dump_json(out_dir / "usage.json", budget.as_dict())
    rows = public_rows(confirmed, known)
    detail = []
    for row, claim in zip(rows, confirmed):
        match = next(
            confirmation
            for confirmed_claim, confirmation in confirmed_pairs
            if confirmed_claim is claim or (
                confirmed_claim.origin == claim.origin
                and confirmed_claim.class_label == claim.class_label
                and confirmed_claim.functions == claim.functions
            )
        )
        detail.append(
            {
                **row,
                "text": claim.text,
                "functions": claim.functions,
                "files": claim.files,
                "reproducer": claim.reproducer,
                "why": match.why,
                "exit_code": match.exit_code,
                "output": match.output,
            }
        )
    dump_json(out_dir / "local" / "detail.json", {"confirmed": detail, "overlap": overlap_functions(confirmed)})
    report = render_report(
        run_id=run_id,
        target=target,
        commit=commit,
        budget=budget,
        claims=confirmed,
        top=top,
        known=known,
        stopped=stopped or state.stopped,
        secret=secret,
        made=state.claims,
        pool=state.candidates,
        confirmed_all=len(confirmed_pairs),
        above_floor=state.above_floor,
        fallback=state.fallback,
    )
    if state.error:
        report += f"\n## Error\n\n{state.error}\n"
    path = out_dir / "REPORT.md"
    path.write_text(report, encoding="utf-8")
    log.info("wrote %s", path)
    return path
