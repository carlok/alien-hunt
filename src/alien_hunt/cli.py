"""Command line: alien-hunt run <url> --commit <sha> --budget 5."""

from __future__ import annotations

import argparse
import logging
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.budget import Budget
from alien_hunt.checkout import (
    CheckoutError,
    commit_timestamp,
    fetch_github,
    parse_github_url,
    prepare_local,
    validate_sha,
)
from alien_hunt.config import ConfigError, load_config
from alien_hunt.llm import LLMError, OpenAIModel
from alien_hunt.pipeline import execute
from alien_hunt.types import KnownAdvisory


def _load_known(path: Path) -> list[KnownAdvisory]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    known = []
    for entry in data.get("known") or []:
        known.append(
            KnownAdvisory(
                id=str(entry["id"]),
                class_label=str(entry.get("class") or entry.get("class_label") or ""),
                symbols=[str(item) for item in entry.get("symbols") or []],
                cve=entry.get("cve"),
                classes=[str(item) for item in entry.get("classes") or []],
            )
        )
    return known


def _commit_time(checkout: Path) -> datetime:
    try:
        stamp = commit_timestamp(checkout)
    except CheckoutError:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alien-hunt",
        description="Look for defects a plain review of a repository does not already produce.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="review one public GitHub commit")
    run.add_argument("url", nargs="?", help="https://github.com/owner/repo")
    run.add_argument("--local", type=Path, help="review an existing checkout instead of cloning")
    run.add_argument("--commit", help="commit sha to fetch")
    run.add_argument("--budget", type=float, default=5.0, help="USD limit (default 5)")
    run.add_argument("--config", type=Path, default=Path("alien-hunt.toml"))
    run.add_argument("--out", type=Path, default=Path("out"))
    run.add_argument("--known", type=Path, help="TOML allowlist of public advisories")
    run.add_argument("--seed", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns a process status code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.error("unknown command")
    try:
        return _run(args)
    except (ConfigError, CheckoutError) as exc:
        print(f"alien-hunt: {exc}", file=sys.stderr)
        return 2
    except LLMError as exc:
        print(f"alien-hunt: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    if args.url and args.local:
        raise CheckoutError("pass either a GitHub URL or --local")
    if args.url:
        parse_github_url(args.url)
        if not args.commit:
            raise CheckoutError("a --commit sha is required for a GitHub URL")
        validate_sha(args.commit)
    elif args.local is None:
        raise CheckoutError("pass a GitHub URL or --local")
    if args.budget < 0:
        raise ConfigError("budget must be >= 0")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(args.config)
    secret = config.secrets()
    model = OpenAIModel(config)
    if args.local:
        checkout = prepare_local(args.local)
        commit = args.commit or ""
        target = str(checkout)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        checkout = args.out / f"src-{stamp}"
        fetch_github(args.url, args.commit, checkout)
        commit = validate_sha(args.commit)
        target = args.url
    known = _load_known(args.known) if args.known else []
    moment = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = (commit or "local")[:8]
    run_id = f"{moment}-{suffix}"
    report = execute(
        checkout,
        model=model,
        budget=Budget(limit_usd=args.budget),
        prices=config.prices,
        out_dir=args.out / run_id,
        known=known,
        seed=args.seed,
        sample_limit=config.sample_limit,
        review_rounds=config.max_tool_rounds_review,
        hunt_rounds=config.max_tool_rounds_hunt,
        hunt_token_cap=config.max_tokens_per_hunt,
        coherence_batch=config.coherence_batch,
        confirm_mode="podman",
        container_image=config.container_image,
        commit_time=_commit_time(checkout),
        target=target,
        commit=commit,
        secret=secret,
        run_id=run_id,
        max_output=config.max_output_tokens,
        min_coherence=config.min_coherence,
        fallback_hunts=config.fallback_hunts,
    )
    print(report)
    return 0
