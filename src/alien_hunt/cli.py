"""Command line: alien-hunt run <url> --commit <sha> --budget 5."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from alien_hunt import __version__
from alien_hunt.arms import load_labels, load_run, render_totals
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
    parser.add_argument("--version", action="version", version=f"alien-hunt {__version__}")
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
    run.add_argument("--arms", type=int, default=0, help="hunt N picks per selection rule, with the floor off (README)")
    arms = sub.add_parser("arms", help="add up the runs made with --arms (no model calls)")
    arms.add_argument("runs", nargs="+", type=Path, help="run folders, each with a 06-arms.json")
    arms.add_argument("--labels", type=Path, help='JSON from the ids in local/arms-to-label.jsonl to "real" or "not"')
    again = sub.add_parser("replay", help="confirm a run's saved claims again with the current check (no model calls)")
    again.add_argument("run", type=Path, help="a run folder, with local/claims.jsonl")
    again.add_argument("url", nargs="?", help="the repository, for a run with no run.json")
    again.add_argument("--commit", help="the commit the run reviewed, for a run with no run.json")
    again.add_argument("--local", type=Path, help="confirm against an existing checkout instead")
    again.add_argument("--against", help="also confirm on this commit of the same repository, e.g. the fix")
    again.add_argument("--against-local", type=Path, help="also confirm on this checkout")
    again.add_argument("--image", help="container image (default: the run's, then the config's)")
    again.add_argument("--config", type=Path, default=Path("alien-hunt.toml"))
    again.add_argument("--out", type=Path, default=Path("out"), help="where fetched checkouts go")
    pool = sub.add_parser("pool", help="show the atoms and pairs a run would draw (no model, no key, no cost)")
    pool.add_argument("url", nargs="?", help="https://github.com/owner/repo")
    pool.add_argument("--local", type=Path, help="look at an existing checkout instead of cloning")
    pool.add_argument("--commit", help="commit sha to fetch")
    pool.add_argument("--seed", type=int, default=0)
    pool.add_argument("--sample-limit", type=int, help="default: the config's, else 80")
    pool.add_argument("--config", type=Path, default=Path("alien-hunt.toml"))
    pool.add_argument("--out", type=Path, default=Path("out"), help="where a fetched checkout goes")
    pool.add_argument("--json", action="store_true", help="print the raw result as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns a process status code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    commands = {"run": _run, "arms": _arms, "replay": _replay, "pool": _pool}
    try:
        return commands[args.command](args)
    except (ConfigError, CheckoutError) as exc:
        print(f"alien-hunt: {exc}", file=sys.stderr)
        return 2
    except LLMError as exc:
        print(f"alien-hunt: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("alien-hunt: interrupted", file=sys.stderr)
        return 130


def _arms(args: argparse.Namespace) -> int:
    if len({folder.resolve() for folder in args.runs}) != len(args.runs):
        raise ConfigError("a run is listed twice")
    runs = [load_run(folder) for folder in args.runs]
    print(render_totals(runs, load_labels(args.labels) if args.labels else None))
    return 0


def _config_image(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return load_config(path).container_image
    except ConfigError:
        return None


def _replay(args: argparse.Namespace) -> int:
    from alien_hunt.pipeline import RUN_FILE
    from alien_hunt.replay import DEFAULT_IMAGE, Tree, dump, load_claims, load_record, render, replay

    if args.url and args.local:
        raise CheckoutError("pass either a GitHub URL or --local")
    if args.against and args.against_local:
        raise CheckoutError("pass either --against or --against-local")
    claims = load_claims(args.run)
    record = load_record(args.run)
    recorded = str(record.get("target") or "")
    url = args.url or (recorded if recorded.startswith("https://github.com/") else None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.local:
        path = prepare_local(args.local)
        here = Tree(path, _commit_time(path), (args.commit or str(path))[:40])
    elif url:
        parse_github_url(url)
        commit = args.commit or str(record.get("commit") or "")
        if not commit:
            raise CheckoutError("a --commit sha is required for a GitHub URL")
        commit = validate_sha(commit)
        path = fetch_github(url, commit, args.out / f"src-{stamp}")
        here = Tree(path, _commit_time(path), commit[:12])
    else:
        raise CheckoutError(f"{args.run} has no {RUN_FILE} with a GitHub target: pass the URL and --commit, or --local")
    there = None
    if args.against:
        if not url:
            raise CheckoutError("--against needs the repository URL; for a checkout use --against-local")
        sha = validate_sha(args.against)
        path = fetch_github(url, sha, args.out / f"src-{stamp}-against")
        there = Tree(path, _commit_time(path), sha[:12])
    elif args.against_local:
        path = prepare_local(args.against_local)
        there = Tree(path, _commit_time(path), str(path)[:40])
    image = args.image or record.get("container_image") or _config_image(args.config) or DEFAULT_IMAGE
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    local = args.run / "local"
    verdicts = replay(claims, here, local / f"replay-{stamp}", there=there, image=str(image))
    dump(verdicts, local / f"replay-{stamp}.json", here, there)
    print(render(verdicts, here, there))
    return 0


def _pool(args: argparse.Namespace) -> int:
    from alien_hunt.preview import preview, render

    if args.url and args.local:
        raise CheckoutError("pass either a GitHub URL or --local")
    if args.local:
        checkout = prepare_local(args.local)
        label = str(checkout)
    elif args.url:
        parse_github_url(args.url)
        if not args.commit:
            raise CheckoutError("a --commit sha is required for a GitHub URL")
        commit = validate_sha(args.commit)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        checkout = fetch_github(args.url, commit, args.out / f"src-{stamp}")
        label = f"{args.url} at {commit[:12]}"
    else:
        raise CheckoutError("pass a GitHub URL or --local")
    limit = args.sample_limit
    if limit is None and args.config.is_file():
        limit = load_config(args.config).sample_limit
    if limit is not None and limit < 1:
        raise ConfigError("--sample-limit must be >= 1")
    result = preview(checkout, sample_limit=limit or 80, seed=args.seed)
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else render(result, label))
    return 0


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
    if args.arms < 0:
        raise ConfigError("--arms must be >= 0")
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
        plain_temperature=config.plain_temperature,
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
        arms=args.arms,
    )
    print(report)
    return 0
