#!/usr/bin/env python3
"""Build the cases scripts/pool_ceiling.py measures, from GitHub's advisory database.

    select   read a clone of github/advisory-database, ask the GitHub API about the fix commits, and write a manifest
    snapshot fetch each case's vulnerable and fixed commits, keep only their library .py files, and delete the rest

An advisory qualifies when it is github-reviewed, not withdrawn, for a PyPI package, and links at least one
`github.com/<owner>/<repo>/commit/<sha>` in the package's own repository (the repository its GHSA page is published in,
or one named like the package). Before is the parent of the earliest fix commit. After is the latest fix commit when the
fix commits lie on one line of history, else the earliest. A case is kept only if the fix changes a non-test .py file.

Cases published before 2025-01-01 are the tuning split; later ones are held out. A draw is seeded, takes at most
`--per-repo` cases from one repository and at most `--family-share` of a split from one CWE family.

The advisory text is data. Only structured fields are read, and nothing from a target repository is run: a snapshot
holds .py files that `ast` will parse.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SPLIT_DATE = "2025-01-01"
_COMMIT = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$")
_GHSA_PAGE = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/security/advisories/GHSA-")


def _span(low: int, high: int) -> set[int]:
    return set(range(low, high + 1))


FAMILIES: dict[str, set[int]] = {
    "injection": {74, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 113, 116, 117, 138, 470, 643, 917, 1236},
    "path-and-file": {22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 59, 61, 62, 64, 65,
                      66, 73, 426, 427, 428, 434, 552, 668},
    "deserialization": {502, 915, 1321},
    "resource-exhaustion": {399, 400, 405, 407, 409, 674, 770, 771, 772, 776, 789, 834, 835, 1050, 1333},
    "memory-and-numeric": {119, 120, 121, 122, 125, 126, 127, 128, 129, 131, 170, 190, 191, 192, 193, 194, 195, 196, 197,
                           369, 415, 416, 457, 466, 680, 681, 682, 787, 788, 805, 823, 824, 825, 843},
    "ssrf-redirect-xxe": {441, 601, 610, 611, 918},
    "crypto-and-tls": _span(295, 299) | _span(310, 347) | {354, 757, 759, 760, 916, 1240},
    "authn-authz": _span(255, 311) | {345, 346, 347, 348, 349, 350, 352, 384, 521, 522, 523, 565, 613, 620, 639, 640, 732,
                                     798, 862, 863, 913, 922, 1275},
    "info-disclosure": {200, 201, 202, 203, 204, 209, 210, 212, 213, 214, 215, 497, 532, 538, 540, 548, 598},
    "crash-and-errors": {248, 252, 253, 390, 391, 392, 394, 395, 396, 397, 476, 617, 703, 754, 755},
    "input-validation": {20, 172, 175, 176, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 1284, 1286, 1287, 1288, 1289},
}
_FAMILY_OF: dict[int, str] = {}
for _name, _ids in FAMILIES.items():
    for _id in sorted(_ids):
        _FAMILY_OF.setdefault(_id, _name)


def parse_commit_url(url: str) -> tuple[str, str, str] | None:
    match = _COMMIT.match(url or "")
    return (match.group(1), match.group(2), match.group(3).lower()) if match else None


def cwe_family(cwe_ids: list[str]) -> str:
    """The family of the most specific listed CWE: generic input validation only if nothing else is listed."""

    found: list[str] = []
    for item in cwe_ids or []:
        match = re.fullmatch(r"CWE-(\d+)", str(item))
        family = _FAMILY_OF.get(int(match.group(1))) if match else None
        if family and family not in found:
            found.append(family)
    specific = [name for name in found if name != "input-validation"]
    return (specific or found or ["other"])[0]


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def qualify(advisory: dict) -> dict | None:
    """A candidate record, or None. Reads structured fields only."""

    packages = [
        (item.get("package") or {}).get("name", "")
        for item in advisory.get("affected") or []
        if (item.get("package") or {}).get("ecosystem") == "PyPI"
    ]
    if not packages or advisory.get("withdrawn"):
        return None
    if not (advisory.get("database_specific") or {}).get("github_reviewed", True):
        return None
    urls = [ref.get("url", "") for ref in advisory.get("references") or []]
    commits = [parsed for parsed in map(parse_commit_url, urls) if parsed]
    pages = {(m.group(1).lower(), m.group(2).lower()) for m in map(_GHSA_PAGE.match, urls) if m}
    wanted = {_norm(name) for name in packages}
    own = [c for c in commits if (c[0].lower(), c[1].lower()) in pages or _norm(c[1]) in wanted]
    if not own:
        return None
    repo = (own[0][0], own[0][1])
    shas = []
    for owner, name, sha in own:
        if (owner.lower(), name.lower()) == (repo[0].lower(), repo[1].lower()) and sha not in shas:
            shas.append(sha)
    cwes = list((advisory.get("database_specific") or {}).get("cwe_ids") or [])
    return {
        "id": advisory.get("id"),
        "package": packages[0],
        "published": advisory.get("published", ""),
        "cwe": cwes,
        "family": cwe_family(cwes),
        "repo": f"{repo[0]}/{repo[1]}",
        "commits": shas,
        "split": "tune" if advisory.get("published", "") < SPLIT_DATE else "heldout",
    }


def scan(db_root: Path) -> list[dict]:
    out = []
    for path in sorted(db_root.rglob("GHSA-*.json")):
        try:
            record = qualify(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
        if record:
            out.append(record)
    return out


def is_library_py(path: str, atoms) -> bool:
    """The test `extract_atoms` applies, on a repository path: a .py file outside tests, docs, examples and build dirs."""

    parts = Path(path).parts
    if not parts or not parts[-1].endswith(".py"):
        return False
    if any(part in atoms._SKIP_DIRS or part in atoms._NOT_LIBRARY_DIRS for part in parts[:-1]):
        return False
    name = parts[-1]
    return not (name in atoms._NOT_LIBRARY_FILES or name.startswith("test_") or name.endswith("_test.py"))


class GhApi:
    """The few GitHub REST calls selection needs, through the `gh` CLI, cached in a folder."""

    def __init__(self, cache: Path) -> None:
        self.cache = cache
        cache.mkdir(parents=True, exist_ok=True)

    def get(self, endpoint: str, jq: str | None = None):
        key = self.cache / (re.sub(r"[^A-Za-z0-9_.-]+", "_", endpoint + (jq or "")) + ".json")
        if key.is_file():
            return json.loads(key.read_text(encoding="utf-8"))
        command = ["gh", "api", endpoint] + (["--jq", jq] if jq else [])
        for attempt in range(4):
            done = subprocess.run(command, capture_output=True, text=True, check=False)
            if done.returncode == 0:
                break
            if "rate limit" in (done.stderr + done.stdout).lower():
                time.sleep(45 * (attempt + 1))
            elif "404" in done.stderr or "422" in done.stderr or "Not Found" in done.stderr:
                return None
            else:
                time.sleep(3)
        else:
            return None
        text = done.stdout.strip()
        try:
            value = json.loads(text) if text else None
        except ValueError:
            value = text.strip('"')
        key.write_text(json.dumps(value), encoding="utf-8")
        return value

    def commit(self, repo: str, sha: str) -> dict | None:
        return self.get(f"repos/{repo}/commits/{sha}")

    def compare_status(self, repo: str, base: str, head: str) -> str | None:
        return self.get(f"repos/{repo}/compare/{base}...{head}", jq=".status")

    def repo_size_kb(self, repo: str) -> int | None:
        return self.get(f"repos/{repo}", jq=".size")


def resolve(candidate: dict, api, atoms) -> dict | None:
    """Fill in before and after, or None when the advisory does not make a usable case."""

    repo = candidate["repo"]
    infos = []
    for sha in candidate["commits"][:6]:
        info = api.commit(repo, sha)
        if not info or not info.get("sha"):
            return None
        infos.append(info)
    infos.sort(key=lambda item: ((item.get("commit") or {}).get("committer") or {}).get("date", ""))
    first = infos[0]
    if not first.get("parents"):
        return None
    changed = [f.get("filename", "") for info in infos for f in info.get("files") or []]
    changed += [f.get("previous_filename", "") for info in infos for f in info.get("files") or []]
    if not any(is_library_py(name, atoms) for name in changed if name):
        return None
    linear = all(
        api.compare_status(repo, low["sha"], high["sha"]) in ("ahead", "identical")
        for low, high in zip(infos, infos[1:])
    )
    after = infos[-1]["sha"] if linear else first["sha"]
    return {**candidate, "commits": [info["sha"] for info in infos], "before": first["parents"][0]["sha"],
            "after": after, "linear": linear}


def choose(
    candidates: list[dict], *, count: int, seed: int, per_repo: int, family_share: float, resolver, workers: int = 8
) -> list[dict]:
    """Walk a seeded shuffle, resolving a chunk at a time, and accept cases while the repository and family limits hold."""

    pool = list(candidates)
    random.Random(seed).shuffle(pool)
    family_cap = max(1, int(count * family_share))
    taken: list[dict] = []
    repos: dict[str, int] = {}
    families: dict[str, int] = {}

    def allowed(item: dict) -> bool:
        return repos.get(item["repo"].lower(), 0) < per_repo and families.get(item["family"], 0) < family_cap

    index = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        while len(taken) < count and index < len(pool):
            chunk = []
            while index < len(pool) and len(chunk) < workers * 2:
                if allowed(pool[index]):
                    chunk.append(pool[index])
                index += 1
            for item, case in zip(chunk, executor.map(resolver, chunk)):
                if case and allowed(item) and len(taken) < count:
                    taken.append(case)
                    repos[item["repo"].lower()] = repos.get(item["repo"].lower(), 0) + 1
                    families[item["family"]] = families.get(item["family"], 0) + 1
    return taken


def prune_to_library(checkout: Path, dest: Path, atoms) -> int:
    """Copy the library .py files of a checkout into `dest` and delete the checkout. Returns the number kept."""

    kept = 0
    for path in atoms._py_files(checkout):
        target = dest / path.relative_to(checkout)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        kept += 1
    shutil.rmtree(checkout, ignore_errors=True)
    return kept


def snapshot_case(case: dict, root: Path, scratch: Path, atoms, fetch) -> tuple[str, str]:
    """Fetch the two commits and keep their library files. Returns (case id, 'ok' or the reason it was dropped)."""

    folder = root / case["id"]
    if (folder / "case.json").is_file():
        return case["id"], "ok"
    scratch.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{case['repo']}"
    try:
        for label in ("before", "after"):
            work = scratch / f"{case['id']}-{label}"
            shutil.rmtree(work, ignore_errors=True)
            fetch(url, case[label], work)
            if prune_to_library(work, folder / label, atoms) == 0:
                raise RuntimeError(f"no library .py files at {label}")
    except Exception as exc:
        shutil.rmtree(folder, ignore_errors=True)
        for label in ("before", "after"):
            shutil.rmtree(scratch / f"{case['id']}-{label}", ignore_errors=True)
        return case["id"], f"{type(exc).__name__}: {exc}"[:200]
    (folder / "case.json").write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return case["id"], "ok"


def load_alien_hunt():
    from alien_hunt import atoms
    from alien_hunt.checkout import fetch_github

    return atoms, fetch_github


def cmd_select(args) -> int:
    atoms, _ = load_alien_hunt()
    api = GhApi(args.cache)
    found = scan(args.advisories)
    print(f"{len(found)} qualifying advisories before the API check", file=sys.stderr)
    out = []
    for split, count in (("tune", args.tune), ("heldout", args.heldout)):
        pool = [item for item in found if item["split"] == split]
        chosen = choose(pool, count=count, seed=args.seed, per_repo=args.per_repo, family_share=args.family_share,
                        resolver=lambda item: resolve(item, api, atoms), workers=args.workers)
        print(f"{split}: {len(chosen)} cases of {len(pool)} candidates", file=sys.stderr)
        out.extend(chosen)
    args.out.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in out), encoding="utf-8")
    return 0


def cmd_snapshot(args) -> int:
    atoms, fetch = load_alien_hunt()
    os.environ.setdefault("GIT_HTTP_LOW_SPEED_LIMIT", "1000")        # a stalled fetch ends instead of hanging a worker
    os.environ.setdefault("GIT_HTTP_LOW_SPEED_TIME", "60")
    api = GhApi(args.cache)
    cases = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.split:
        cases = [case for case in cases if case["split"] == args.split]
    skipped = {}
    runnable = []
    for case in cases:
        size = api.repo_size_kb(case["repo"])
        if size is not None and size > args.max_repo_kb:
            skipped[case["id"]] = f"repository is {size} KB"
        else:
            runnable.append(case)
    failed = dict(skipped)
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for ident, status in executor.map(
            lambda case: snapshot_case(case, args.root, args.scratch, atoms, fetch), runnable
        ):
            if status != "ok":
                failed[ident] = status
            print(f"{ident}: {status}", file=sys.stderr)
    (args.root / "dropped.json").write_text(json.dumps(failed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(cases) - len(failed)} snapshots, {len(failed)} dropped", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench_cases", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    pick = sub.add_parser("select")
    pick.add_argument("advisories", type=Path, help="advisories/github-reviewed in a clone of github/advisory-database")
    pick.add_argument("--out", type=Path, required=True)
    pick.add_argument("--cache", type=Path, required=True)
    pick.add_argument("--tune", type=int, default=160)
    pick.add_argument("--heldout", type=int, default=100)
    pick.add_argument("--seed", type=int, default=0)
    pick.add_argument("--per-repo", type=int, default=2)
    pick.add_argument("--family-share", type=float, default=0.3)
    pick.add_argument("--workers", type=int, default=8)
    snap = sub.add_parser("snapshot")
    snap.add_argument("manifest", type=Path)
    snap.add_argument("--root", type=Path, required=True, help="where the case folders go")
    snap.add_argument("--scratch", type=Path, required=True, help="where checkouts live until they are pruned")
    snap.add_argument("--cache", type=Path, required=True)
    snap.add_argument("--split", choices=("tune", "heldout"))
    snap.add_argument("--workers", type=int, default=6)
    snap.add_argument("--max-repo-kb", type=int, default=2_000_000)
    args = parser.parse_args(argv)
    return cmd_select(args) if args.command == "select" else cmd_snapshot(args)


if __name__ == "__main__":
    raise SystemExit(main())
