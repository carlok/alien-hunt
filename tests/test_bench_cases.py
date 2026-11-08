"""scripts/bench_cases.py: which advisories become cases, and how a case is cut down to its library files."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from alien_hunt import atoms as atoms_module

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bench_cases.py"
_spec = importlib.util.spec_from_file_location("bench_cases", SCRIPT)
bc = importlib.util.module_from_spec(_spec)
sys.modules["bench_cases"] = bc
_spec.loader.exec_module(bc)


def advisory(**over) -> dict:
    base = {
        "id": "GHSA-aaaa-bbbb-cccc",
        "published": "2023-05-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Some_Pkg"}}],
        "database_specific": {"github_reviewed": True, "cwe_ids": ["CWE-20", "CWE-22"]},
        "references": [
            {"type": "WEB", "url": "https://github.com/acme/somepkg/security/advisories/GHSA-aaaa-bbbb-cccc"},
            {"type": "WEB", "url": "https://github.com/acme/somepkg/commit/ABCDEF1234567"},
            {"type": "WEB", "url": "https://github.com/someone-else/fork/commit/1234567abcdef"},
        ],
    }
    base.update(over)
    return base


def test_commit_urls_are_parsed_and_lowercased():
    assert bc.parse_commit_url("https://github.com/o/r/commit/ABCDEF1") == ("o", "r", "abcdef1")
    assert bc.parse_commit_url("https://github.com/o/r/commit/abcdef1234567890abcdef1234567890abcdef12/files")
    assert bc.parse_commit_url("https://github.com/o/r/pull/12") is None
    assert bc.parse_commit_url("https://github.com/o/r/commit/zzz") is None
    assert bc.parse_commit_url("") is None


def test_the_most_specific_cwe_names_the_family():
    assert bc.cwe_family(["CWE-20", "CWE-22"]) == "path-and-file"
    assert bc.cwe_family(["CWE-20"]) == "input-validation"
    assert bc.cwe_family(["CWE-502"]) == "deserialization"
    assert bc.cwe_family(["CWE-327"]) == "crypto-and-tls"
    assert bc.cwe_family(["CWE-862"]) == "authn-authz"
    assert bc.cwe_family(["CWE-9999", "junk"]) == "other"
    assert bc.cwe_family([]) == "other"


def test_a_reviewed_pypi_advisory_with_a_commit_in_its_own_repository_qualifies():
    record = bc.qualify(advisory())
    assert record["repo"] == "acme/somepkg"
    assert record["commits"] == ["abcdef1234567"]            # the fork's commit is not the package's own
    assert record["family"] == "path-and-file" and record["split"] == "tune"
    assert record["package"] == "Some_Pkg"


def test_a_repository_named_like_the_package_qualifies_without_a_ghsa_page():
    refs = [{"type": "WEB", "url": "https://github.com/acme/some-pkg/commit/abcdef1"}]
    assert bc.qualify(advisory(references=refs))["repo"] == "acme/some-pkg"
    other = [{"type": "WEB", "url": "https://github.com/acme/unrelated/commit/abcdef1"}]
    assert bc.qualify(advisory(references=other)) is None


@pytest.mark.parametrize(
    "over",
    [
        {"withdrawn": "2024-01-01T00:00:00Z"},
        {"affected": [{"package": {"ecosystem": "npm", "name": "somepkg"}}]},
        {"database_specific": {"github_reviewed": False}},
        {"references": [{"type": "WEB", "url": "https://github.com/acme/somepkg/pull/3"}]},
    ],
)
def test_other_advisories_do_not_qualify(over):
    assert bc.qualify(advisory(**over)) is None


def test_published_before_2025_is_tuning_and_the_rest_is_held_out():
    assert bc.qualify(advisory(published="2024-12-31T23:59:59Z"))["split"] == "tune"
    assert bc.qualify(advisory(published="2025-01-01T00:00:00Z"))["split"] == "heldout"


def test_scan_reads_a_folder_and_skips_bad_files(tmp_path: Path):
    good = tmp_path / "2023" / "GHSA-aaaa-bbbb-cccc"
    good.mkdir(parents=True)
    (good / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps(advisory()), encoding="utf-8")
    (tmp_path / "GHSA-bad.json").write_text("{not json", encoding="utf-8")
    assert [item["id"] for item in bc.scan(tmp_path)] == ["GHSA-aaaa-bbbb-cccc"]


def test_library_files_are_the_ones_atoms_reads():
    assert bc.is_library_py("pkg/mod.py", atoms_module)
    assert bc.is_library_py("src/pkg/sub/mod.py", atoms_module)
    for path in ("tests/test_x.py", "pkg/test_x.py", "pkg/x_test.py", "docs/conf.py", "setup.py", "pkg/conftest.py",
                 "examples/demo.py", "pkg/data.json", "README.md", ""):
        assert not bc.is_library_py(path, atoms_module), path


class FakeApi:
    """Commit facts by sha, and a fixed ancestry answer."""

    def __init__(self, commits: dict[str, dict], status: str = "ahead") -> None:
        self.commits, self.status = commits, status

    def commit(self, repo, sha):
        return self.commits.get(sha)

    def compare_status(self, repo, base, head):
        return self.status


def info(sha: str, date: str, parent: str | None, files: list[str]) -> dict:
    return {
        "sha": sha,
        "commit": {"committer": {"date": date}},
        "parents": [{"sha": parent}] if parent else [],
        "files": [{"filename": name} for name in files],
    }


CANDIDATE = {"id": "GHSA-1", "repo": "acme/somepkg", "commits": ["c2", "c1"], "family": "other", "split": "tune"}


def test_before_is_the_parent_of_the_earliest_fix_and_after_the_latest_on_one_line():
    api = FakeApi(
        {
            "c1": info("c1", "2023-01-01T00:00:00Z", "p1", ["pkg/mod.py"]),
            "c2": info("c2", "2023-02-01T00:00:00Z", "c1", ["tests/test_mod.py"]),
        }
    )
    case = bc.resolve(CANDIDATE, api, atoms_module)
    assert (case["before"], case["after"], case["linear"]) == ("p1", "c2", True)
    assert case["commits"] == ["c1", "c2"]


def test_fix_commits_on_different_lines_use_the_earliest_alone():
    api = FakeApi(
        {
            "c1": info("c1", "2023-01-01T00:00:00Z", "p1", ["pkg/mod.py"]),
            "c2": info("c2", "2023-02-01T00:00:00Z", "q1", ["pkg/mod.py"]),
        },
        status="diverged",
    )
    case = bc.resolve(CANDIDATE, api, atoms_module)
    assert (case["before"], case["after"], case["linear"]) == ("p1", "c1", False)


def test_a_fix_that_touches_no_library_python_file_is_dropped():
    api = FakeApi(
        {
            "c1": info("c1", "2023-01-01T00:00:00Z", "p1", ["tests/test_a.py", "docs/index.md", "pkg/data.json"]),
            "c2": info("c2", "2023-02-01T00:00:00Z", "c1", ["README.md"]),
        }
    )
    assert bc.resolve(CANDIDATE, api, atoms_module) is None


def test_a_root_commit_and_an_unknown_commit_are_dropped():
    root = FakeApi({"c1": info("c1", "2023-01-01T00:00:00Z", None, ["pkg/mod.py"]), "c2": info("c2", "2023-02-01T00:00:00Z", "c1", [])})
    assert bc.resolve(CANDIDATE, root, atoms_module) is None
    assert bc.resolve(CANDIDATE, FakeApi({}), atoms_module) is None


def test_choose_limits_a_repository_and_a_family_and_is_seeded():
    pool = [
        {"id": f"G{i}", "repo": f"o/r{i % 4}", "family": "injection" if i % 2 else "crypto-and-tls", "split": "tune"}
        for i in range(40)
    ]
    resolver = lambda item: {**item, "before": "b", "after": "a"}                       # noqa: E731
    first = bc.choose(pool, count=6, seed=3, per_repo=2, family_share=0.5, resolver=resolver, workers=2)
    again = bc.choose(pool, count=6, seed=3, per_repo=2, family_share=0.5, resolver=resolver, workers=2)
    assert [c["id"] for c in first] == [c["id"] for c in again]
    assert len(first) == 6
    repos = [c["repo"] for c in first]
    assert max(repos.count(name) for name in set(repos)) <= 2
    families = [c["family"] for c in first]
    assert max(families.count(name) for name in set(families)) <= 3
    skipped = bc.choose(pool, count=6, seed=3, per_repo=2, family_share=0.5, resolver=lambda item: None, workers=2)
    assert skipped == []


def test_a_checkout_is_cut_to_library_files_and_removed(tmp_path: Path):
    checkout = tmp_path / "co"
    for relative in ("pkg/a.py", "pkg/sub/b.py", "tests/test_a.py", "docs/conf.py", "pkg/data.json", ".git/config"):
        path = checkout / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    dest = tmp_path / "snap"
    assert bc.prune_to_library(checkout, dest, atoms_module) == 2
    assert sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()) == ["pkg/a.py", "pkg/sub/b.py"]
    assert not checkout.exists()


def test_snapshot_case_writes_both_trees_and_a_manifest_or_cleans_up(tmp_path: Path):
    case = {"id": "GHSA-9", "repo": "acme/somepkg", "before": "b" * 40, "after": "a" * 40, "family": "x", "split": "tune"}

    def fetch(url, sha, dest):
        assert url == "https://github.com/acme/somepkg"
        (dest / "pkg").mkdir(parents=True)
        (dest / "pkg" / "m.py").write_text(f"SHA = {sha[:1]!r}\n", encoding="utf-8")

    root, scratch = tmp_path / "root", tmp_path / "scratch"
    assert bc.snapshot_case(case, root, scratch, atoms_module, fetch) == ("GHSA-9", "ok")
    assert (root / "GHSA-9" / "before" / "pkg" / "m.py").read_text(encoding="utf-8") == "SHA = 'b'\n"
    assert (root / "GHSA-9" / "after" / "pkg" / "m.py").is_file()
    assert json.loads((root / "GHSA-9" / "case.json").read_text(encoding="utf-8"))["repo"] == "acme/somepkg"
    assert not list(scratch.iterdir())

    def failing(url, sha, dest):
        if sha.startswith("a"):
            raise RuntimeError("fetch failed")
        fetch(url, sha, dest)

    other = {**case, "id": "GHSA-8"}
    ident, status = bc.snapshot_case(other, root, scratch, atoms_module, failing)
    assert ident == "GHSA-8" and "fetch failed" in status
    assert not (root / "GHSA-8").exists() and not list(scratch.iterdir())


def test_empty_snapshots_are_dropped(tmp_path: Path):
    case = {"id": "GHSA-7", "repo": "acme/somepkg", "before": "b" * 40, "after": "a" * 40}
    ident, status = bc.snapshot_case(case, tmp_path / "r", tmp_path / "s", atoms_module, lambda url, sha, dest: dest.mkdir())
    assert "no library .py files" in status and not (tmp_path / "r" / ident).exists()
