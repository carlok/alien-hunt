"""PyJWT's run 4 confirmed GHSA-ffqj-6fqr-9h24 as "algorithm-confusion" while the case said "key confusion", and the
report did not cite it; asciitree hunted nothing because no candidate reached 3; joserfc needs Python 3.11 or later
while the run always fetched cp310 wheels. These tests pin the fixes."""

from __future__ import annotations

from alien_hunt.confirm import python_tag_for
from alien_hunt.redact import class_hit, file_hit, matching_advisory
from alien_hunt.types import Claim, KnownAdvisory


def test_the_wheel_tag_follows_the_container_image():
    assert python_tag_for("docker.io/library/python:3.12-slim") == "cp312"
    assert python_tag_for("python:3.10") == "cp310"
    assert python_tag_for("ubuntu:24.04") == "cp310"


def advisory(**kw) -> KnownAdvisory:
    return KnownAdvisory(**{"id": "GHSA-x", "class_label": "key confusion", "symbols": ["jwt.algorithms"], **kw})


def test_a_class_matches_by_a_shared_word_but_not_a_generic_one():
    assert class_hit("algorithm-confusion", advisory())
    assert class_hit("Key Confusion", advisory())
    assert not class_hit("error-handling", advisory())
    assert not class_hit("input-validation-error", advisory(class_label="error handling"))   # "error" alone is not a match
    assert class_hit("dos", advisory(class_label="denial of service", classes=["dos"]))
    assert class_hit("denial-of-service", advisory(class_label="denial of service"))


def test_a_module_symbol_matches_a_file():
    assert file_hit(["jwt/algorithms.py"], "jwt.algorithms")
    assert file_hit(["src/joserfc/_rfc7516/json.py"], "joserfc._rfc7516.json")
    assert not file_hit(["jwt/api_jws.py"], "jwt.algorithms")


def test_pyjwts_run_four_claim_would_now_be_cited():
    claim = Claim(text="ssh-ed25519 public key accepted as an HMAC secret", class_label="algorithm-confusion",
                  files=["jwt/algorithms.py"], functions=["HMACAlgorithm.sign", "HMACAlgorithm.prepare_key", "PyJWS.encode"],
                  reproducer="r", origin="hunt", candidate_id="c1")
    known = [advisory(id="GHSA-ffqj-6fqr-9h24", symbols=["jwt.api_jwk", "PyJWK", "jwt.algorithms"])]
    assert matching_advisory(claim, known).id == "GHSA-ffqj-6fqr-9h24"
    other = Claim(text="t", class_label="state-mutation", files=["jwt/api_jwt.py"], functions=["PyJWT.decode_complete"],
                  reproducer="r", origin="plain", candidate_id=None)
    assert matching_advisory(other, known) is None


def test_with_nothing_at_the_floor_the_best_rated_two_are_hunted(tmp_path):
    import test_pipeline
    from alien_hunt.budget import Budget
    from alien_hunt.config import Prices
    from alien_hunt.pipeline import execute

    class Lukewarm(test_pipeline.ScriptedModel):
        def _ratings(self, blob):
            return [dict(item, score=min(item["score"], 2)) for item in super()._ratings(blob)]

    execute(test_pipeline.FIXTURE, model=Lukewarm(), budget=Budget(limit_usd=5), prices=Prices(1, 1, 1), out_dir=tmp_path,
            sample_limit=1000, confirm_mode="local", scanners=False, run_id="lukewarm", fallback_hunts=2)
    text = (tmp_path / "REPORT.md").read_text(encoding="utf-8")
    assert "At or above the coherence floor: 0 (only those are hunted; none was, so the best 2 rated 2 were)" in text
    assert "Top candidates judged: 2 of 2" in text

    execute(test_pipeline.FIXTURE, model=Lukewarm(), budget=Budget(limit_usd=5), prices=Prices(1, 1, 1),
            out_dir=tmp_path / "off", sample_limit=1000, confirm_mode="local", scanners=False, run_id="off", fallback_hunts=0)
    assert "Top candidates judged: 0 of 0" in (tmp_path / "off" / "REPORT.md").read_text(encoding="utf-8")


def test_a_src_layout_is_the_repositorys_own_and_comes_first_on_the_path(tmp_path):
    """joserfc keeps its code in src/joserfc: the run refused all 6 reproducers as not importing the repository, and
    fetched joserfc 1.7.4 from PyPI onto a path that came before the checkout."""
    from pathlib import Path

    from alien_hunt.confirm import podman_exec_argv, reproducer_imports
    from alien_hunt.habits import package_names, src_layout

    root = tmp_path / "repo"
    (root / "src" / "joserfc").mkdir(parents=True)
    (root / "src" / "joserfc" / "__init__.py").write_text("", encoding="utf-8")
    (root / "docs").mkdir()
    assert src_layout(root) and package_names(root) == ["joserfc"]
    assert reproducer_imports(["import joserfc\nfrom cryptography import x509\n"], set(package_names(root))) == ["cryptography"]
    argv = podman_exec_argv("python:3.12-slim", root, tmp_path / "w", tmp_path / "r", tmp_path / "deps")
    assert "PYTHONPATH=/src/src:/src:/opt/deps" in argv

    flat = tmp_path / "flat"
    (flat / "jwt").mkdir(parents=True)
    (flat / "jwt" / "__init__.py").write_text("", encoding="utf-8")
    (flat / "src").mkdir()                                        # a src folder with no package in it is not a layout
    assert not src_layout(flat) and package_names(flat) == ["jwt"]
    assert "PYTHONPATH=/src" in podman_exec_argv("python:3.12-slim", flat, tmp_path / "w", tmp_path / "r", None)


def test_the_local_runner_sees_a_src_layout(tmp_path):
    from alien_hunt.confirm import _run_runner

    root = tmp_path / "repo"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "pkg" / "__init__.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    import sys

    code, calls, output = _run_runner(root, "import pkg\nimport sys\nsys.exit(0 if pkg.f() == 1 else 1)\n", tmp_path / "w",
                                      python=sys.executable)
    assert code == 0, output
