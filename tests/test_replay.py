"""`replay`: a run's saved claims confirmed again, and against a fixed tree, with no model call."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from alien_hunt import replay as replay_module
from alien_hunt.cli import main
from alien_hunt.config import ConfigError
from alien_hunt.pipeline import RUN_FILE, iter_confirmations
from alien_hunt.replay import (
    CONFIRMED,
    FIRES_THERE,
    FIXED_THERE,
    REFUSED,
    Tree,
    load_claims,
    load_record,
    render,
    replay,
)

from test_pipeline import ALLOC, FIXTURE

ROOT = Path(__file__).resolve().parents[1]
WHEN = datetime(2024, 1, 1, tzinfo=timezone.utc)

# Comes out true when allocate is right: the shape the check alone cannot refuse (reports/offline-tune/SUMMARY.md).
TRUE_FOR_CORRECT = """import sys
from samplelib import allocate

got = allocate(3)
if len(got) == 3:
    print("DEFECT-OBSERVED")
    sys.exit(0)
sys.exit(1)
"""

NO_REPOSITORY = 'print("DEFECT-OBSERVED")\n'


def _row(text: str, reproducer: str, origin: str = "hunt") -> dict:
    return {"text": text, "class": "broken-length", "files": ["samplelib/__init__.py"],
            "functions": ["samplelib.allocate"], "origin": origin, "candidate_id": "c1", "reproducer": reproducer}


def _run_folder(tmp_path: Path, rows: list[dict], record: dict | None = None) -> Path:
    run = tmp_path / "run"
    (run / "local").mkdir(parents=True)
    (run / "local" / "claims.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    if record is not None:
        (run / RUN_FILE).write_text(json.dumps(record), encoding="utf-8")
    return run


def _fixed_copy(tmp_path: Path) -> Path:
    fixed = tmp_path / "fixed"
    shutil.copytree(FIXTURE, fixed, ignore=shutil.ignore_patterns("__pycache__"))
    module = fixed / "samplelib" / "__init__.py"
    text = module.read_text(encoding="utf-8")
    module.write_text(text.replace("    if n > 0:\n        return [0] * n\n    return [0]", "    return [0] * n"),
                      encoding="utf-8")
    assert "return [0]\n" not in module.read_text(encoding="utf-8")
    return fixed


ROWS = [
    _row("allocate(0) is not empty", ALLOC),
    _row("allocate(3) has length 3", TRUE_FOR_CORRECT, origin="plain"),
    _row("prints the marker without calling anything", NO_REPOSITORY),
]


def test_saved_claims_are_read_back_in_order(tmp_path: Path):
    claims = load_claims(_run_folder(tmp_path, ROWS))
    assert [claim.text for claim in claims] == [row["text"] for row in ROWS]
    assert claims[0].class_label == "broken-length" and claims[0].functions == ["samplelib.allocate"]
    assert claims[1].origin == "plain" and claims[0].reproducer == ALLOC


def test_a_folder_with_no_claims_file_or_a_broken_line_is_an_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="no local/claims.jsonl"):
        load_claims(tmp_path)
    run = _run_folder(tmp_path, ROWS)
    with (run / "local" / "claims.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"text": "no reproducer"}\n')
    with pytest.raises(ConfigError, match=":4 is not a saved claim"):
        load_claims(run)


def test_against_a_fixed_tree_a_real_defect_is_fixed_and_a_test_true_for_correct_code_still_fires(tmp_path: Path):
    claims = load_claims(_run_folder(tmp_path, ROWS))
    here = Tree(FIXTURE, WHEN, "planted")
    there = Tree(_fixed_copy(tmp_path), WHEN, "fixed")
    verdicts = replay(claims, here, tmp_path / "work", there=there, mode="local")
    assert [verdict.label for verdict in verdicts] == [FIXED_THERE, FIRES_THERE, REFUSED]
    assert verdicts[2].there is None                              # refused here: not run again there
    table = render(verdicts, here, there)
    assert "fixed there: 1, fires there too: 1" in table and "refused: 1" in table
    assert "allocate" not in table.split("\n\n")[1]               # the table names no function or claim text


def test_without_a_second_tree_each_claim_is_confirmed_or_refused(tmp_path: Path):
    claims = load_claims(_run_folder(tmp_path, ROWS))
    verdicts = replay(claims, Tree(FIXTURE, WHEN, "planted"), tmp_path / "work", mode="local")
    assert [verdict.label for verdict in verdicts] == [CONFIRMED, CONFIRMED, REFUSED]


def test_the_command_uses_the_run_record_writes_the_details_and_prints_the_table(tmp_path: Path, monkeypatch, capsys):
    seen = {}

    def on_the_host(claims, checkout, work, *, mode, image, commit_time):        # no Podman in the test
        seen.setdefault("images", []).append(image)
        return iter_confirmations(claims, checkout, work, mode="local", image=image, commit_time=commit_time)

    monkeypatch.setattr(replay_module, "iter_confirmations", on_the_host)
    run = _run_folder(tmp_path, ROWS, {"target": str(FIXTURE), "commit": "", "container_image": "img:recorded"})
    status = main(["replay", str(run), "--local", str(FIXTURE), "--against-local", str(_fixed_copy(tmp_path)),
                   "--config", str(tmp_path / "none.toml")])
    assert status == 0
    assert seen["images"] == ["img:recorded", "img:recorded"]
    assert "fixed there: 1, fires there too: 1" in capsys.readouterr().out
    details = list((run / "local").glob("replay-*.json"))
    assert len(details) == 1
    payload = json.loads(details[0].read_text(encoding="utf-8"))
    assert [item["verdict"] for item in payload["claims"]] == [FIXED_THERE, FIRES_THERE, REFUSED]
    assert payload["claims"][0]["there"]["confirmed"] is False


def test_an_old_run_with_no_record_needs_a_target(tmp_path: Path, capsys):
    run = _run_folder(tmp_path, ROWS)
    assert load_record(run) == {}
    assert main(["replay", str(run)]) == 2
    assert "pass the URL and --commit, or --local" in capsys.readouterr().err


def test_replay_never_imports_the_model_client():
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r})\n"
        "import alien_hunt.cli, alien_hunt.replay\n"
        "assert 'openai' not in sys.modules, 'openai imported'\n"
        "print('clean')\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)
    assert done.stdout.strip() == "clean", done.stderr
