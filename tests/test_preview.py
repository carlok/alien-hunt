"""`alien-hunt pool`: the atoms and pairs a run would draw, with no model, no key and no cost."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from alien_hunt.cli import main
from alien_hunt.preview import preview, render

from test_pipeline import FIXTURE

ROOT = Path(__file__).resolve().parents[1]


def test_the_preview_holds_the_planted_pair():
    result = preview(FIXTURE)
    assert result["atoms"]["sources"] >= 2 and result["atoms"]["mechanisms"] == 62
    pairs = {(pair["source"]["text"], pair["other"]["text"]) for pair in result["pairs"]}
    assert any(source == "caller argument n of allocate" and "length equals n" in other for source, other in pairs)
    assert any(source == "caller argument blob of load_config" and other.startswith("pickle") for source, other in pairs)


def test_the_preview_follows_the_seed_and_the_limit():
    assert preview(FIXTURE, seed=3) == preview(FIXTURE, seed=3)
    assert len(preview(FIXTURE, sample_limit=4)["pairs"]) == 1          # a quarter of sample_limit, as in a run
    text = render(preview(FIXTURE), "fixture")
    assert "Pool preview for fixture" in text and "| file | source | sink or invariant |" in text


def test_the_command_prints_a_table_or_json(capsys, tmp_path: Path):
    assert main(["pool", "--local", str(FIXTURE), "--config", str(tmp_path / "none.toml")]) == 0
    assert "caller argument n of allocate" in capsys.readouterr().out
    assert main(["pool", "--local", str(FIXTURE), "--json", "--config", str(tmp_path / "none.toml")]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sample_limit"] == 80 and payload["pairs"]
    assert main(["pool"]) == 2


def test_the_pool_command_never_imports_the_model_client():
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r})\n"
        "import contextlib, io\n"
        "from alien_hunt.cli import main\n"
        f"with contextlib.redirect_stdout(io.StringIO()):\n"
        f"    assert main(['pool', '--local', {str(FIXTURE)!r}, '--config', '/nonexistent.toml']) == 0\n"
        "assert 'openai' not in sys.modules, 'openai imported'\n"
        "print('clean')\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)
    assert done.stdout.strip() == "clean", done.stderr
