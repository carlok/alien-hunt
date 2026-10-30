"""Local scanner commands never request a registry pack."""

from pathlib import Path

from alien_hunt.atoms import extract_atoms, load_mechanisms
from alien_hunt.scanners import semgrep_command

FIXTURE = Path(__file__).resolve().parents[0] / "fixtures" / "samplelib"


def test_semgrep_command_uses_only_local_rules(tmp_path: Path):
    command = semgrep_command("semgrep", tmp_path)
    config_value = command[command.index("--config") + 1]
    assert config_value.endswith("python.yml")
    assert "auto" not in command
    assert not any(part.startswith(("p/", "r/")) for part in command)
    assert "registry" not in command
    assert str(tmp_path) in command


def test_mechanisms_are_original_and_numerous():
    mechanisms = load_mechanisms()
    assert len(mechanisms) == 62
    assert mechanisms[0].id == "m01"
    texts = [item.text for item in mechanisms]
    assert len(set(texts)) == 62
    blob = "\n".join(texts).lower()
    assert "cwe-" not in blob


def test_fixture_atoms_include_the_planted_pair():
    sources, sinks, invariants, _mechanisms = extract_atoms(FIXTURE)
    source_text = " ".join(item.text for item in sources)
    sink_text = " ".join(item.text for item in sinks)
    invariant_text = " ".join(item.text for item in invariants)
    assert "blob" in source_text and "load_config" in source_text
    assert "n" in source_text and "allocate" in source_text
    assert "pickle.loads" in sink_text
    assert "must be >= 0" in invariant_text
    assert "result length equals" in invariant_text
