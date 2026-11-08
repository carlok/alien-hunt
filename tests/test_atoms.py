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


def test_atoms_record_the_function_they_sit_in(tmp_path: Path):
    (tmp_path / "dir_a").mkdir()
    (tmp_path / "dir_a" / "mod_a.py").write_text(
        "import pickle\n"
        "import os\n"
        "ENV_X = os.environ['ENV_X']\n"
        "\n"
        "def fn_one(arg_a):\n"
        "    def fn_two(arg_b):\n"
        "        return pickle.loads(arg_b)\n"
        "    return fn_two(arg_a)\n"
        "\n"
        "class Klass:\n"
        "    def method_a(self, arg_c):\n"
        '        """The value must be positive."""\n'
        "        return arg_c * 2\n",
        encoding="utf-8",
    )
    sources, sinks, invariants, _mechanisms = extract_atoms(tmp_path)
    source_scope = {atom.text: atom.scope for atom in sources}
    assert source_scope["caller argument arg_a of fn_one"] == "fn_one"
    assert source_scope["caller argument arg_b of fn_two"] == "fn_one.fn_two"
    assert source_scope["caller argument arg_c of method_a"] == "Klass.method_a"
    assert source_scope["environment variable read in dir_a/mod_a.py"] is None         # module level
    sink_scope = {atom.function: atom.scope for atom in sinks}
    assert sink_scope["pickle.loads"] == "fn_one.fn_two"                               # the callee is named, the scope is its caller
    assert sink_scope["multiplication"] == "Klass.method_a"
    assert [atom.scope for atom in invariants] == ["Klass.method_a"]
