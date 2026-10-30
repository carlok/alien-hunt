"""The third live run (PyJWT, 2026-10-30): the hunt's two claims were CVE-2022-29217, and both stopped on `import
cryptography`, an optional extra nothing installed. A replay with cryptography 35.0.0, cffi 1.15.0 and pycparser 2.20
(the newest before the commit) confirmed both. These tests pin the fixes, offline, against a fake package index."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from alien_hunt.confirm import (
    podman_pip_argv,
    prepare_wheels,
    reproducer_imports,
    resolve_wheels,
    wheel_compatible,
    wheel_requires,
)

COMMIT = datetime(2021, 10, 16, 15, 46, 5, tzinfo=timezone.utc)


def test_the_wheel_filter_takes_abi3_and_refuses_musl():
    ok = [
        "cryptography-35.0.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "cffi-1.15.0-cp310-cp310-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "pycparser-2.20-py2.py3-none-any.whl",
    ]
    no = [
        "cryptography-35.0.0-cp36-abi3-musllinux_1_1_aarch64.whl",          # the container is Debian
        "cryptography-42.0.0-cp311-abi3-manylinux_2_28_aarch64.whl",        # stable ABI from a later Python
        "cffi-1.15.0-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "cffi-1.15.0-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "cffi-1.15.0-cp310-cp310-macosx_11_0_arm64.whl",
    ]
    assert all(wheel_compatible(name, "cp310", "aarch64") for name in ok)
    assert not any(wheel_compatible(name, "cp310", "aarch64") for name in no)


def test_the_reproducers_third_party_imports_are_found():
    sources = [
        "import sys\nimport jwt\nfrom cryptography.hazmat.primitives import serialization\n",
        "import json, yaml\nfrom . import local\nimport _private\n",
        "this is not python (",
    ]
    assert reproducer_imports(sources, {"jwt"}) == ["cryptography", "yaml"]


def wheel(name: str, version: str, filename: str, when: str) -> dict:
    return {"filename": filename, "version": version, "packagetype": "bdist_wheel", "upload_time_iso_8601": when,
            "url": f"https://files.example/{filename}"}


INDEX = {
    "cryptography": [
        wheel("cryptography", "35.0.0", "cryptography-35.0.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "2021-09-30T10:00:00Z"),
        wheel("cryptography", "35.0.0", "cryptography-35.0.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", "2021-09-30T10:00:00Z"),
        wheel("cryptography", "36.0.0", "cryptography-36.0.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", "2021-11-21T10:00:00Z"),
    ],
    "cffi": [
        wheel("cffi", "1.15.0", "cffi-1.15.0-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "2021-10-13T10:00:00Z"),
        wheel("cffi", "1.15.0", "cffi-1.15.0-cp310-cp310-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", "2021-10-13T10:00:00Z"),
    ],
    "pycparser": [wheel("pycparser", "2.20", "pycparser-2.20-py2.py3-none-any.whl", "2020-03-04T10:00:00Z")],
}
REQUIRES = {
    ("cryptography", "35.0.0"): ["cffi>=1.12", "pytest>=6.2.0; extra == 'test'", "pywin32; sys_platform == 'win32'"],
    ("cffi", "1.15.0"): ["pycparser"],
    ("pycparser", "2.20"): [],
}


def fetch(name: str) -> list[dict]:
    if name not in INDEX:
        raise OSError("404")
    return INDEX[name]


def fetch_requires(name: str, version: str) -> list[str]:
    return REQUIRES.get((name, version), [])


def test_the_closure_is_resolved_as_of_the_commit_date():
    chosen, missing = resolve_wheels([("cryptography", None), ("nosuchpkg", None)], COMMIT, arch="aarch64",
                                     fetch=fetch, requires=lambda item: fetch_requires(item["name"], item["version"]))
    assert [(item["name"], item["version"]) for item in chosen] == [("cryptography", "35.0.0"), ("cffi", "1.15.0"),
                                                                    ("pycparser", "2.20")]
    assert missing == ["nosuchpkg"]                       # pytest (an extra) and pywin32 (Windows) were never asked for


def test_prepare_wheels_adds_the_imports_and_says_what_it_could_not_find(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("alien_hunt.confirm.linux_arch", lambda: "aarch64")
    root = tmp_path / "repo"
    root.mkdir()
    got: list[str] = []
    status = prepare_wheels(root, COMMIT, tmp_path / "work", imports=["cryptography", "yaml"], fetch=fetch,
                            fetch_requires=fetch_requires, download=lambda link, dest: got.append(Path(dest).name))
    assert status.ok and status.target is not None
    assert "PyYAML" in status.why                          # yaml maps to PyYAML, which this fake index lacks
    requirements = (tmp_path / "work" / "requirements.txt").read_text(encoding="utf-8").split()
    assert requirements == ["cryptography", "cffi", "pycparser"]
    assert all("aarch64" in name or "none-any" in name for name in got)


def test_nothing_to_install_when_nothing_is_needed(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    assert prepare_wheels(root, COMMIT, tmp_path / "work", imports=[]).why == "no third-party dependencies"


def test_pip_installs_exactly_the_resolved_wheels():
    argv = podman_pip_argv("python:3.10-slim", Path("/w"), Path("/d"), Path("/r/requirements.txt"))
    assert "--no-deps" in argv and "--no-index" in argv


def test_a_wheels_own_metadata_gives_its_requirements(tmp_path: Path):
    """PyPI's JSON says cryptography 35.0.0 requires nothing; its wheel says cffi."""
    import zipfile

    path = tmp_path / "cryptography-35.0.0-cp36-abi3-manylinux2014_aarch64.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("cryptography-35.0.0.dist-info/METADATA",
                         "Metadata-Version: 2.1\nName: cryptography\nRequires-Dist: cffi (>=1.12)\n"
                         "Requires-Dist: pytest (>=6.2.0) ; extra == 'test'\n\nbody\n")
        archive.writestr("cryptography/vendor/x.dist-info/METADATA", "Requires-Dist: nested-should-not-count\n")
    assert wheel_requires(path) == ["cffi (>=1.12)", "pytest (>=6.2.0) ; extra == 'test'"]
    assert wheel_requires(tmp_path / "missing.whl") == []


def test_prepare_wheels_reads_the_downloaded_wheels_requirements(tmp_path: Path, monkeypatch):
    import zipfile

    monkeypatch.setattr("alien_hunt.confirm.linux_arch", lambda: "aarch64")

    def download(link: str, dest) -> None:
        name = Path(dest).name.split("-")[0]
        with zipfile.ZipFile(dest, "w") as archive:
            needs = {"cryptography": "Requires-Dist: cffi (>=1.12)\n", "cffi": "Requires-Dist: pycparser\n"}.get(name, "")
            archive.writestr(f"{name}-0.dist-info/METADATA", "Name: " + name + "\n" + needs)

    root = tmp_path / "repo"
    root.mkdir()
    status = prepare_wheels(root, COMMIT, tmp_path / "work", imports=["cryptography"], fetch=fetch,
                            fetch_requires=lambda name, version: [], download=download)
    assert status.ok and status.why == "wheels downloaded"
    assert (tmp_path / "work" / "requirements.txt").read_text(encoding="utf-8").split() == ["cryptography", "cffi", "pycparser"]
