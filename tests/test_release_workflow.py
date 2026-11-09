"""Release publishing is versioned, complete, gated and never overwrites tags."""

import io
import json
import zipfile
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

from script import release


def test_release_archive_contains_only_runtime_files(tmp_path):
    path = tmp_path / "gecko.zip"
    release.build_archive(path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        assert (
            json.loads(archive.read("manifest.json"))["version"]
            == release.release_info()[0]
        )
        assert "gecko_iot_client/__init__.py" in names
        assert "gecko_iot_client/LICENSE" in names
        assert "gecko_iot_client/NOTICE" in names
        assert "icons.json" in names
        for filename, size in (("icon.png", 256), ("icon@2x.png", 512)):
            image = archive.read(f"brand/{filename}")
            assert image[:8] == b"\x89PNG\r\n\x1a\n"
            assert image[12:16] == b"IHDR"
            assert int.from_bytes(image[16:20], "big") == size
            assert int.from_bytes(image[20:24], "big") == size
        assert not any(
            name.startswith(("tests/", "custom_components/")) or "__pycache__" in name
            for name in names
        )


@pytest.mark.parametrize("version", ["3.0.0.dev1", "v3.0.0", "../3.0.0", "03.0.0"])
def test_invalid_release_versions_fail_before_publication(
    tmp_path, monkeypatch, version
):
    component = tmp_path / "component"
    component.mkdir()
    (component / "manifest.json").write_text(
        json.dumps({"version": version, "domain": "gecko"})
    )
    monkeypatch.setattr(release, "COMPONENT", component)
    with pytest.raises(ValueError, match="major.minor.patch"):
        release.release_info()


@pytest.mark.parametrize(
    "status,absent", [(404, True), (401, False), (403, False), (500, False)]
)
def test_only_missing_tag_is_treated_as_unreleased(monkeypatch, status, absent):
    monkeypatch.setenv("GH_TOKEN", "test-token")
    failure = HTTPError("https://example.test", status, "failure", {}, io.BytesIO())
    monkeypatch.setattr(release, "urlopen", Mock(side_effect=failure))
    if absent:
        assert release.tag_exists("owner/repo", "v3.0.0") is False
    else:
        with pytest.raises(HTTPError):
            release.tag_exists("owner/repo", "v3.0.0")


@pytest.mark.parametrize(
    "branch",
    ["refs/heads/restore/official-base", "refs/pull/1/merge", "refs/tags/v3.0.0"],
)
def test_non_master_runs_cannot_publish(monkeypatch, branch):
    monkeypatch.setenv("GITHUB_REF", branch)
    monkeypatch.setattr(release.sys, "argv", ["release.py", "publish"])
    publish = Mock()
    monkeypatch.setattr(release.subprocess, "run", publish)
    with pytest.raises(ValueError, match="only be published from master"):
        release.main()
    publish.assert_not_called()


def test_existing_tag_is_never_republished(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/master")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setattr(release.sys, "argv", ["release.py", "publish"])
    monkeypatch.setattr(release, "tag_exists", Mock(return_value=True))
    publish = Mock()
    monkeypatch.setattr(release.subprocess, "run", publish)
    release.main()
    publish.assert_not_called()


def test_prepare_emits_version_and_publish_decision(tmp_path, monkeypatch):
    output = tmp_path / "output"
    monkeypatch.setenv("GITHUB_REF", "refs/heads/master")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(release.sys, "argv", ["release.py", "prepare"])
    monkeypatch.setattr(release, "tag_exists", Mock(return_value=False))
    monkeypatch.setattr(
        release, "release_info", Mock(return_value=("4.5.6", tmp_path / "notes.md"))
    )
    release.main()
    assert output.read_text() == "version=4.5.6\npublish=true\n"


def test_publish_targets_exact_checked_commit(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/master")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "checked-commit-sha")
    monkeypatch.setattr(release.sys, "argv", ["release.py", "publish"])
    monkeypatch.setattr(release, "tag_exists", Mock(return_value=False))
    notes = tmp_path / "notes.md"
    monkeypatch.setattr(release, "release_info", Mock(return_value=("3.0.0", notes)))
    monkeypatch.setattr(release, "ROOT", tmp_path)
    build = Mock()
    monkeypatch.setattr(release, "build_archive", build)
    publish = Mock()
    monkeypatch.setattr(release.subprocess, "run", publish)
    release.main()
    build.assert_called_once_with(tmp_path / "gecko.zip")
    args = publish.call_args.args[0]
    assert args[args.index("--target") + 1] == "checked-commit-sha"
    assert args[3] == "v3.0.0"
    assert "--latest" in args
