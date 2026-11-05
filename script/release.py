"""Publish a versioned HACS release only after CI checks succeed."""

import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components/gecko"


def release_info():
    """Resolve a stable release version and require version-specific notes."""
    manifest = json.loads((COMPONENT / "manifest.json").read_text())
    version = manifest["version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError(
            "Automatic releases require a stable major.minor.patch version"
        )
    if manifest["domain"] != "gecko":
        raise ValueError("The release must retain the gecko integration domain")
    notes = ROOT / "docs/releases" / f"{version}.md"
    if not notes.is_file():
        raise ValueError(f"Release notes are missing for {version}")
    return version, notes


def tag_exists(repository, tag):
    """Treat only a 404 as absence; authentication/network errors must fail CI."""
    request = Request(
        f"https://api.github.com/repos/{repository}/git/ref/tags/{tag}",
        headers={
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urlopen(request, timeout=30):
            return True
    except HTTPError as err:
        if err.code == 404:
            return False
        raise


def build_archive(destination):
    """Package exactly the tracked runtime files, with no tests or caches."""
    tracked = (
        subprocess.check_output(
            ["git", "ls-files", "-z", "custom_components/gecko"], cwd=ROOT
        )
        .decode()
        .split("\0")
    )
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in filter(None, tracked):
            source = ROOT / name
            archive.write(source, str(source.relative_to(COMPONENT)))
    with zipfile.ZipFile(destination) as archive:
        if json.loads(archive.read("manifest.json"))["domain"] != "gecko":
            raise ValueError("Invalid archive root")
        if "gecko_iot_client/__init__.py" not in archive.namelist():
            raise ValueError("The bundled client is missing")


def main():
    """Support CI prepare, gated publish and offline package validation."""
    version, notes = release_info()
    action = sys.argv[1]
    if action == "build":
        destination = Path(sys.argv[2])
        build_archive(destination)
        print(f"Built {destination} for {version}")
        return
    if os.environ.get("GITHUB_REF") != "refs/heads/master":
        raise ValueError("Releases may only be published from master")
    repository = os.environ["GITHUB_REPOSITORY"]
    tag = f"v{version}"
    if action == "prepare":
        publish = not tag_exists(repository, tag)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"version={version}\npublish={str(publish).lower()}\n")
        print(f"{tag}: {'new release' if publish else 'already tagged; no release'}")
    elif action == "publish":
        # A tag that appeared since preparation must not be moved or overwritten.
        if tag_exists(repository, tag):
            print(f"{tag} already exists; leaving it unchanged")
            return
        archive = ROOT / "gecko.zip"
        build_archive(archive)
        subprocess.run(
            [
                "gh",
                "release",
                "create",
                tag,
                str(archive),
                "--repo",
                repository,
                "--target",
                os.environ["GITHUB_SHA"],
                "--title",
                f"Gecko in.touch 3 v{version}",
                "--notes-file",
                str(notes),
                "--latest",
            ],
            check=True,
        )
    else:
        raise ValueError(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
