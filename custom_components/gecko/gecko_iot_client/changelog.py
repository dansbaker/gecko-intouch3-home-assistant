"""Changelog generation utilities for the Gecko IoT Client."""

import subprocess
import sys
from pathlib import Path


def build_changelog() -> None:
    """Build the changelog from git history using auto-changelog."""
    project_root = Path(__file__).parent.parent.parent.parent

    print(f"Generating changelog from project root: {project_root}")

    try:
        # Use auto-changelog with explicit parameters that work
        result = subprocess.run(
            [
                "auto-changelog",
                "--template",
                "compact",
                "--output",
                "CHANGELOG.md",
                "--unreleased",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=project_root,
        )

        print("Changelog generated successfully!")
        if result.stdout:
            print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error generating changelog: {e}")
        if e.stdout:
            print(f"Stdout: {e.stdout}")
        if e.stderr:
            print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print(
            "auto-changelog not found. Please install it with: pip install auto-changelog"
        )
        sys.exit(1)


if __name__ == "__main__":
    build_changelog()
