"""Verify the folder HACS installs contains a single usable client runtime."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[1]


class BundledClientTests(unittest.TestCase):
    def test_hacs_folder_imports_without_standalone_client(self):
        """Import the deployment folder outside the checkout, without a wheel."""
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            shutil.copytree(
                ROOT / "custom_components" / "gecko",
                stage / "custom_components" / "gecko",
                ignore=shutil.ignore_patterns("__pycache__", ".env"),
            )
            result = subprocess.run(
                [sys.executable, "-c", """
import importlib.util
from pathlib import Path
assert importlib.util.find_spec('gecko_iot_client') is None
from custom_components.gecko import api, climate, connection_manager, coordinator, fan, light
from custom_components.gecko import gecko_iot_client as client
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType
assert api.GeckoApiClient is client.GeckoApiClient
assert connection_manager.GeckoIotClient is client.GeckoIotClient
for module in (climate, coordinator, fan, light):
    assert module.ZoneType is ZoneType
assert Path(client.__file__).is_relative_to(Path.cwd())
assert Path(client.__file__).with_name('LICENSE').is_file()
assert client.__version__ == '1.0.3+bundled'
"""],
                cwd=stage,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manifest_requires_no_separate_gecko_package(self):
        manifest = json.loads(
            (ROOT / "custom_components" / "gecko" / "manifest.json").read_text()
        )
        self.assertFalse(
            any(requirement.startswith("gecko-iot-client") for requirement in manifest["requirements"])
        )
