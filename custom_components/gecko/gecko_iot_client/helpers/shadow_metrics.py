"""Read-only extension discovery adapted from @markus-lassfolk's Gecko fork.

Only reported data is used. Calibration/model constants are diagnostics, never
water-quality readings. Unknown fields are opt-in diagnostics and get no guessed
energy classes, setpoint controls, or write commands.
"""

# SPDX-License-Identifier: Apache-2.0
# Extracted from the community HA integration; see ../NOTICE and ../LICENSE-APACHE.

from __future__ import annotations

import math
import re
from typing import Any

KNOWN_ZONE_TYPES = frozenset({"flow", "lighting", "temperatureControl"})
MAX_EXTENSION_METRICS = 192


def _path_segments(path: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", path)
    return [segment for segment in re.split(r"[._-]+", spaced.lower()) if segment]


def is_calibration_path(path: str) -> bool:
    lower = path.lower()
    return any(
        term in lower for term in ("calibrat", "offset", "slope", "mvperph", "mvatph")
    ) or bool({"therm", "thermistor", "beta", "r0", "t0"} & set(_path_segments(path)))


def _sensitive(path: str) -> bool:
    return any(
        term in path.lower()
        for term in (
            "password",
            "secret",
            "token",
            "credential",
            "ssid",
            "email",
            "account",
            "serial",
        )
    )


def extract_extension_metrics(
    state_data: dict[str, Any] | None,
) -> dict[str, float | int]:
    """Bound numeric discovery to reported extensions; exclude primary zones."""
    if not isinstance(state_data, dict):
        return {}
    state = state_data.get("state", state_data)
    if not isinstance(state, dict):
        return {}
    reported = state.get("reported", {})
    if not isinstance(reported, dict):
        return {}
    result = {}

    def walk(value, path, depth=0):
        if depth > 16 or len(result) >= MAX_EXTENSION_METRICS or _sensitive(path):
            return
        if isinstance(value, bool):
            return
        if isinstance(value, (float, int)):
            if math.isfinite(value):
                result[path] = value
        elif isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    walk(child, f"{path}.{key}", depth + 1)

    zones = reported.get("zones", {})
    if isinstance(zones, dict):
        for zone_type, bundle in zones.items():
            if zone_type not in KNOWN_ZONE_TYPES:
                walk(bundle, f"zones.{zone_type}")
    features = reported.get("features", {})
    if isinstance(features, dict):
        for feature, value in features.items():
            if feature != "operationMode":
                walk(value, f"features.{feature}")
    return result


def water_quality_kind(path: str) -> str | None:
    """Identify explicit measured pH/ORP leaves, not arbitrary chemical params."""
    if is_calibration_path(path):
        return None
    segments = _path_segments(path)
    if not segments:
        return None
    leaves = {"value", "reading", "current", "ph", "orp", "redox"}
    if segments[-1] not in leaves:
        return None
    if "ph" in segments:
        return "ph"
    if "orp" in segments or "redox" in segments:
        return "orp"
    return None


def humanize_shadow_path(path: str) -> str:
    words = _path_segments(path)
    aliases = {"ph": "pH", "orp": "ORP", "waterlab": "Waterlab"}
    return " ".join(
        aliases.get(word, word.capitalize())
        for word in words
        if word not in {"features", "zones"}
    )
