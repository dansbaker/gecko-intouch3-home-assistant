"""Read-only Waterlab reading extraction, adapted from @markus-lassfolk.

Only actual reading values are exposed; calibration settings and cloud dosing
instructions never become measurements or commands.
"""

# SPDX-License-Identifier: Apache-2.0
# Extracted from the community HA integration; see ../NOTICE and ../LICENSE-APACHE.

from __future__ import annotations

import math
from typing import Any


def _number(value):
    return (
        value
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        else None
    )


def extract_readings(payload: Any) -> dict[str, dict]:
    """Extract bounded chemistry records from the v6 vessel response."""
    if not isinstance(payload, dict):
        return {}
    status = payload.get("status")
    status = status if isinstance(status, dict) else {}
    result = {}
    allowed = {
        "ph",
        "orp",
        "waterTemp",
        "alkalinity",
        "chlorine",
        "bromine",
        "hardness",
        "cyanuricAcid",
        "freeChlorine",
        "totalChlorine",
    }
    for root in (payload, status):
        for collection in (
            "readings",
            "monitorReadings",
            "reportReadings",
            "computedReadings",
        ):
            records = root.get(collection)
            if not isinstance(records, dict):
                continue
            for key, record in records.items():
                if key not in allowed or not isinstance(record, dict):
                    continue
                value = _number(record.get("value"))
                if value is None or (key == "ph" and not 0 <= value <= 14):
                    continue
                metadata = {
                    name: item[:255]
                    for name in (
                        "title",
                        "unit",
                        "status",
                        "source",
                        "updatedAt",
                        "lastUpdated",
                        "readingType",
                    )
                    if isinstance((item := record.get(name)), str)
                }
                result[key] = {**metadata, "value": value}
    disc = status.get("discElements", status.get("disc_elements", {}))
    disc = disc if isinstance(disc, dict) else {}
    for key, aliases, leaves in (
        ("ph", ("phStatus", "ph_status"), ("value", "ph", "reading", "current")),
        (
            "orp",
            ("orpStatus", "orp_status"),
            ("value", "orp", "reading", "current", "mv"),
        ),
    ):
        if key in result:
            continue
        for source in (disc, status):
            for alias in aliases:
                record = source.get(alias)
                candidates = (
                    [record.get(leaf) for leaf in leaves]
                    if isinstance(record, dict)
                    else [record]
                )
                value = next(
                    (
                        n
                        for candidate in candidates
                        if (n := _number(candidate)) is not None
                    ),
                    None,
                )
                if value is not None and (key != "ph" or 0 <= value <= 14):
                    result[key] = {
                        "value": value,
                        "source": "Gecko cloud summary",
                        "unit": "pH" if key == "ph" else "mV",
                    }
                    break
            if key in result:
                break
    return result
