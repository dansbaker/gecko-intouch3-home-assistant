"""Measurement age and shareable metadata must not imply live probe readings."""

from datetime import datetime, timezone
import json

import pytest

from custom_components.gecko.gecko_iot_client.helpers.waterlab import (
    measurement_freshness,
    reading_diagnostics,
)

NOW = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"updatedAt": "PRIVATE"},
        {"updatedAt": 42},
        {"updatedAt": "2026-11-06T10:00:00"},
        {"updatedAt": "999999999-01-01"},
    ],
)
def test_missing_or_invalid_time_is_unknown(record):
    assert measurement_freshness(record, NOW) == {"measurement_time_status": "unknown"}


def test_measurement_time_fallback_offset_and_clock_skew():
    result = measurement_freshness(
        {"updatedAt": "bad", "lastUpdated": "2026-11-06T12:00:00+01:00"}, NOW
    )
    assert result["measurement_age_seconds"] == 3600
    assert result["measurement_time_status"] == "known"
    future = measurement_freshness({"updatedAt": "2026-11-07T12:00:00Z"}, NOW)
    assert future["measurement_age_seconds"] == 0
    assert future["measurement_time_status"] == "future"


def test_diagnostics_allowlist_rejects_identity_and_arbitrary_text():
    readings = {
        "ph": {
            "value": 7.4,
            "unit": "pH",
            "source": "monitor",
            "status": "normal",
            "updatedAt": "2026-11-06T11:00:00Z",
            "token": "PRIVATE",
        },
        "orp": {
            "source": "PRIVATE",
            "unit": "PRIVATE",
            "status": "PRIVATE",
            "lastUpdated": "PRIVATE",
        },
        "PRIVATE": {"value": 1},
        "chlorine": None,
        "bromine": {"source": 1},
    }
    result = reading_diagnostics(readings, NOW)
    assert "PRIVATE" not in json.dumps(result)
    ph = next(item for item in result if item["type"] == "ph")
    assert ph["measurement_age_seconds"] == 3600
    assert ph["source"] == "monitor"
    assert "value" not in ph
    orp = next(item for item in result if item["type"] == "orp")
    assert orp["source"] == "unrecognized"


def test_sensor_reports_measurement_age_independently_of_poll_time():
    from types import SimpleNamespace
    from custom_components.gecko.sensor import GeckoWaterlabSensor

    coordinator = SimpleNamespace(
        entry_id="entry",
        vessel_id="vessel",
        waterlab_readings={"ph": {"value": 7.4, "updatedAt": "2020-01-01T00:00:00Z"}},
        waterlab_last_success="2026-11-06T12:00:00Z",
    )
    sensor = GeckoWaterlabSensor(coordinator, "ph")
    attributes = sensor.extra_state_attributes
    assert attributes["measurement_age_seconds"] > 86400
    assert attributes["last_successful_poll"] == coordinator.waterlab_last_success
