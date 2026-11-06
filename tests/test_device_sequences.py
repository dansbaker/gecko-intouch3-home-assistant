"""Replay provenance-labelled protocol sequences through the production parser."""

import json
from pathlib import Path

import pytest

from custom_components.gecko.gecko_iot_client.models.zone_parser import (
    ZoneConfigurationParser,
)
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType


@pytest.mark.parametrize(
    "path",
    sorted((Path(__file__).parent / "fixtures/device_sequences").glob("*.json")),
    ids=lambda path: path.stem,
)
def test_device_sequence(path):
    recording = json.loads(path.read_text())
    assert recording["provenance"]["evidence"]
    parser = ZoneConfigurationParser()
    zones = None
    for event in recording["events"]:
        if "configuration" in event:
            zones = parser.parse_zones_configuration(event["configuration"])
        if "reported" in event:
            assert zones is not None
            parser.apply_state_to_zones(
                zones, {"state": {"reported": {"zones": event["reported"]}}}
            )
            pump = zones[ZoneType.FLOW_ZONE][0]
            expected = event["expected"]
            assert pump.active == expected["active"]
            assert pump.speed == expected["speed"]
            assert pump.speed_config["maximum"] == expected["maximum"]
            if "count" in expected:
                assert len(zones[ZoneType.FLOW_ZONE]) == expected["count"]
                assert [
                    zone.speed for zone in zones[ZoneType.FLOW_ZONE][1:]
                ] == expected["other_speeds"]


@pytest.mark.parametrize(
    "path",
    sorted(
        (Path(__file__).parent / "fixtures/device_sequences/waterlab").glob("*.json")
    ),
    ids=lambda path: path.stem,
)
def test_cloud_reading_sequence(path):
    from datetime import datetime, timezone
    from custom_components.gecko.gecko_iot_client.helpers.waterlab import (
        extract_readings,
        measurement_freshness,
    )

    recording = json.loads(path.read_text())
    assert recording["provenance"]["evidence"]
    now = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)
    for event in recording["events"]:
        readings = extract_readings(event["payload"])
        assert sorted(readings) == event["expected_keys"]
        if "expected_ph" in event:
            assert readings["ph"]["value"] == event["expected_ph"]
            assert (
                measurement_freshness(readings["ph"], now)["measurement_age_seconds"]
                == event["expected_age_seconds"]
            )
