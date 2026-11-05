"""Bounded public snapshots expose modeled data, never raw identity-bearing fields."""

import json
from unittest.mock import Mock

import pytest

from custom_components.gecko.gecko_iot_client import GeckoIotClient
from custom_components.gecko.gecko_iot_client.models.operation_mode import OperationMode
from custom_components.gecko.gecko_iot_client.models.zone_types import (
    FlowZone,
    LightingZone,
    TemperatureControlZone,
    ZoneType,
)
from custom_components.gecko.gecko_iot_client.transporters import AbstractTransporter


def client():
    return GeckoIotClient("PRIVATE-ID", Mock(spec=AbstractTransporter))


def test_empty_client_snapshot_needs_no_network_or_identity():
    c = client()
    c._operation_mode_controller = None
    snap = c.diagnostic_snapshot()
    assert not snap["has_configuration"]
    assert not snap["has_state"]
    assert snap["operation_mode"] is None
    assert snap["zones"] == {}
    assert snap["connectivity"]["gateway_status"] == "UNKNOWN"
    assert "PRIVATE" not in json.dumps(snap)
    c.transporter.connect.assert_not_called()


@pytest.mark.parametrize(
    "speed", [None, True, "PRIVATE", float("nan"), float("inf"), 10**1000]
)
def test_invalid_numeric_fields_are_not_serialized(speed):
    c = client()
    pump = FlowZone("PRIVATE-ID", {})
    pump.speed = speed
    pump.active = "PRIVATE-ACTIVE"
    c._zones = {ZoneType.FLOW_ZONE: [pump]}
    snap = c.diagnostic_snapshot()
    assert snap["zones"]["flow"]["samples"][0]["speed"] is None
    assert snap["zones"]["flow"]["samples"][0]["active"] is None
    assert "PRIVATE" not in json.dumps(snap, allow_nan=False)


def test_snapshot_is_bounded_and_unknown_keys_never_escape():
    c = client()
    c._zones = {
        ZoneType.FLOW_ZONE: [FlowZone("PRIVATE-ID", {})] * 130,
        "PRIVATE-KEY": [{"token": "PRIVATE-TOKEN"}],
    }
    snap = c.diagnostic_snapshot()
    assert snap["zones"]["flow"]["count"] == 130
    assert len(snap["zones"]["flow"]["samples"]) == 128
    assert snap["zones"]["flow"]["truncated"]
    assert "PRIVATE" not in json.dumps(snap)


def test_unknown_status_and_partial_zone_state_are_safe():
    c = client()
    c._connectivity_status.gateway_status = "PRIVATE-TOKEN"
    c._connectivity_status.vessel_status = "PRIVATE-TOKEN"
    c._operation_mode_controller.operation_mode = OperationMode.AWAY
    temp = TemperatureControlZone("PRIVATE-TEMP", {})
    c._zones = {
        ZoneType.LIGHTING_ZONE: [LightingZone("PRIVATE-LIGHT", {})],
        ZoneType.TEMPERATURE_CONTROL_ZONE: [temp],
        ZoneType.FLOW_ZONE: [object()],
    }
    snap = c.diagnostic_snapshot()
    assert snap["connectivity"]["gateway_status"] == "OTHER"
    assert snap["connectivity"]["vessel_status"] == "OTHER"
    assert snap["operation_mode"] == 0
    assert snap["zones"]["temperatureControl"]["samples"][0]["status"] is None
    assert not snap["zones"]["lighting"]["samples"][0]["has_effect"]
    assert snap["zones"]["flow"]["samples"] == [{}]
    assert "PRIVATE" not in json.dumps(snap, allow_nan=False)
