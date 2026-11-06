"""Shareable diagnostics must never expose identity, raw data or error strings."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko.connection_manager import (
    GECKO_CONNECTION_MANAGER_KEY,
    GeckoMonitorConnection,
)
from custom_components.gecko.coordinator import GeckoVesselCoordinator
from custom_components.gecko.diagnostics import async_get_config_entry_diagnostics
from custom_components.gecko.gecko_iot_client import GeckoIotClient
from custom_components.gecko.gecko_iot_client.models.connectivity import (
    ConnectivityStatus,
)
from custom_components.gecko.gecko_iot_client.models.zone_parser import (
    ZoneConfigurationParser,
)
from custom_components.gecko.gecko_iot_client.transporters import AbstractTransporter


@pytest.fixture
def device():
    client = GeckoIotClient("PRIVATE-DEVICE-ID", Mock(spec=AbstractTransporter))
    parser = ZoneConfigurationParser()
    client._zones = parser.parse_zones_configuration(
        {
            "flow": {
                str(n): {
                    "name": "PRIVATE-NAME",
                    "speed": {"minimum": 50, "maximum": 100, "stepIncrement": 50},
                }
                for n in range(1, 4)
            },
            "lighting": {"1": {"name": "PRIVATE-LIGHT", "effect": "PRIVATE-EFFECT"}},
            "temperatureControl": {
                "1": {
                    "name": "PRIVATE-TEMP",
                    "minTemperatureSetPointC": 10,
                    "maxTemperatureSetPointC": 40,
                }
            },
        }
    )
    parser.apply_state_to_zones(
        client._zones,
        {
            "state": {
                "reported": {
                    "zones": {
                        "flow": {"1": {"active": True, "speed": 99}},
                        "lighting": {"1": {"active": False}},
                        "temperatureControl": {
                            "1": {"temperature_": 30, "setPoint": 37, "status_": 0}
                        },
                    }
                }
            }
        },
    )
    client._configuration = {"secret": "PRIVATE-TOKEN"}
    client._state = {"private": "PRIVATE-RAW-PAYLOAD"}
    client._connectivity_status = ConnectivityStatus(True, "CONNECTED", "RUNNING")
    return client


async def test_no_runtime_diagnostics_are_safe_and_do_not_create_manager(hass):
    entry = MockConfigEntry(
        domain="gecko", title="PRIVATE-TITLE", data={"token": "PRIVATE-TOKEN"}
    )
    entry.add_to_hass(hass)
    before = set(hass.data)
    result = await async_get_config_entry_diagnostics(hass, entry)
    assert not result["runtime_loaded"]
    assert result["connections"] == {}
    assert result["coordinators"] == []
    assert set(hass.data) == before
    assert "PRIVATE" not in json.dumps(result)


async def test_runtime_snapshot_is_useful_scoped_and_identity_free(hass, device):
    entry = MockConfigEntry(domain="gecko", title="PRIVATE-TITLE", data={})
    entry.add_to_hass(hass)
    coord = GeckoVesselCoordinator(
        hass, entry.entry_id, "PRIVATE-VESSEL", "PRIVATE-MONITOR", "PRIVATE-NAME"
    )
    coord._zones = device.get_zones()
    coord.waterlab_readings = {
        "ph": {
            "value": 7.4,
            "token": "PRIVATE-TOKEN",
            "unit": "pH",
            "source": "monitor",
            "status": "normal",
            "updatedAt": "2026-11-05T12:00:00Z",
        }
    }
    entry.runtime_data = SimpleNamespace(coordinators=[coord])
    connection = GeckoMonitorConnection(
        "PRIVATE-MONITOR", device, "wss://PRIVATE-TOKEN", "PRIVATE-NAME"
    )
    connection.is_connected = True
    other = Mock()
    manager = Mock()
    manager.get_connection.side_effect = lambda monitor: (
        connection if monitor == "PRIVATE-MONITOR" else other
    )
    hass.data[GECKO_CONNECTION_MANAGER_KEY] = manager
    result = await async_get_config_entry_diagnostics(hass, entry)
    manager.get_connection.assert_called_once_with("PRIVATE-MONITOR")
    assert result["coordinators"][0]["zone_counts"]["flow"] == 3
    assert result["coordinators"][0]["waterlab"]["reading_count"] == 1
    reading = result["coordinators"][0]["waterlab"]["readings"][0]
    assert reading["type"] == "ph"
    assert reading["source"] == "monitor"
    assert reading["measurement_timestamp"] == "2026-11-05T12:00:00+00:00"
    assert "value" not in reading
    snap = result["connections"]["vessel_1"]["client"]
    assert snap["zones"]["flow"]["samples"][0]["speed_config"] == {
        "minimum": 50,
        "maximum": 100,
        "stepIncrement": 50,
    }
    assert snap["zones"]["flow"]["samples"][0]["speed"] == 99
    assert snap["zones"]["temperatureControl"]["samples"][0]["target_temperature"] == 37
    assert snap["connectivity"]["is_fully_connected"]
    assert "PRIVATE" not in json.dumps(result, allow_nan=False)
    assert device.id == "PRIVATE-DEVICE-ID"  # Redaction must not mutate live objects.


@pytest.mark.parametrize("present", [False, True])
async def test_missing_or_disposed_client_is_reportable(hass, present):
    entry = MockConfigEntry(domain="gecko", data={})
    entry.add_to_hass(hass)
    coord = GeckoVesselCoordinator(hass, entry.entry_id, "vessel", "monitor", "Spa")
    entry.runtime_data = SimpleNamespace(coordinators=[coord])
    client = Mock() if present else None
    if client:
        client.diagnostic_snapshot.side_effect = RuntimeError("https://PRIVATE-TOKEN")
    connection = GeckoMonitorConnection(
        "monitor", client, "PRIVATE-URL", "PRIVATE-NAME"
    )
    manager = Mock()
    manager.get_connection.return_value = connection
    hass.data[GECKO_CONNECTION_MANAGER_KEY] = manager
    result = await async_get_config_entry_diagnostics(hass, entry)
    if present:
        assert result["connections"]["vessel_1"]["client"] == {
            "status": "snapshot_unavailable"
        }
    else:
        assert "client" not in result["connections"]["vessel_1"]
    assert "PRIVATE" not in json.dumps(result)


async def test_runtime_with_no_manager_or_no_connection(hass):
    entry = MockConfigEntry(domain="gecko", data={})
    entry.add_to_hass(hass)
    coord = GeckoVesselCoordinator(hass, entry.entry_id, "vessel", "monitor", "Spa")
    entry.runtime_data = SimpleNamespace(coordinators=[coord])
    assert (await async_get_config_entry_diagnostics(hass, entry))["connections"] == {}
    manager = Mock()
    manager.get_connection.return_value = None
    hass.data[GECKO_CONNECTION_MANAGER_KEY] = manager
    assert (await async_get_config_entry_diagnostics(hass, entry))["connections"] == {}
