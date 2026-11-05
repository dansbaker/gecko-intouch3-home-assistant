"""Shared fixtures for the Gecko integration tests.

The tests run against a real Home Assistant (pytest-homeassistant-custom-component)
and the real gecko_iot_client zone models. Only the network edge is faked:
MqttTransporter and GeckoIotClient are replaced by FakeTransporter and
FakeGeckoClient, which record connect/disconnect and let a test emit the
events a real client would (zone updates, connectivity changes).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko.gecko_iot_client.models.events import EventChannel
from custom_components.gecko.gecko_iot_client.models.zone_parser import (
    ZoneConfigurationParser,
)

pytest_plugins = "pytest_homeassistant_custom_component"

MONITOR_ID = "123456789"

# One spa as the shadow describes it: two pumps, one light, one heater.
ZONES_CONFIG: dict[str, Any] = {
    "flow": {"1": {"name": "Pump 1"}, "2": {"name": "Pump 2"}},
    "lighting": {"1": {"name": "Light 1"}},
    "temperatureControl": {
        "1": {"minTemperatureSetPointC": 15, "maxTemperatureSetPointC": 40}
    },
}


def build_zones(reported: dict[str, Any] | None = None):
    """Build zones the way GeckoIotClient does: parse the configuration, apply state.

    Every call returns NEW zone objects, as a new GeckoIotClient does after a
    reconnect.
    """
    parser = ZoneConfigurationParser()
    zones = parser.parse_zones_configuration(copy.deepcopy(ZONES_CONFIG))
    if reported:
        parser.apply_state_to_zones(
            zones, {"state": {"reported": {"zones": copy.deepcopy(reported)}}}
        )
    return zones


def record_publishes(zones, sink: list) -> None:
    """Route every zone's desired-state publish into `sink`, tagged by zone object."""
    for zone_list in zones.values():
        for zone in zone_list:
            zone.set_publish_callback(
                lambda zone_type, zone_id, updates, _zone=zone: sink.append(
                    (_zone, zone_type, zone_id, updates)
                )
            )


class FakeTransporter:
    """Stands in for MqttTransporter; keeps the refresh callback where the manager reads it."""

    def __init__(self, broker_url: str, monitor_id: str, token_refresh_callback=None):
        self.broker_url = broker_url
        self.monitor_id = monitor_id
        self._token_refresh_callback = token_refresh_callback
        self.configuration_callbacks = []
        self.state_callbacks = []

    def on_configuration_loaded(self, callback):
        self.configuration_callbacks.append(callback)

    def on_state_loaded(self, callback):
        self.state_callbacks.append(callback)

    def on_state_change(self, callback):
        self.state_callbacks.append(callback)


class FakeGeckoClient:
    """Stands in for GeckoIotClient at the network edge."""

    def __init__(self, monitor_id: str, transporter: FakeTransporter, config_timeout=None):
        self.monitor_id = monitor_id
        self.transporter = transporter
        self.connected = False
        self.operation_mode_controller = None
        self.connect_calls = 0
        self.disconnect_calls = 0
        # Zones this client emits during connect(), like a real client does
        # once its configuration and state are loaded.
        self.zones_on_connect = None
        self._zone_callbacks: list[Callable] = []
        self._connectivity_callbacks: list[Callable] = []
        self._operation_mode_callbacks: list[Callable] = []

    # --- the surface the integration uses ---------------------------------
    def on_zone_update(self, callback: Callable) -> None:
        self._zone_callbacks.append(callback)

    def on(self, channel, callback: Callable) -> None:
        if channel == EventChannel.CONNECTIVITY_UPDATE:
            self._connectivity_callbacks.append(callback)

        elif channel == EventChannel.OPERATION_MODE_UPDATE:
            self._operation_mode_callbacks.append(callback)

    def get_zones(self):
        return self.zones_on_connect or {}

    def off(self, channel, callback: Callable) -> None:
        if channel == EventChannel.CONNECTIVITY_UPDATE and callback in self._connectivity_callbacks:
            self._connectivity_callbacks.remove(callback)

    def connect(self) -> None:
        self.connect_calls += 1
        self.connected = True
        self.emit_connectivity(True)
        if self.zones_on_connect is not None:
            self.emit_zones(self.zones_on_connect)

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.connected = False

    @property
    def is_connected(self) -> bool:
        return self.connected

    # --- what a test drives -----------------------------------------------
    def emit_zones(self, zones) -> None:
        for callback in list(self._zone_callbacks):
            callback(zones)

    def emit_connectivity(self, transport_connected: bool) -> None:
        self.connected = transport_connected
        status = SimpleNamespace(
            transport_connected=transport_connected,
            is_fully_connected=transport_connected,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        for callback in list(self._connectivity_callbacks):
            callback(status)


class FakeNetwork:
    """Every client connection_manager creates, in order, and what the next one emits."""

    def __init__(self) -> None:
        self.clients: list[FakeGeckoClient] = []
        # Zones the NEXT client created will emit during connect(); None = nothing.
        self.next_zones_on_connect = None

    def make_client(self, monitor_id, transporter, config_timeout=None) -> FakeGeckoClient:
        client = FakeGeckoClient(monitor_id, transporter, config_timeout)
        client.zones_on_connect = self.next_zones_on_connect
        self.next_zones_on_connect = None
        self.clients.append(client)
        return client


@pytest.fixture
def network(monkeypatch) -> FakeNetwork:
    """Replace the network edge in connection_manager with fakes."""
    from custom_components.gecko import connection_manager

    fake = FakeNetwork()
    monkeypatch.setattr(connection_manager, "MqttTransporter", FakeTransporter)
    monkeypatch.setattr(connection_manager, "GeckoIotClient", fake.make_client)
    monkeypatch.setattr(connection_manager, "ensure_aws_crt_compatible", lambda: None)
    monkeypatch.setattr(connection_manager, "RECONNECT_DELAY", 0)
    monkeypatch.setattr(connection_manager, "TOKEN_REFRESH_DELAY", 0)
    return fake


@pytest.fixture
def account(hass, enable_custom_integrations, network):
    hass.config.components.add("my")
    network.next_zones_on_connect = build_zones(
        {
            "flow": {"1": {"active": False, "speed": 50}},
            "lighting": {"1": {"active": False}},
            "temperatureControl": {
                "1": {"temperature_": 30, "setPoint": 35, "status_": 0}
            },
        }
    )
    entry = MockConfigEntry(
        domain="gecko",
        data={
            "account_id": "account",
            "auth_implementation": "gecko",
            "token": {
                "access_token": "access",
                "refresh_token": "refresh",
                "expires_at": 9999999999,
            },
            "vessels": [{"vesselId": "spa", "monitorId": "monitor", "name": "Spa"}],
        },
    )
    entry.add_to_hass(hass)
    return entry


@pytest.fixture
def cloud():
    with (
        patch(
            "custom_components.gecko.config_entry_oauth2_flow.async_get_config_entry_implementation",
            AsyncMock(return_value=Mock()),
        ),
        patch("custom_components.gecko.config_entry_oauth2_flow.OAuth2Session"),
        patch("custom_components.gecko.OAuthGeckoApi", autospec=True) as cls,
    ):
        api = cls.return_value
        api.async_get_monitor_livestream.return_value = {
            "brokerUrl": "wss://example.com"
        }
        api.async_get_vessel_detail.return_value = {}
        yield api
