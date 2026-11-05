"""Use real HA config-entry and platform setup with only network edges replaced."""

from unittest.mock import AsyncMock, Mock, patch

import pytest
from aiohttp import ClientResponseError
from homeassistant.config_entries import ConfigEntryState
from homeassistant.helpers import entity_registry as er

from custom_components.gecko.connection_manager import GECKO_CONNECTION_MANAGER_KEY

from .conftest import build_zones


async def test_setup_unload_and_reload_without_restart(hass, account, cloud, network):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    assert account.state is ConfigEntryState.LOADED
    assert hass.states.get("fan.spa_pump_1") is not None
    first = network.clients[0]
    runtime = account.runtime_data
    assert await hass.config_entries.async_unload(account.entry_id)
    assert first.disconnect_calls == 1
    assert getattr(account, "runtime_data", None) is None
    assert not hass.data[GECKO_CONNECTION_MANAGER_KEY]._connections
    assert hass.states.get("fan.spa_pump_1").state == "unavailable"
    assert hass.states.get("fan.spa_pump_1").attributes["restored"] is True
    assert runtime.coordinators[0]._shutdown_requested
    network.next_zones_on_connect = build_zones(
        {"flow": {"1": {"active": True, "speed": 50}}}
    )
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    assert network.clients[-1] is not first
    assert await hass.config_entries.async_unload(account.entry_id)


async def test_failed_unload_keeps_live_runtime(hass, account, cloud, network):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    runtime = account.runtime_data
    with patch.object(
        hass.config_entries, "async_unload_platforms", AsyncMock(return_value=False)
    ):
        from custom_components.gecko import async_unload_entry

        assert not await async_unload_entry(hass, account)
    assert account.runtime_data is runtime
    assert network.clients[0].disconnect_calls == 0
    assert not runtime.coordinators[0]._shutdown_requested
    assert await hass.config_entries.async_unload(account.entry_id)


@pytest.mark.parametrize(
    "failure",
    [
        OSError("offline"),
        ClientResponseError(Mock(real_url="https://example.com"), (), status=500),
        {},
    ],
)
async def test_partial_account_setup_failure_cleans_first_spa(
    hass, account, cloud, network, failure
):
    hass.config_entries.async_update_entry(
        account,
        data={
            **account.data,
            "vessels": [
                *account.data["vessels"],
                {"vesselId": "spa2", "monitorId": "monitor2", "name": "Spa 2"},
            ],
        },
    )
    cloud.async_get_monitor_livestream.side_effect = [
        {"brokerUrl": "wss://example.com"},
        failure,
    ]
    assert not await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    assert account.state is ConfigEntryState.SETUP_RETRY
    assert network.clients[0].disconnect_calls == 1
    assert not hass.data[GECKO_CONNECTION_MANAGER_KEY]._connections
    assert getattr(account, "runtime_data", None) is None


async def test_name_id_migration_preserves_entity_and_prefix_boundaries(
    hass, account, cloud
):
    registry = er.async_get(hass)
    old = registry.async_get_or_create(
        "fan", "gecko", f"{account.entry_id}_Spa_pump_1", config_entry=account
    )
    neighbour = registry.async_get_or_create(
        "fan", "gecko", f"{account.entry_id}_Spa 2_pump_1", config_entry=account
    )
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    assert (
        registry.async_get(old.entity_id).unique_id == f"{account.entry_id}_spa_pump_1"
    )
    assert (
        registry.async_get(neighbour.entity_id).unique_id
        == f"{account.entry_id}_Spa 2_pump_1"
    )
    assert await hass.config_entries.async_unload(account.entry_id)
