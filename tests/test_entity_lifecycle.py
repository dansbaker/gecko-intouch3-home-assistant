"""HA entity lifecycle owns all event subscriptions, including after reconnect."""

import logging
from unittest.mock import Mock

from homeassistant.helpers.entity_component import EntityComponent
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko.connection_manager import async_get_connection_manager
from custom_components.gecko.coordinator import GeckoVesselCoordinator
from custom_components.gecko.fan import GeckoFan
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType

from .conftest import MONITOR_ID, build_zones


async def test_registered_entity_rebinds_and_unsubscribes_on_removal(hass, network):
    entry = MockConfigEntry(domain="gecko", data={})
    entry.add_to_hass(hass)
    coord = GeckoVesselCoordinator(hass, entry.entry_id, "vessel", MONITOR_ID, "Spa")
    zones = build_zones({"flow": {"1": {"active": False, "speed": 50}}})
    coord._zones = zones
    manager = await async_get_connection_manager(hass)
    await manager.async_get_or_create_connection(
        MONITOR_ID, "wss://first", "Spa", refresh_token_callback=lambda *_: "wss://new"
    )
    client = network.clients[-1]
    zone = zones[ZoneType.FLOW_ZONE][0]
    fan = GeckoFan(coord, entry, zone)
    fan.hass = hass
    before = len(client._connectivity_callbacks)
    # Entity properties can be read before adding, including disabled entities.
    _ = fan.available
    _ = fan.available
    assert len(client._connectivity_callbacks) == before
    component = EntityComponent(logging.getLogger(__name__), "fan", hass)
    component._platforms["fan"].config_entry = entry
    await component.async_add_entities([fan])
    assert len(client._connectivity_callbacks) == before + 1
    stale_callback = client._connectivity_callbacks[-1]
    assert await manager.async_reconnect_monitor(MONITOR_ID)
    await hass.async_block_till_done()
    new_client = network.clients[-1]
    coord.async_set_updated_data({"reconnected": True})
    assert fan._registered_gecko_client is new_client
    assert stale_callback not in client._connectivity_callbacks
    await component.async_remove_entity(fan.entity_id)
    assert fan._registered_gecko_client is None
    assert len(new_client._connectivity_callbacks) == 1  # manager only
    assert not list(coord.async_contexts())
    writer = Mock()
    fan.async_write_ha_state = writer
    await hass.async_add_executor_job(stale_callback, Mock())
    await hass.async_block_till_done()
    writer.assert_not_called()
    # Reading state after removal must not attach to the new client again.
    _ = fan.available
    assert len(new_client._connectivity_callbacks) == 1
    await manager.async_disconnect_monitor(MONITOR_ID)
