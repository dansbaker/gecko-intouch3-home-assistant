"""Missing metadata must not claim device identity or break normal controls."""

import pytest
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_component import DATA_INSTANCES


async def test_metadata_unavailable_then_explicit_values_recover_without_new_entities(
    hass, account, cloud
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    coordinator = account.runtime_data.coordinators[0]
    sensors = hass.data[DATA_INSTANCES]["sensor"]
    registry = er.async_get(hass)
    ids = {
        "home_firmware_version": "sensor.spa_home_en_firmware_version",
        "spa_firmware_version": "sensor.spa_spa_co_firmware_version",
        "spa_serial_number": "sensor.spa_spa_co_serial_number",
        "home_serial_number": "sensor.spa_home_en_serial_number",
    }
    identities = {
        key: registry.async_get(entity_id).unique_id for key, entity_id in ids.items()
    }
    try:
        coordinator.update_device_telemetry(
            {
                "metadata": {"configurationId": "PACK"},
                "accessories": {},
                "vesselId": "NOT-A-SERIAL",
            }
        )
        coordinator.async_update_listeners()
        await hass.async_block_till_done()
        for key, entity_id in ids.items():
            if key == "home_serial_number":
                # Existing EN/monitor metadata remains independent of CO identity.
                assert hass.states.get(entity_id).state == "monitor"
            else:
                assert hass.states.get(entity_id).state == "unavailable"
                assert sensors.get_entity(entity_id).native_value is None
        assert hass.states.get("climate.spa_thermostat_1").state != "unavailable"
        coordinator.update_device_telemetry(
            {
                "en_": {"fwVersion": "1.10.2", "sn": "EN-EXPLICIT"},
                "co_": {"fwVersion": "1.6.4", "sn": "CO-EXPLICIT"},
            }
        )
        coordinator.async_update_listeners()
        await hass.async_block_till_done()
        for key, entity_id in ids.items():
            assert hass.states.get(entity_id).state not in ("unavailable", "unknown")
            assert registry.async_get(entity_id).unique_id == identities[key]
            assert registry.async_get(entity_id).entity_id == entity_id
        assert hass.states.get(ids["spa_serial_number"]).state == "CO-EXPLICIT"
        assert (
            sensors.get_entity(ids["spa_serial_number"])
            .extra_state_attributes["source_field"]
            .endswith("co_.sn")
        )
        coordinator.update_device_telemetry(
            {
                "metadata": {"configurationId": "PACK"},
                "accessories": {},
                "vesselId": "WRONG",
            }
        )
        coordinator.async_update_listeners()
        await hass.async_block_till_done()
        assert hass.states.get(ids["spa_serial_number"]).state == "CO-EXPLICIT"
        assert await hass.config_entries.async_reload(account.entry_id)
        await hass.async_block_till_done()
        for key in (
            "home_firmware_version",
            "spa_firmware_version",
            "spa_serial_number",
        ):
            assert hass.states.get(ids[key]).state == "unavailable"
            assert registry.async_get(ids[key]).unique_id == identities[key]
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)
