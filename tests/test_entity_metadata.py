"""HA-visible names, units, categories and registration across every platform."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import EntityCategory, UnitOfTemperature
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_component import DATA_INSTANCES

from custom_components.gecko import binary_sensor, climate, fan, light, sensor
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType


@pytest.mark.parametrize("module", [fan, light, climate, sensor, binary_sensor])
@pytest.mark.parametrize("runtime", ["absent", None, "empty"])
async def test_setup_without_loaded_coordinators_creates_no_entities(
    hass, module, runtime
):
    entry = SimpleNamespace(entry_id="empty")
    if runtime != "absent":
        entry.runtime_data = (
            SimpleNamespace(coordinators=[]) if runtime == "empty" else None
        )
    add = Mock()
    await module.async_setup_entry(hass, entry, add)
    add.assert_not_called()


async def test_entity_metadata_uses_translations_and_correct_units(
    hass, account, cloud
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    registry = er.async_get(hass)
    try:
        for item in er.async_entries_for_config_entry(registry, account.entry_id):
            assert item.has_entity_name, item.entity_id
            assert item.device_id is not None
        for object_id, name in {
            "binary_sensor.spa_spa_in_use": "Spa Spa In Use",
            "binary_sensor.spa_heating": "Spa Heating",
            "binary_sensor.spa_filtration": "Spa Filtration",
            "binary_sensor.spa_eco_mode_1": "Spa Water Temperature 1 Eco Mode",
            "climate.spa_thermostat_1": "Spa Thermostat 1",
            "sensor.spa_water_temperature_1_status": "Spa Water Temperature 1 Status",
        }.items():
            assert hass.states.get(object_id).name == name
            entity = hass.data[DATA_INSTANCES][object_id.split(".")[0]].get_entity(
                object_id
            )
            assert entity.translation_key
        for suffix in ["current", "target"]:
            entity_id = f"sensor.spa_water_temperature_1_{suffix}_temperature"
            entity = hass.data[DATA_INSTANCES]["sensor"].get_entity(entity_id)
            assert entity.device_class is SensorDeviceClass.TEMPERATURE
            assert entity.native_unit_of_measurement is UnitOfTemperature.CELSIUS
            assert entity.state_class == (
                SensorStateClass.MEASUREMENT if suffix == "current" else None
            )
        for suffix in [
            "gateway_status",
            "spa_status",
            "transport_connection",
            "overall_connection",
        ]:
            item = registry.async_get(f"binary_sensor.spa_{suffix}")
            assert item.entity_category is EntityCategory.DIAGNOSTIC
        for suffix in [
            "rf_channel",
            "home_en_serial_number",
            "spa_co_firmware_version",
        ]:
            item = registry.async_get(f"sensor.spa_{suffix}")
            assert item.entity_category is EntityCategory.DIAGNOSTIC
        raw = next(
            item
            for item in er.async_entries_for_config_entry(registry, account.entry_id)
            if item.unique_id.endswith("raw_api_data")
        )
        assert raw.disabled_by is not None
        assert raw.entity_category is EntityCategory.DIAGNOSTIC
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_initial_black_light_and_color_command_use_white_hue(
    hass, account, cloud, network
):
    zone = network.next_zones_on_connect[ZoneType.LIGHTING_ZONE][0]
    zone.update_from_state({"active": True, "rgbi": [0, 0, 0, 1]})
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        entity = hass.data[DATA_INSTANCES]["light"].get_entity("light.spa_light_1")
        assert entity.rgb_color == (255, 255, 255)
        assert entity.brightness == 0
        publish = Mock()
        zone.set_publish_callback(publish)
        await entity.async_turn_on(brightness=128)
        assert publish.call_args.args[-1] == {
            "rgbi": [128, 128, 128, 1],
            "active": True,
        }
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


@pytest.mark.parametrize(
    "key,unit,device_class,native_unit,state_class",
    [
        ("ph", "pH", SensorDeviceClass.PH, None, SensorStateClass.MEASUREMENT),
        ("orp", "mV", SensorDeviceClass.VOLTAGE, "mV", SensorStateClass.MEASUREMENT),
        ("orp", None, None, None, None),
        ("orp", "custom", None, "custom", None),
        (
            "waterTemp",
            "C",
            SensorDeviceClass.TEMPERATURE,
            "°C",
            SensorStateClass.MEASUREMENT,
        ),
        (
            "waterTemp",
            "F",
            SensorDeviceClass.TEMPERATURE,
            "°F",
            SensorStateClass.MEASUREMENT,
        ),
        ("waterTemp", None, None, None, None),
        ("chlorine", "ppm", None, "ppm", SensorStateClass.MEASUREMENT),
    ],
)
async def test_waterlab_metadata_requires_known_units(
    hass, account, cloud, key, unit, device_class, native_unit, state_class
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    coord = account.runtime_data.coordinators[0]
    coord.waterlab_readings = {key: {"value": 7.2, "unit": unit}}
    entity = sensor.GeckoWaterlabSensor(coord, key)
    assert entity.device_class == device_class
    assert entity.native_unit_of_measurement == native_unit
    assert entity.state_class == state_class
    assert entity.translation_key == f"waterlab_{key.lower()}"
    assert await hass.config_entries.async_unload(account.entry_id)


def test_translation_catalogs_cover_declared_enums_and_names():
    root = Path(__file__).resolve().parents[1] / "custom_components/gecko"
    source = json.loads((root / "strings.json").read_text())
    english = json.loads((root / "translations/en.json").read_text())
    assert source["entity"] == english["entity"]
    for description in sensor.DEVICE_TELEMETRY_SENSOR_DESCRIPTIONS:
        assert source["entity"]["sensor"][description.translation_key]["name"]
    for description in binary_sensor.BINARY_SENSOR_DESCRIPTIONS:
        assert source["entity"]["binary_sensor"][description.translation_key]["name"]
    # Legacy uppercase status and title-case Watercare states are retained.
    # Hassfest requires lowercase slug keys; do not ship unusable translations.
    assert "state" not in source["entity"]["sensor"]["temperature_status"]
    assert "state" not in source["entity"]["select"]["watercare_mode"]
    assert set(source["entity"]["sensor"]["speed_mode"]["state"]) == set(
        sensor.FLOW_SPEED_MODE_OPTIONS
    )


async def test_black_light_color_without_cached_brightness_uses_full_level(
    hass, account, cloud, network
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        entity = hass.data[DATA_INSTANCES]["light"].get_entity("light.spa_light_1")
        # Color capability arrives after the on/off-only entity was created.
        zone = entity._current_zone()
        zone.update_from_state({"rgbi": [255, 0, 0, 1]})
        publish = Mock()
        zone.set_publish_callback(publish)
        await entity.async_turn_on(rgb_color=(0, 0, 255))
        assert publish.call_args.args[-1] == {"rgbi": [0, 0, 255, 1], "active": True}
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_user_entity_id_and_name_survive_metadata_upgrade(hass, account, cloud):
    registry = er.async_get(hass)
    original = registry.async_get_or_create(
        "binary_sensor",
        "gecko",
        f"{account.entry_id}_spa_heating",
        config_entry=account,
        suggested_object_id="my_existing_heating",
    )
    registry.async_update_entity(original.entity_id, name="My heating override")
    original_id = original.entity_id
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        item = registry.async_get(original_id)
        assert item.name == "My heating override"
        assert hass.states.get(original_id).name == "My heating override"
        assert item.unique_id == f"{account.entry_id}_spa_heating"
        assert item.has_entity_name
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_unknown_units_do_not_become_voltage_when_waterlab_updates(
    hass, account, cloud
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        coord = account.runtime_data.coordinators[0]
        coord.waterlab_available = True
        coord.waterlab_readings = {"orp": {"value": 300, "unit": "mV"}}
        await coord._async_handle_zone_update({"test": "waterlab_discovery"})
        await hass.async_block_till_done()
        entity = hass.data[DATA_INSTANCES]["sensor"].get_entity(
            "sensor.spa_waterlab_orp"
        )
        assert entity.device_class is SensorDeviceClass.VOLTAGE
        assert entity.native_unit_of_measurement == "mV"
        coord.waterlab_readings = {"orp": {"value": 0.3, "unit": "V"}}
        coord.async_update_listeners()
        assert entity.native_unit_of_measurement == "V"
        coord.waterlab_readings = {"orp": {"value": 7, "unit": "custom"}}
        coord.async_update_listeners()
        assert entity.device_class is None
        assert entity.state_class is None
        assert entity.native_unit_of_measurement == "custom"
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_disappearing_zones_clear_availability_and_restore_on_return(
    hass, account, cloud, network
):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    coord = account.runtime_data.coordinators[0]
    before = coord.get_all_zones()
    try:
        coord._zones = {kind: [] for kind in before}
        coord.async_update_listeners()
        for entity_id in [
            "climate.spa_thermostat_1",
            "light.spa_light_1",
            "fan.spa_pump_1",
            "sensor.spa_water_temperature_1_status",
            "sensor.spa_water_temperature_1_flow_status",
            "sensor.spa_water_temperature_1_current_temperature",
            "sensor.spa_pump_1_speed_mode",
            "binary_sensor.spa_eco_mode_1",
            "binary_sensor.spa_heating_1",
        ]:
            assert hass.states.get(entity_id).state == "unavailable"
            entity = hass.data[DATA_INSTANCES][entity_id.split(".")[0]].get_entity(
                entity_id
            )
            if entity_id.startswith(("sensor.", "binary_sensor.")):
                assert not entity.extra_state_attributes
        coord._zones = before
        coord.async_update_listeners()
        assert hass.states.get("climate.spa_thermostat_1").state != "unavailable"
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_reported_effect_updates_light_capabilities(
    hass, account, cloud, network
):
    zone = network.next_zones_on_connect[ZoneType.LIGHTING_ZONE][0]
    zone.update_from_state({"active": True, "effect": "rainbow"})
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        entity = hass.data[DATA_INSTANCES]["light"].get_entity("light.spa_light_1")
        assert entity.effect_list == ["rainbow"]
        assert entity.effect == "rainbow"
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_extension_measurements_and_opt_in_diagnostics_are_distinct(
    hass, account, cloud
):
    with (
        patch.object(
            sensor.GeckoRawApiSensor, "_attr_entity_registry_enabled_default", True
        ),
        patch.object(
            sensor.GeckoShadowMetricSensor,
            "entity_registry_enabled_default",
            property(lambda self: True),
        ),
    ):
        assert await hass.config_entries.async_setup(account.entry_id)
        await hass.async_block_till_done()
        coord = account.runtime_data.coordinators[0]
        coord.update_spa_state(
            {
                "state": {
                    "reported": {
                        "zones": {
                            "waterlab": {
                                "ph": {"value": 7.4},
                                "orp": {"value": 350},
                                "phCalibration": {"offset": 2},
                            }
                        }
                    }
                }
            }
        )
        await coord._async_handle_zone_update({"test": "initial_extensions"})
        await hass.async_block_till_done()
    registry = er.async_get(hass)
    try:
        coord.update_spa_state(
            {
                "state": {
                    "reported": {
                        "zones": {
                            "waterlab": {
                                "ph": {"value": 7.4},
                                "orp": {"value": 350},
                                "phCalibration": {"offset": 2},
                            }
                        }
                    }
                }
            }
        )
        await coord._async_handle_zone_update({"test": "extensions"})
        await hass.async_block_till_done()
        entries = [
            entry
            for entry in er.async_entries_for_config_entry(registry, account.entry_id)
            if "_extension_" in entry.unique_id
        ]
        assert len(entries) == 3
        entities = [
            hass.data[DATA_INSTANCES]["sensor"].get_entity(entry.entity_id)
            for entry in entries
        ]
        ph = next(
            entity for entity in entities if entity.device_class is SensorDeviceClass.PH
        )
        orp = next(entity for entity in entities if entity._kind == "orp")
        calibration = next(entity for entity in entities if entity._kind is None)
        assert ph.native_value == 7.4
        assert ph.state_class is SensorStateClass.MEASUREMENT
        assert orp.native_value == 350
        assert orp.native_unit_of_measurement is None
        assert orp.device_class is None
        assert orp.state_class is None
        assert calibration.entity_category is EntityCategory.DIAGNOSTIC
        assert calibration.state_class is None
        assert calibration.extra_state_attributes["calibration_parameter"]
        coord.update_spa_state(
            {"state": {"reported": {"zones": {"waterlab": {"ph": {"value": 20}}}}}}
        )
        await hass.async_block_till_done()
        assert ph.native_value is None
        assert orp.native_value is None
        raw = hass.data[DATA_INSTANCES]["sensor"].get_entity("sensor.spa_raw_api_data")
        assert raw.native_value == "captured"
        assert "MQTT shadow" in raw.extra_state_attributes["payloads"]
        coord._raw_api_payloads.clear()
        coord.async_update_listeners()
        assert raw.native_value == "empty"
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


@pytest.mark.parametrize(
    "vessel_status,state",
    [("READY", "on"), ("RUNNING", "on"), ("OFFLINE", "off"), ("UNKNOWN", "unknown")],
)
async def test_vessel_connection_diagnostic_preserves_unknown_state(
    hass, account, cloud, vessel_status, state
):
    from custom_components.gecko.connection_manager import GECKO_CONNECTION_MANAGER_KEY

    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    try:
        connection = hass.data[GECKO_CONNECTION_MANAGER_KEY].get_connection("monitor")
        connection.connectivity_status = SimpleNamespace(
            gateway_status="UNKNOWN",
            vessel_status=vessel_status,
            transport_connected=True,
            is_fully_connected=False,
        )
        account.runtime_data.coordinators[0].async_update_listeners()
        assert hass.states.get("binary_sensor.spa_spa_status").state == state
        assert hass.states.get("binary_sensor.spa_gateway_status").state == "unknown"
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def test_manager_absence_unsubscribes_entities_and_recovers(
    hass, account, cloud, network
):
    from custom_components.gecko.connection_manager import GECKO_CONNECTION_MANAGER_KEY

    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    coord = account.runtime_data.coordinators[0]
    entity = hass.data[DATA_INSTANCES]["fan"].get_entity("fan.spa_pump_1")
    client = network.clients[-1]
    before = len(client._connectivity_callbacks)
    manager = hass.data.pop(GECKO_CONNECTION_MANAGER_KEY)
    try:
        coord.async_update_listeners()
        assert entity._registered_gecko_client is None
        assert len(client._connectivity_callbacks) < before
        assert hass.states.get(entity.entity_id).state == "unavailable"
        assert hass.states.get("binary_sensor.spa_gateway_status").state == "unknown"
    finally:
        hass.data[GECKO_CONNECTION_MANAGER_KEY] = manager
    coord.async_update_listeners()
    assert entity._registered_gecko_client is client
    assert len(client._connectivity_callbacks) == before
    assert hass.states.get(entity.entity_id).state != "unavailable"
    assert await hass.config_entries.async_unload(account.entry_id)


async def test_connection_diagnostics_fall_back_to_client_then_unknown(
    hass, account, cloud, network
):
    from custom_components.gecko.connection_manager import GECKO_CONNECTION_MANAGER_KEY

    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    connection = hass.data[GECKO_CONNECTION_MANAGER_KEY].get_connection("monitor")
    client = connection.gecko_client
    previous_status = connection.connectivity_status
    try:
        client.connectivity_status = SimpleNamespace(
            gateway_status="CONNECTED",
            vessel_status="READY",
            transport_connected=True,
            is_fully_connected=True,
        )
        connection.connectivity_status = None
        account.runtime_data.coordinators[0].async_update_listeners()
        assert hass.states.get("binary_sensor.spa_gateway_status").state == "on"
        assert hass.states.get("binary_sensor.spa_spa_status").state == "on"
        connection.gecko_client = None
        account.runtime_data.coordinators[0].async_update_listeners()
        assert hass.states.get("binary_sensor.spa_gateway_status").state == "unknown"
        connection.gecko_client = client
        client.connectivity_status = SimpleNamespace()
        account.runtime_data.coordinators[0].async_update_listeners()
        assert hass.states.get("binary_sensor.spa_gateway_status").state == "unknown"
    finally:
        connection.gecko_client = client
        connection.connectivity_status = previous_status
        assert await hass.config_entries.async_unload(account.entry_id)
