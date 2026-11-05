"""Exercise pump, light and thermostat actions through real HA entities/services."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from homeassistant.components.climate import ClimateEntityFeature
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.entity_component import DATA_INSTANCES

from custom_components.gecko.gecko_iot_client.models.operation_mode import OperationMode
from custom_components.gecko.gecko_iot_client.models.operation_mode_controller import (
    OperationModeController,
)
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType

from .conftest import build_zones

ACTIONS = [
    ("fan", "turn_on", {}),
    ("fan", "turn_off", {}),
    ("fan", "set_percentage", {"percentage": 50}),
    ("light", "turn_on", {}),
    ("light", "turn_off", {}),
    ("light", "turn_on", {"rgb_color": (255, 0, 0), "brightness": 128}),
    ("climate", "set_temperature", {"temperature": 37}),
    ("climate", "set_preset_mode", {"preset_mode": "Away"}),
]


@pytest.fixture
async def controls(hass, account, cloud, network):
    zones = network.next_zones_on_connect
    zones[ZoneType.FLOW_ZONE][0].config["speed"] = {
        "minimum": 50,
        "maximum": 100,
        "stepIncrement": 50,
    }
    zones[ZoneType.LIGHTING_ZONE][0].update_from_state({"rgbi": [0, 255, 0, 1]})
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    client = network.clients[-1]
    controller = OperationModeController()
    controller.operation_mode = OperationMode.STANDARD
    client.operation_mode_controller = controller
    coordinator = account.runtime_data.coordinators[0]
    coordinator.async_update_listeners()
    entities = {}
    for domain, name in (
        ("fan", "spa_pump_1"),
        ("light", "spa_light_1"),
        ("climate", "spa_thermostat_1"),
    ):
        entities[domain] = hass.data[DATA_INSTANCES][domain].get_entity(
            f"{domain}.{name}"
        )
        assert entities[domain] is not None, list(hass.states.async_entity_ids(domain))
    try:
        yield SimpleNamespace(
            entities=entities,
            client=client,
            coordinator=coordinator,
            controller=controller,
            zones=zones,
        )
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


def publish_callback(controls, domain, service, callback):
    if service == "set_preset_mode":
        controls.controller.set_publish_callback(callback)
    else:
        controls.entities[domain]._current_zone().set_publish_callback(callback)


async def call(hass, controls, domain, service, data):
    await hass.services.async_call(
        domain,
        service,
        {"entity_id": controls.entities[domain].entity_id, **data},
        blocking=True,
    )


@pytest.mark.parametrize("domain,service,data", ACTIONS)
@pytest.mark.parametrize(
    "failure", [ConnectionError, TimeoutError, RuntimeError, ValueError, Exception]
)
async def test_failed_publish_is_translated_and_keeps_state(
    hass, controls, domain, service, data, failure
):
    entity = controls.entities[domain]
    before = hass.states.get(entity.entity_id)
    zone = entity._current_zone()
    model = zone.to_config()
    publish_callback(
        controls, domain, service, Mock(side_effect=failure("PRIVATE-provider-token"))
    )
    with pytest.raises(HomeAssistantError) as caught:
        await call(hass, controls, domain, service, data)
    assert caught.value.translation_domain == "gecko"
    assert caught.value.translation_key == "command_failed"
    assert "PRIVATE" not in str(caught.value)
    assert hass.states.get(entity.entity_id) == before
    assert zone.to_config() == model


@pytest.mark.parametrize("domain,service,data", ACTIONS)
async def test_commands_publish_off_the_event_loop(
    hass, controls, domain, service, data
):
    calls = []
    publish_callback(
        controls,
        domain,
        service,
        lambda *args: calls.append((threading.get_ident(), args[-1])),
    )
    await call(hass, controls, domain, service, data)
    assert len(calls) == 1
    assert calls[0][0] != threading.get_ident()
    assert calls[0][1]


@pytest.mark.parametrize("domain,service,data", ACTIONS)
@pytest.mark.parametrize("missing_zone", [False, True])
async def test_unavailable_commands_do_not_silently_succeed(
    hass, controls, domain, service, data, missing_zone
):
    entity = controls.entities[domain]
    publish = Mock()
    publish_callback(controls, domain, service, publish)
    if missing_zone:
        controls.coordinator._zones[entity._zone_type] = []
    else:
        controls.client.emit_connectivity(False)
        await hass.async_block_till_done()
    with pytest.raises(HomeAssistantError) as caught:
        await getattr(entity, f"async_{service}")(**data)
    assert caught.value.translation_key == "device_unavailable"
    assert not entity.available
    publish.assert_not_called()


@pytest.mark.parametrize(
    "temperature", [True, "37", float("nan"), float("inf"), 14, 41, 10**1000]
)
async def test_invalid_temperature_is_rejected_without_publishing(
    controls, temperature
):
    entity = controls.entities["climate"]
    publish = Mock()
    entity._current_zone().set_publish_callback(publish)
    with pytest.raises(ServiceValidationError) as caught:
        await entity.async_set_temperature(temperature=temperature)
    assert caught.value.translation_key == "invalid_temperature"
    publish.assert_not_called()


async def test_plain_light_rejects_color_before_publishing_effect(controls):
    entity = controls.entities["light"]
    zone = entity._current_zone()
    zone.rgbi = None
    publish = Mock()
    zone.set_publish_callback(publish)
    with pytest.raises(ServiceValidationError) as caught:
        await entity.async_turn_on(effect="rainbow", rgb_color=(255, 0, 0))
    assert caught.value.translation_key == "light_color_unsupported"
    publish.assert_not_called()


async def test_reconnect_between_light_commands_does_not_command_old_zone(controls):
    entity = controls.entities["light"]
    old = entity._current_zone()
    publish = Mock()
    old.set_publish_callback(publish)
    original = entity._async_zone_command

    async def reconnect_after_effect(method, *args):
        result = await original(method, *args)
        controls.coordinator._zones = build_zones(
            {"lighting": {"1": {"rgbi": [0, 0, 255, 1]}}}
        )
        return result

    with (
        patch.object(entity, "_async_zone_command", reconnect_after_effect),
        pytest.raises(HomeAssistantError) as caught,
    ):
        await entity.async_turn_on(effect="rainbow", rgb_color=(255, 0, 0))
    assert caught.value.translation_key == "device_reconnected"
    assert publish.call_count == 1
    assert publish.call_args.args[-1] == {"effect": "rainbow", "active": True}


async def test_unknown_pump_speed_is_never_an_activation_command(controls):
    entity = controls.entities["fan"]
    publish = Mock()
    entity._current_zone().set_publish_callback(publish)
    with pytest.raises(ServiceValidationError) as caught:
        await entity.async_set_speed("turbo")
    assert caught.value.translation_key == "unsupported_pump_speed"
    publish.assert_not_called()


async def test_pump_start_timeout_cleans_up_confirmation_listener(controls):
    entity = controls.entities["fan"]
    zone = entity._current_zone()
    zone.set_publish_callback(Mock())
    before = len(controls.coordinator._listeners)
    original_timeout = asyncio.timeout
    with (
        patch(
            "custom_components.gecko.fan.asyncio.timeout", lambda _: original_timeout(0)
        ),
        pytest.raises(HomeAssistantError) as caught,
    ):
        await entity._start_low_first(zone, 50)
    assert caught.value.translation_key == "pump_start_unconfirmed"
    assert len(controls.coordinator._listeners) == before


async def test_climate_missing_watercare_controller_has_action_error(controls):
    controls.client.operation_mode_controller = None
    with pytest.raises(HomeAssistantError) as caught:
        await controls.entities["climate"].async_set_preset_mode("Away")
    assert caught.value.translation_key == "watercare_unavailable"


async def test_climate_advertises_watercare_only_when_controller_exists(controls):
    entity = controls.entities["climate"]
    assert entity.supported_features & ClimateEntityFeature.PRESET_MODE
    controls.client.operation_mode_controller = None
    controls.coordinator.async_update_listeners()
    assert not entity.supported_features & ClimateEntityFeature.PRESET_MODE
    assert entity.preset_mode is None
    controls.client.operation_mode_controller = controls.controller
    controls.coordinator.async_update_listeners()
    assert entity.supported_features & ClimateEntityFeature.PRESET_MODE
    assert entity.preset_mode == "Standard"


@pytest.mark.parametrize("cancel", [False, True])
async def test_low_first_start_stops_after_reconnect_or_cancellation(
    hass, controls, cancel
):
    entity = controls.entities["fan"]
    zone = entity._current_zone()
    zone.speed = 100
    zone.active = False
    entered = asyncio.Event()
    published = []

    def publish(*args):
        published.append(args[-1])
        hass.loop.call_soon_threadsafe(entered.set)

    zone.set_publish_callback(publish)
    before = len(controls.coordinator._listeners)
    task = hass.async_create_task(entity.async_set_percentage(100))
    try:
        async with asyncio.timeout(3):
            await entered.wait()
            if cancel:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                controls.coordinator._zones = build_zones(
                    {"flow": {"1": {"active": True, "speed": 50}}}
                )
                controls.coordinator.async_update_listeners()
                with pytest.raises(HomeAssistantError) as caught:
                    await task
                assert caught.value.translation_key == "device_reconnected"
        assert published == [{"speed": 50, "active": True}]
        assert len(controls.coordinator._listeners) == before
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize(
    "method,value,key",
    [
        ("async_set_preset_mode", "Other", "unsupported_preset_mode"),
        ("async_set_hvac_mode", "off", "unsupported_hvac_mode"),
    ],
)
async def test_unsupported_climate_modes_are_validation_errors(
    controls, method, value, key
):
    publish = Mock()
    controls.controller.set_publish_callback(publish)
    with pytest.raises(ServiceValidationError) as caught:
        await getattr(controls.entities["climate"], method)(value)
    assert caught.value.translation_key == key
    publish.assert_not_called()


async def test_reload_preserves_control_registry_ids_and_uses_new_zones(
    hass, controls, account, network
):
    old = {
        domain: (entity.entity_id, entity.unique_id, entity)
        for domain, entity in controls.entities.items()
    }
    stale_publishes = Mock()
    for entity in controls.entities.values():
        entity._current_zone().set_publish_callback(stale_publishes)
    assert await hass.config_entries.async_unload(account.entry_id)
    network.next_zones_on_connect = build_zones(
        {
            "flow": {"1": {"active": True, "speed": 50}},
            "lighting": {"1": {"active": True}},
            "temperatureControl": {"1": {"temperature_": 32, "setPoint": 35}},
        }
    )
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    for domain, service, data in (
        ("fan", "turn_off", {}),
        ("light", "turn_off", {}),
        ("climate", "set_temperature", {"temperature": 36}),
    ):
        entity_id, unique_id, previous = old[domain]
        entity = hass.data[DATA_INSTANCES][domain].get_entity(entity_id)
        assert entity is not previous
        assert entity.unique_id == unique_id
        assert entity.device_info == previous.device_info
        publish = Mock()
        entity._current_zone().set_publish_callback(publish)
        await hass.services.async_call(
            domain, service, {"entity_id": entity_id, **data}, blocking=True
        )
        publish.assert_called_once()
    stale_publishes.assert_not_called()
