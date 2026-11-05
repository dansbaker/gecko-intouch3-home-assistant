"""Watercare state, action failures and serialization through real HA services."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.entity_component import DATA_INSTANCES
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko.gecko_iot_client.models.operation_mode import OperationMode
from custom_components.gecko.gecko_iot_client.models.operation_mode_controller import (
    OperationModeController,
)
from custom_components.gecko.select import async_setup_entry


@pytest.fixture
async def control(hass, account, cloud, network):
    assert await hass.config_entries.async_setup(account.entry_id)
    await hass.async_block_till_done()
    client = network.clients[-1]
    controller = OperationModeController()
    controller.operation_mode = OperationMode.STANDARD
    client.operation_mode_controller = controller
    coordinator = account.runtime_data.coordinators[0]
    coordinator.async_set_updated_data({"changed": True})
    await hass.async_block_till_done()
    entity = hass.data[DATA_INSTANCES]["select"].get_entity("select.spa_watercare_mode")
    assert entity is not None
    try:
        yield SimpleNamespace(
            entry=account,
            client=client,
            controller=controller,
            coordinator=coordinator,
            entity=entity,
        )
    finally:
        assert await hass.config_entries.async_unload(account.entry_id)


async def command(hass, option):
    await hass.services.async_call(
        "select",
        "select_option",
        {"entity_id": "select.spa_watercare_mode", "option": option},
        blocking=True,
    )


async def test_publish_is_not_confirmation_and_reported_changes_win(hass, control):
    published = []
    control.controller.set_publish_callback(
        lambda _, data: published.append((threading.get_ident(), data))
    )
    assert hass.states.get(control.entity.entity_id).state == "Standard"
    assert "Other" not in control.entity.options
    await command(hass, "Super Savings")
    assert published[0][1] == {"operationMode": 3}
    assert published[0][0] != threading.get_ident()
    assert hass.states.get(control.entity.entity_id).state == "Standard"
    control.controller.update_from_state_data(
        {"state": {"reported": {"features": {"operationMode": 3}}}}
    )
    for callback in control.client._operation_mode_callbacks:
        callback(control.controller)
    await hass.async_block_till_done()
    assert hass.states.get(control.entity.entity_id).state == "Super Savings"
    control.controller.operation_mode = OperationMode.OTHER
    control.coordinator.async_update_listeners()
    assert hass.states.get(control.entity.entity_id).state == "unknown"


@pytest.mark.parametrize(
    "failure", [TimeoutError("PRIVATE-TOKEN"), RuntimeError("PRIVATE-TOKEN")]
)
async def test_publish_failure_is_a_translated_action_error(hass, control, failure):
    control.controller.set_publish_callback(Mock(side_effect=failure))
    with pytest.raises(HomeAssistantError) as caught:
        await command(hass, "Away")
    assert caught.value.translation_key == "command_failed"
    assert caught.value.translation_domain == "gecko"
    assert "PRIVATE" not in str(caught.value)
    assert hass.states.get(control.entity.entity_id).state == "Standard"


async def test_unavailable_controller_or_connection_does_not_silently_succeed(
    hass, control
):
    for missing_controller in (True, False):
        control.client.operation_mode_controller = (
            None if missing_controller else control.controller
        )
        if not missing_controller:
            control.client.emit_connectivity(False)
        with pytest.raises(HomeAssistantError) as caught:
            await control.entity.async_select_option("Away")
        assert caught.value.translation_key == "watercare_unavailable"
    control.coordinator.async_update_listeners()
    assert hass.states.get(control.entity.entity_id).state == "unavailable"


@pytest.mark.parametrize("option", ["Other", "not-a-mode"])
async def test_unsupported_mode_is_rejected_before_publishing(control, option):
    published = Mock()
    control.controller.set_publish_callback(published)
    with pytest.raises(ServiceValidationError) as caught:
        await control.entity.async_select_option(option)
    assert caught.value.translation_key == "unsupported_watercare_mode"
    published.assert_not_called()


async def test_setup_without_runtime_does_not_create_entities(hass):
    entry = MockConfigEntry(domain="gecko", data={})
    add = Mock()
    await async_setup_entry(hass, entry, add)
    add.assert_not_called()


async def test_simultaneous_commands_are_serialized_while_reports_still_update(
    hass, control
):
    entered = asyncio.Event()
    second_request = asyncio.Event()
    release = threading.Event()
    published = []
    pending = []

    def publish(_, data):
        published.append(data)
        if data["operationMode"] == 2:
            hass.loop.call_soon_threadsafe(entered.set)
            if not release.wait(3):
                raise TimeoutError("Test command was not released")

    control.controller.set_publish_callback(publish)
    original = control.entity.async_request_call
    calls = 0

    async def observe(coro):
        nonlocal calls
        calls += 1
        if calls == 2:
            second_request.set()
        return await original(coro)

    with (
        patch.object(control.entity, "async_request_call", observe),
        patch.object(
            hass, "async_add_executor_job", wraps=hass.async_add_executor_job
        ) as executor,
    ):
        try:
            pending.append(asyncio.create_task(command(hass, "Savings")))
            await asyncio.wait_for(entered.wait(), 2)
            pending.append(asyncio.create_task(command(hass, "Away")))
            await asyncio.wait_for(second_request.wait(), 2)
            submitted = [
                call
                for call in executor.call_args_list
                if call.args[0] == control.controller.set_mode_by_name
            ]
            assert len(submitted) == 1
            # Push reports must not wait for the command semaphore.
            control.controller.operation_mode = OperationMode.WEEKENDER
            control.coordinator.async_update_listeners()
            assert hass.states.get(control.entity.entity_id).state == "Weekender"
        finally:
            release.set()
            await asyncio.gather(*pending)
    assert published == [{"operationMode": 2}, {"operationMode": 0}]
