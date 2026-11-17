"""Registry transfer preserves existing entities without touching in.touch 2."""

from unittest.mock import patch

import pytest
from homeassistant.loader import IntegrationNotFound
from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.gecko_intouch3.migration import (
    SOURCE_ENTRY,
    async_transfer_legacy_entry,
    is_legacy_intouch3,
)


def cloud_entry(**kwargs):
    return MockConfigEntry(
        domain="gecko",
        data={
            "account_id": "account",
            "user_id": "user",
            "vessels": [],
            "token": {"refresh_token": "test"},
        },
        **kwargs,
    )


async def test_transfers_registries_and_keeps_entity_id(hass):
    old = cloud_entry()
    old.add_to_hass(hass)
    new = MockConfigEntry(
        domain="gecko_intouch3", data={**old.data, SOURCE_ENTRY: old.entry_id}
    )
    new.add_to_hass(hass)
    local = MockConfigEntry(domain="gecko", data={"host": "192.0.2.1"})
    local.add_to_hass(hass)
    devices = dr.async_get(hass)
    device = devices.async_get_or_create(
        config_entry_id=old.entry_id, identifiers={("gecko", "spa")}
    )
    registry = er.async_get(hass)
    entity = registry.async_get_or_create(
        "sensor",
        "gecko",
        f"{old.entry_id}_spa_temperature",
        config_entry=old,
        device_id=device.id,
        suggested_object_id="existing_spa",
    )
    registry.async_get_or_create("sensor", "gecko", "stable_id", config_entry=old)
    with patch(
        "homeassistant.loader.async_get_integration",
        side_effect=IntegrationNotFound("gecko"),
    ):
        await async_transfer_legacy_entry(hass, new)
    migrated = registry.async_get(entity.entity_id)
    assert migrated.entity_id == entity.entity_id
    assert migrated.platform == "gecko_intouch3"
    assert migrated.config_entry_id == new.entry_id
    assert migrated.unique_id == f"{new.entry_id}_spa_temperature"
    assert devices.async_get(device.id).identifiers == {("gecko_intouch3", "spa")}
    assert devices.async_get(device.id).config_entry_id == new.entry_id
    assert hass.config_entries.async_get_entry(old.entry_id) is None
    assert hass.config_entries.async_get_entry(local.entry_id) is local
    assert SOURCE_ENTRY not in new.data
    await async_transfer_legacy_entry(hass, new)  # Retry is harmless.


def test_local_gecko_entry_is_not_a_migration_candidate():
    assert not is_legacy_intouch3(
        MockConfigEntry(domain="gecko", data={"host": "192.0.2.1"})
    )
    assert is_legacy_intouch3(cloud_entry())


async def test_conflict_leaves_source_untouched(hass):
    from homeassistant.exceptions import ConfigEntryNotReady

    old = cloud_entry()
    old.add_to_hass(hass)
    new = MockConfigEntry(
        domain="gecko_intouch3", data={**old.data, SOURCE_ENTRY: old.entry_id}
    )
    new.add_to_hass(hass)
    registry = er.async_get(hass)
    entity = registry.async_get_or_create("sensor", "gecko", "stable", config_entry=old)
    registry.async_get_or_create("sensor", "gecko_intouch3", "stable", config_entry=new)
    with pytest.raises(ConfigEntryNotReady):
        await async_transfer_legacy_entry(hass, new)
    assert registry.async_get(entity.entity_id).platform == "gecko"
    assert hass.config_entries.async_get_entry(old.entry_id) is old


async def test_missing_source_clears_completed_marker(hass):
    entry = MockConfigEntry(
        domain="gecko_intouch3", data={SOURCE_ENTRY: "removed", "account_id": "a"}
    )
    entry.add_to_hass(hass)
    await async_transfer_legacy_entry(hass, entry)
    assert entry.data == {"account_id": "a"}


async def test_rejects_non_cloud_source(hass):
    from homeassistant.exceptions import ConfigEntryNotReady

    old = MockConfigEntry(domain="gecko", data={"host": "192.0.2.1"})
    old.add_to_hass(hass)
    entry = MockConfigEntry(domain="gecko_intouch3", data={SOURCE_ENTRY: old.entry_id})
    entry.add_to_hass(hass)
    with pytest.raises(ConfigEntryNotReady, match="not an in.touch"):
        await async_transfer_legacy_entry(hass, entry)
    assert hass.config_entries.async_get_entry(old.entry_id) is old


@pytest.mark.parametrize(
    "state,unload_result", [("loaded", False), ("failed_unload", True)]
)
async def test_unload_failure_keeps_source(hass, state, unload_result):
    from unittest.mock import AsyncMock
    from homeassistant.config_entries import ConfigEntryState
    from homeassistant.exceptions import ConfigEntryNotReady

    old = cloud_entry()
    old.add_to_hass(hass)
    old.mock_state(hass, ConfigEntryState(state))
    entry = MockConfigEntry(domain="gecko_intouch3", data={SOURCE_ENTRY: old.entry_id})
    entry.add_to_hass(hass)
    with (
        patch.object(
            hass.config_entries, "async_unload", AsyncMock(return_value=unload_result)
        ),
        pytest.raises(ConfigEntryNotReady),
    ):
        await async_transfer_legacy_entry(hass, entry)
    assert hass.config_entries.async_get_entry(old.entry_id) is old


async def test_loaded_source_is_unloaded_before_transfer(hass):
    from unittest.mock import AsyncMock
    from homeassistant.config_entries import ConfigEntryState

    old = cloud_entry()
    old.add_to_hass(hass)
    old.mock_state(hass, ConfigEntryState.LOADED)
    entry = MockConfigEntry(domain="gecko_intouch3", data={SOURCE_ENTRY: old.entry_id})
    entry.add_to_hass(hass)

    async def unload(_, **kwargs):
        old.mock_state(hass, ConfigEntryState.NOT_LOADED)
        return True

    with (
        patch.object(hass.config_entries, "async_unload", side_effect=unload) as mocked,
        patch(
            "homeassistant.loader.async_get_integration",
            side_effect=IntegrationNotFound("gecko"),
        ),
    ):
        await async_transfer_legacy_entry(hass, entry)
    mocked.assert_awaited()
    assert hass.config_entries.async_get_entry(old.entry_id) is None


async def test_remove_failure_retains_retry_marker(hass):
    from unittest.mock import AsyncMock
    from homeassistant.exceptions import ConfigEntryNotReady

    old = cloud_entry()
    old.add_to_hass(hass)
    entry = MockConfigEntry(domain="gecko_intouch3", data={SOURCE_ENTRY: old.entry_id})
    entry.add_to_hass(hass)
    with (
        patch.object(hass.config_entries, "async_remove", AsyncMock(return_value={})),
        pytest.raises(ConfigEntryNotReady),
    ):
        await async_transfer_legacy_entry(hass, entry)
    assert entry.data[SOURCE_ENTRY] == old.entry_id
