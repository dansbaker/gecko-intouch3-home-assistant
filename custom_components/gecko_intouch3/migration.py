"""Explicit migration from the cloud in.touch 3 integration's old domain."""

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er

LEGACY_DOMAIN = "gecko"
SOURCE_ENTRY = "legacy_intouch3_entry_id"


def is_legacy_intouch3(entry: ConfigEntry) -> bool:
    """Recognize the cloud account schema, never just the shared domain name."""
    data = entry.data
    return (
        entry.domain == LEGACY_DOMAIN
        and bool(data.get("account_id"))
        and bool(data.get("user_id"))
        and isinstance(data.get("vessels"), list)
        and isinstance(data.get("token"), dict)
        and bool(data["token"].get("refresh_token"))
    )


async def async_transfer_legacy_entry(hass, entry: ConfigEntry) -> None:
    """Transfer unloaded registrations using HA APIs, preserving entity IDs.

    Keep the source marker until the transfer completes so retries are idempotent.
    Never remove a legacy entry unless it matches the in.touch 3 account schema.
    """
    source_id = entry.data.get(SOURCE_ENTRY)
    if not source_id:
        return
    old = hass.config_entries.async_get_entry(source_id)
    if old is None:
        hass.config_entries.async_update_entry(
            entry, data={k: v for k, v in entry.data.items() if k != SOURCE_ENTRY}
        )
        return
    if not is_legacy_intouch3(old):
        raise ConfigEntryNotReady(
            "The selected legacy entry is not an in.touch 3 cloud account"
        )
    registry = er.async_get(hass)
    entities = er.async_entries_for_config_entry(registry, source_id)
    # Check every destination before modifying either registry.
    for entity in entities:
        unique_id = entity.unique_id
        if unique_id.startswith(f"{source_id}_"):
            unique_id = f"{entry.entry_id}_{unique_id[len(source_id) + 1 :]}"
        conflict = registry.async_get_entity_id(entity.domain, entry.domain, unique_id)
        if conflict and conflict != entity.entity_id:
            raise ConfigEntryNotReady(
                "Resolve duplicate in.touch 3 entities before migration"
            )
    if old.state == ConfigEntryState.LOADED:
        if not await hass.config_entries.async_unload(source_id):
            raise ConfigEntryNotReady(
                "Disable the old in.touch 3 integration and restart before importing"
            )
    if old.state == ConfigEntryState.FAILED_UNLOAD:
        raise ConfigEntryNotReady(
            "Restart Home Assistant before retrying the in.touch 3 import"
        )
    for entity in entities:
        unique_id = entity.unique_id
        if unique_id.startswith(f"{source_id}_"):
            unique_id = f"{entry.entry_id}_{unique_id[len(source_id) + 1 :]}"
        registry.async_update_entity_platform(
            entity.entity_id,
            entry.domain,
            new_config_entry_id=entry.entry_id,
            **({"new_unique_id": unique_id} if unique_id != entity.unique_id else {}),
        )
    devices = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(devices, source_id):
        identifiers = {
            (entry.domain if domain == LEGACY_DOMAIN else domain, identifier)
            for domain, identifier in device.identifiers
        }
        devices.async_update_device(
            device.id,
            new_config_entry_id=entry.entry_id,
            new_identifiers=identifiers,
        )
    # HA removes only the old config-entry associations; transferred entities remain.
    if not (await hass.config_entries.async_remove(source_id)):
        raise ConfigEntryNotReady("Unable to remove the migrated legacy entry")
    hass.config_entries.async_update_entry(
        entry, data={k: v for k, v in entry.data.items() if k != SOURCE_ENTRY}
    )
