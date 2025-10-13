"""Select platform for Gecko Spa."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import GeckoDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

# Water Care Mode mapping
WATER_CARE_MODES = {
    0: "Away from home",
    1: "Standard",
    2: "Energy Savings",
    3: "Super Energy Savings",
    4: "Weekender",
}

# Reverse mapping for setting values
WATER_CARE_MODE_VALUES = {v: k for k, v in WATER_CARE_MODES.items()}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Gecko Spa select entities."""
    coordinator: GeckoDataUpdateCoordinator = entry.runtime_data
    
    entities = [
        GeckoWaterCareModeSelect(coordinator),
    ]
    
    async_add_entities(entities)


class GeckoWaterCareModeSelect(SelectEntity):
    """Representation of a Gecko Spa Water Care Mode select entity."""

    def __init__(self, coordinator: GeckoDataUpdateCoordinator) -> None:
        """Initialize the select entity."""
        self.coordinator = coordinator
        self._attr_name = f"{coordinator.vessel_name} Water Care Mode"
        self._attr_unique_id = f"{coordinator.monitor_id}_water_care_mode"
        self._attr_options = list(WATER_CARE_MODE_VALUES.keys())
        self._attr_should_poll = False

    @property
    def device_info(self):
        """Return device information about this entity."""
        return {
            "identifiers": {(DOMAIN, self.coordinator.monitor_id)},
            "name": self.coordinator.vessel_name,
            "manufacturer": "Gecko Alliance",
            "model": "in.touch3",
        }

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success and self.coordinator.controller.connected

    @property
    def current_option(self) -> str | None:
        """Return the current water care mode."""
        shadow_state = self.coordinator.controller.last_shadow_state
        if not shadow_state:
            return None
        
        try:
            operation_mode = shadow_state.get("features", {}).get("operationMode")
            if operation_mode is not None:
                return WATER_CARE_MODES.get(operation_mode)
        except Exception as e:
            _LOGGER.error(f"Error getting water care mode: {e}")
        
        return None

    async def async_select_option(self, option: str) -> None:
        """Change the water care mode."""
        mode_value = WATER_CARE_MODE_VALUES.get(option)
        if mode_value is None:
            _LOGGER.error(f"Invalid water care mode: {option}")
            return
        
        try:
            await self.coordinator.controller.set_water_care_mode(mode_value)
            # Request an immediate update
            await self.coordinator.async_request_refresh()
        except Exception as e:
            _LOGGER.error(f"Error setting water care mode to {option}: {e}")

    async def async_added_to_hass(self) -> None:
        """Register callbacks when entity is added."""
        self.async_on_remove(
            self.coordinator.async_add_listener(self.async_write_ha_state)
        )

    async def async_update(self) -> None:
        """Update the entity."""
        await self.coordinator.async_request_refresh()
