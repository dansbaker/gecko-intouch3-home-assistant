"""Climate platform for Gecko Spa integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER, MODEL, CLIMATE_ENTITY_NAME
from .coordinator import GeckoDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Gecko Spa climate entity."""
    coordinator: GeckoDataUpdateCoordinator = config_entry.runtime_data
    
    async_add_entities([
        GeckoClimateEntity(coordinator, config_entry)
    ])


class GeckoClimateEntity(CoordinatorEntity[GeckoDataUpdateCoordinator], ClimateEntity):
    """Gecko Spa climate entity."""

    _attr_has_entity_name = True
    _attr_name = CLIMATE_ENTITY_NAME
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_hvac_modes = [HVACMode.HEAT, HVACMode.OFF]
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.TURN_ON
        | ClimateEntityFeature.TURN_OFF
    )
    _attr_min_temp = 20.0
    _attr_max_temp = 40.0
    _attr_target_temperature_step = 1.0

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the climate entity."""
        super().__init__(coordinator)
        
        self._attr_unique_id = f"{config_entry.entry_id}_climate"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.monitor_id)},
            name="Gecko Hot Tub",
            manufacturer=MANUFACTURER,
            model=MODEL,
            sw_version="1.0.0",
        )

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success and self.coordinator.data is not None

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        if self.coordinator.data and (temp_data := self.coordinator.data.get("temperature")):
            return temp_data.get("current_temp")
        return None

    @property
    def target_temperature(self) -> float | None:
        """Return the target temperature."""
        if self.coordinator.data and (temp_data := self.coordinator.data.get("temperature")):
            return temp_data.get("target_temp")
        return None

    @property
    def hvac_mode(self) -> HVACMode:
        """Return current operation mode."""
        if self.coordinator.data and (temp_data := self.coordinator.data.get("temperature")):
            heating = temp_data.get("heating_status", False)
            current_temp = temp_data.get("current_temp")
            target_temp = temp_data.get("target_temp")
            
            if current_temp and target_temp:
                if target_temp > current_temp:
                    return HVACMode.HEAT
                    
        return HVACMode.OFF

    @property
    def hvac_action(self) -> str | None:
        """Return current HVAC action."""
        if self.coordinator.data and (temp_data := self.coordinator.data.get("temperature")):
            if temp_data.get("heating_status"):
                return "heating"
            else:
                return "idle"
        return None

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set new target temperature."""
        if temperature := kwargs.get(ATTR_TEMPERATURE):
            await self.coordinator.async_set_temperature(float(temperature))

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new HVAC mode."""
        if hvac_mode == HVACMode.HEAT:
            # Turn on by setting a target temperature (if current is available)
            if self.current_temperature:
                target = max(self.current_temperature + 1, self._attr_min_temp)
                await self.coordinator.async_set_temperature(target)
        elif hvac_mode == HVACMode.OFF:
            # Turn off by setting temperature to minimum (or current - this is device specific)
            if self.current_temperature:
                await self.coordinator.async_set_temperature(self._attr_min_temp)

    async def async_turn_on(self) -> None:
        """Turn the entity on."""
        await self.async_set_hvac_mode(HVACMode.HEAT)

    async def async_turn_off(self) -> None:
        """Turn the entity off."""
        await self.async_set_hvac_mode(HVACMode.OFF)
