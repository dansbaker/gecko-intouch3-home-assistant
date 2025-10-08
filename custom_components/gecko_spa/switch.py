"""Switch platform for Gecko Spa integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER, MODEL, LIGHTS_SWITCH_NAME, JETS_SWITCH_NAME
from .coordinator import GeckoDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Gecko Spa switch entities."""
    coordinator: GeckoDataUpdateCoordinator = config_entry.runtime_data
    
    entities = []
    
    # Add light entity (zone 1)
    entities.append(GeckoLightSwitch(coordinator, config_entry, 1))
    
    # Add pump entities (pumps 1, 2, 3)
    entities.append(GeckoPumpSwitch(coordinator, config_entry, 1))
    entities.append(GeckoPumpSwitch(coordinator, config_entry, 2))
    entities.append(GeckoPumpSwitch(coordinator, config_entry, 3))
    
    async_add_entities(entities)


class GeckoBaseSwitchEntity(CoordinatorEntity[GeckoDataUpdateCoordinator], SwitchEntity):
    """Base class for Gecko switch entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
        name: str,
        switch_type: str,
    ) -> None:
        """Initialize the switch entity."""
        super().__init__(coordinator)
        
        self._switch_type = switch_type
        self._attr_name = name
        self._attr_unique_id = f"{config_entry.entry_id}_{switch_type}"
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


class GeckoLightSwitch(GeckoBaseSwitchEntity):
    """Representation of a Gecko light switch for a specific zone."""

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
        zone_id: int,
    ) -> None:
        """Initialize the light switch."""
        super().__init__(coordinator, config_entry, f"Light", f"light_zone_{zone_id}")
        self._zone_id = zone_id
        self._optimistic_state = None  # For optimistic updates
        self._optimistic_expiry = None  # When to expire optimistic state

    @property
    def is_on(self) -> bool:
        """Return true if the light is on."""
        # Check optimistic state first (for immediate UI feedback)
        if self._optimistic_state is not None and self._optimistic_expiry:
            import datetime
            if datetime.datetime.now() < self._optimistic_expiry:
                return self._optimistic_state
            else:
                # Optimistic state expired, clear it
                self._optimistic_state = None
                self._optimistic_expiry = None
        
        # Fall back to coordinator data
        if self.coordinator.data and self.coordinator.data.get("lights"):
            lights_data = self.coordinator.data["lights"]
            return lights_data.get(self._zone_id, False)
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the light on."""
        # Set optimistic state for immediate UI feedback
        self._set_optimistic_state(True)
        
        # Send command to spa
        self.coordinator.controller.set_light_state(self._zone_id, True)
        # Real-time MQTT callbacks will update actual state

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the light off."""
        # Set optimistic state for immediate UI feedback
        self._set_optimistic_state(False)
        
        # Send command to spa
        self.coordinator.controller.set_light_state(self._zone_id, False)
        # Real-time MQTT callbacks will update actual state
    
    def _set_optimistic_state(self, state: bool) -> None:
        """Set optimistic state with expiry."""
        import datetime
        self._optimistic_state = state
        # Optimistic state expires after 10 seconds
        self._optimistic_expiry = datetime.datetime.now() + datetime.timedelta(seconds=10)
        # Trigger state update in UI
        self.async_write_ha_state()


class GeckoPumpSwitch(GeckoBaseSwitchEntity):
    """Representation of a Gecko pump switch for a specific pump."""

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
        pump_id: int,
    ) -> None:
        """Initialize the pump switch."""
        super().__init__(coordinator, config_entry, f"Pump {pump_id}", f"pump_{pump_id}")
        self._pump_id = pump_id
        self._optimistic_state = None  # For optimistic updates
        self._optimistic_expiry = None  # When to expire optimistic state

    @property
    def is_on(self) -> bool:
        """Return true if the pump is on."""
        # Check optimistic state first (for immediate UI feedback)
        if self._optimistic_state is not None and self._optimistic_expiry:
            import datetime
            if datetime.datetime.now() < self._optimistic_expiry:
                return self._optimistic_state
            else:
                # Optimistic state expired, clear it
                self._optimistic_state = None
                self._optimistic_expiry = None
        
        # Fall back to coordinator data
        if self.coordinator.data and self.coordinator.data.get("pumps"):
            pumps_data = self.coordinator.data["pumps"]
            pump_info = pumps_data.get(self._pump_id, {})
            return pump_info.get("active", False)
        return False

    @property
    def extra_state_attributes(self) -> dict:
        """Return the extra state attributes."""
        attributes = {}
        if self.coordinator.data and self.coordinator.data.get("pumps"):
            pumps_data = self.coordinator.data["pumps"]
            pump_info = pumps_data.get(self._pump_id, {})
            if "speed" in pump_info:
                attributes["speed"] = pump_info["speed"]
            if "initiators" in pump_info:
                attributes["initiators"] = pump_info["initiators"]
        return attributes

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the pump on."""
        self._set_optimistic_state(True)
        self.coordinator.controller.set_pump_state(self._pump_id, True)
        # Don't refresh immediately - let the natural update cycle handle it

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the pump off."""
        self._set_optimistic_state(False)
        self.coordinator.controller.set_pump_state(self._pump_id, False)
        # Don't refresh immediately - let the natural update cycle handle it

    def _set_optimistic_state(self, state: bool) -> None:
        """Set optimistic state with expiry."""
        import datetime
        self._optimistic_state = state
        # Optimistic state expires after 10 seconds
        self._optimistic_expiry = datetime.datetime.now() + datetime.timedelta(seconds=10)
        # Trigger state update in UI
        self.async_write_ha_state()


class GeckoLightsSwitch(GeckoBaseSwitchEntity):
    """Gecko Spa lights switch."""

    _attr_icon = "mdi:lightbulb"

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the lights switch."""
        super().__init__(coordinator, config_entry, LIGHTS_SWITCH_NAME, "lights")

    @property
    def is_on(self) -> bool:
        """Return true if lights are on."""
        # Check coordinator data for lights status
        if self.coordinator.data and self.coordinator.data.get("lights"):
            lights_data = self.coordinator.data["lights"]
            return any(lights_data.values())
        return False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the lights."""
        await self.coordinator.async_turn_on_lights()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the lights."""
        await self.coordinator.async_turn_off_lights()


class GeckoJetsSwitch(GeckoBaseSwitchEntity):
    """Gecko Spa jets/pump switch."""

    _attr_icon = "mdi:water-pump"

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
    ) -> None:
        """Initialize the jets switch."""
        super().__init__(coordinator, config_entry, JETS_SWITCH_NAME, "jets")

    @property
    def is_on(self) -> bool:
        """Return true if jets/pump are on."""
        # Check coordinator data for pump status
        if self.coordinator.data and self.coordinator.data.get("pumps"):
            pumps_data = self.coordinator.data["pumps"]
            return any(pump.get("active", False) for pump in pumps_data.values())
        return False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the jets/pump."""
        await self.coordinator.async_start_pump(pump_id=1, speed=75)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the jets/pump."""
        await self.coordinator.async_stop_pump(pump_id=1)
