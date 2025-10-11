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
    
    # Get spa configuration
    spa_config = coordinator.spa_config
    
    # Debug: Log the actual spa configuration structure
    _LOGGER.info("=== SPA CONFIGURATION DEBUG ===")
    _LOGGER.info("Full spa_config keys: %s", list(spa_config.keys()) if spa_config else "None")
    
    accessories = spa_config.get("accessories", {})
    _LOGGER.info("Accessories keys: %s", list(accessories.keys()) if accessories else "None")
    _LOGGER.info("Accessories content: %s", accessories)
    
    zones = spa_config.get("zones", {})
    _LOGGER.info("Zones keys: %s", list(zones.keys()) if zones else "None")
    
    flow_zones_config = zones.get("flow", {})  # This is a DICT, not a list!
    _LOGGER.info("Flow zones config type: %s, value: %s", type(flow_zones_config), flow_zones_config)
    
    # Build a mapping of accessory ID -> flow zone ID
    # The flow zones dict tells us which accessories are assigned to which flow zones
    accessory_to_flow_zone = {}
    if isinstance(flow_zones_config, dict):
        for zone_id, zone_info in flow_zones_config.items():
            # Check for pumps in this flow zone
            pumps_in_zone = zone_info.get("pumps", [])
            for pump_id in pumps_in_zone:
                key = f"pump_{pump_id}"
                accessory_to_flow_zone[key] = int(zone_id)
                _LOGGER.info(f"Flow zone {zone_id} assigned to pump {pump_id}")
            
            # Check for waterfalls in this flow zone
            waterfalls_in_zone = zone_info.get("waterfalls", [])
            for waterfall_id in waterfalls_in_zone:
                key = f"waterfall_{waterfall_id}"
                accessory_to_flow_zone[key] = int(zone_id)
                _LOGGER.info(f"Flow zone {zone_id} assigned to waterfall {waterfall_id}")
            
            # Check for blowers in this flow zone
            blowers_in_zone = zone_info.get("blowers", [])
            for blower_id in blowers_in_zone:
                key = f"blower_{blower_id}"
                accessory_to_flow_zone[key] = int(zone_id)
                _LOGGER.info(f"Flow zone {zone_id} assigned to blower {blower_id}")
    
    _LOGGER.info("Accessory to flow zone mapping: %s", accessory_to_flow_zone)
    _LOGGER.info("=== END SPA CONFIGURATION DEBUG ===")
    
    # Create pump entities based on actual configuration
    pumps = accessories.get("pumps", {})
    if pumps:
        _LOGGER.info("Creating %d pump switch entities from spa configuration", len(pumps))
        for pump_id, pump_info in pumps.items():
            # Find the flow zone for this pump
            flow_zone_id = accessory_to_flow_zone.get(f"pump_{pump_id}")
            if flow_zone_id:
                display_name = f"Pump {pump_id} (Flow Zone {flow_zone_id})"
                entities.append(GeckoPumpSwitch(coordinator, config_entry, flow_zone_id, display_name))
            else:
                _LOGGER.warning(f"Pump {pump_id} has no assigned flow zone")
    
    # Create light entities based on actual configuration  
    lights = accessories.get("lights", {})
    lighting_zones_config = zones.get("lighting", {})
    if lights and isinstance(lighting_zones_config, dict):
        _LOGGER.info("Creating %d light switch entities from spa configuration", len(lights))
        for light_id, light_info in lights.items():
            # Find the lighting zone for this light
            lighting_zone_id = None
            for zone_id, zone_info in lighting_zones_config.items():
                lights_in_zone = zone_info.get("lights", [])
                if light_id in lights_in_zone:
                    lighting_zone_id = int(zone_id)
                    break
            
            if lighting_zone_id:
                display_name = f"Light {light_id} (Lighting Zone {lighting_zone_id})"
                entities.append(GeckoLightSwitch(coordinator, config_entry, lighting_zone_id, display_name))
            else:
                _LOGGER.warning(f"Light {light_id} has no assigned lighting zone")
    
    # Create waterfall entities - these use flow zones!
    waterfalls = accessories.get("waterfalls", {})
    _LOGGER.info("Waterfalls found: %s", waterfalls)
    if waterfalls:
        _LOGGER.info("Creating %d waterfall switch entities from spa configuration", len(waterfalls))
        for waterfall_id, waterfall_info in waterfalls.items():
            # Find the flow zone for this waterfall
            flow_zone_id = accessory_to_flow_zone.get(f"waterfall_{waterfall_id}")
            _LOGGER.info(f"Waterfall {waterfall_id}: looking for flow zone with key 'waterfall_{waterfall_id}', found: {flow_zone_id}")
            if flow_zone_id:
                display_name = f"Waterfall {waterfall_id} (Flow Zone {flow_zone_id})"
                # Waterfalls are just flow zones, so use GeckoPumpSwitch with waterfall icon
                entities.append(GeckoWaterfallSwitch(coordinator, config_entry, flow_zone_id, int(waterfall_id), display_name))
            else:
                _LOGGER.warning(f"Waterfall {waterfall_id} has no assigned flow zone")
    else:
        _LOGGER.info("No waterfalls found in accessories")
    
    # Create blower entities - these also use flow zones!
    blowers = accessories.get("blowers", {})
    if blowers:
        _LOGGER.info("Creating %d blower switch entities from spa configuration", len(blowers))
        for blower_id, blower_info in blowers.items():
            # Find the flow zone for this blower
            flow_zone_id = accessory_to_flow_zone.get(f"blower_{blower_id}")
            if flow_zone_id:
                display_name = f"Blower {blower_id} (Flow Zone {flow_zone_id})"
                # Blowers are just flow zones, so use GeckoPumpSwitch with blower icon
                entities.append(GeckoBlowerSwitch(coordinator, config_entry, flow_zone_id, int(blower_id), display_name))
            else:
                _LOGGER.warning(f"Blower {blower_id} has no assigned flow zone")
    
    # Fallback if no entities were created
    if not entities:
        _LOGGER.warning("No accessories found in spa configuration, creating default entities")
        entities.append(GeckoPumpSwitch(coordinator, config_entry, 1, "Pump 1"))
        entities.append(GeckoPumpSwitch(coordinator, config_entry, 2, "Pump 2"))
        entities.append(GeckoLightSwitch(coordinator, config_entry, 1, "Light"))
    
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
        display_name: str = "Light",
    ) -> None:
        """Initialize the light switch."""
        super().__init__(coordinator, config_entry, display_name, f"light_zone_{zone_id}")
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
        display_name: str | None = None,
    ) -> None:
        """Initialize the pump switch."""
        name = display_name or f"Pump {pump_id}"
        super().__init__(coordinator, config_entry, name, f"pump_{pump_id}")
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


class GeckoWaterfallSwitch(GeckoBaseSwitchEntity):
    """Representation of a Gecko waterfall switch (uses flow zones)."""

    _attr_icon = "mdi:waterfall"

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
        flow_zone_id: int,
        waterfall_id: int,
        display_name: str = "Waterfall",
    ) -> None:
        """Initialize the waterfall switch."""
        super().__init__(coordinator, config_entry, display_name, f"waterfall_{waterfall_id}")
        self._flow_zone_id = flow_zone_id  # The actual MQTT flow zone to control
        self._waterfall_id = waterfall_id  # The accessory ID for display purposes
        self._optimistic_state = None
        self._optimistic_expiry = None

    @property
    def is_on(self) -> bool:
        """Return true if the waterfall is on."""
        # Check optimistic state first
        if self._optimistic_state is not None and self._optimistic_expiry:
            import datetime
            if datetime.datetime.now() < self._optimistic_expiry:
                return self._optimistic_state
            else:
                self._optimistic_state = None
                self._optimistic_expiry = None
        
        # Fall back to coordinator data - waterfalls are in the pumps/flow zone data
        if self.coordinator.data and self.coordinator.data.get("pumps"):
            pumps_data = self.coordinator.data["pumps"]
            flow_zone_info = pumps_data.get(self._flow_zone_id, {})
            return flow_zone_info.get("active", False)
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the waterfall on."""
        self._set_optimistic_state(True)
        # Waterfalls use flow zones, so call set_pump_state with the flow zone ID
        self.coordinator.controller.set_pump_state(self._flow_zone_id, True)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the waterfall off."""
        self._set_optimistic_state(False)
        # Waterfalls use flow zones, so call set_pump_state with the flow zone ID
        self.coordinator.controller.set_pump_state(self._flow_zone_id, False)

    def _set_optimistic_state(self, state: bool) -> None:
        """Set optimistic state with expiry."""
        import datetime
        self._optimistic_state = state
        self._optimistic_expiry = datetime.datetime.now() + datetime.timedelta(seconds=10)
        self.async_write_ha_state()


class GeckoBlowerSwitch(GeckoBaseSwitchEntity):
    """Representation of a Gecko blower switch (uses flow zones)."""

    _attr_icon = "mdi:fan"

    def __init__(
        self,
        coordinator: GeckoDataUpdateCoordinator,
        config_entry: ConfigEntry,
        flow_zone_id: int,
        blower_id: int,
        display_name: str = "Blower",
    ) -> None:
        """Initialize the blower switch."""
        super().__init__(coordinator, config_entry, display_name, f"blower_{blower_id}")
        self._flow_zone_id = flow_zone_id  # The actual MQTT flow zone to control
        self._blower_id = blower_id  # The accessory ID for display purposes
        self._optimistic_state = None
        self._optimistic_expiry = None

    @property
    def is_on(self) -> bool:
        """Return true if the blower is on."""
        # Check optimistic state first
        if self._optimistic_state is not None and self._optimistic_expiry:
            import datetime
            if datetime.datetime.now() < self._optimistic_expiry:
                return self._optimistic_state
            else:
                self._optimistic_state = None
                self._optimistic_expiry = None
        
        # Fall back to coordinator data - blowers are in the pumps/flow zone data
        if self.coordinator.data and self.coordinator.data.get("pumps"):
            pumps_data = self.coordinator.data["pumps"]
            flow_zone_info = pumps_data.get(self._flow_zone_id, {})
            return flow_zone_info.get("active", False)
        return False

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the blower on."""
        self._set_optimistic_state(True)
        # Blowers use flow zones, so call set_pump_state with the flow zone ID
        self.coordinator.controller.set_pump_state(self._flow_zone_id, True)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the blower off."""
        self._set_optimistic_state(False)
        # Blowers use flow zones, so call set_pump_state with the flow zone ID
        self.coordinator.controller.set_pump_state(self._flow_zone_id, False)

    def _set_optimistic_state(self, state: bool) -> None:
        """Set optimistic state with expiry."""
        import datetime
        self._optimistic_state = state
        self._optimistic_expiry = datetime.datetime.now() + datetime.timedelta(seconds=10)
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
