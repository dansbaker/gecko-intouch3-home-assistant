"""Support for Gecko fan entities (pumps with speed control)."""

from __future__ import annotations

import asyncio
import logging
import math
from homeassistant.exceptions import HomeAssistantError
from typing import Any

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import GeckoVesselCoordinator
from .entity import GeckoEntityAvailabilityMixin, GeckoZoneEntityMixin
from . import GeckoConfigEntry
from .telemetry import (
    derive_flow_percentage,
    get_flow_speed_step_values,
    _reports_binary_near_max_speed_encoding,
    derive_flow_speed_mode,
    get_flow_initiators,
    get_non_user_flow_initiators,
    get_flow_speed_mode_for_percentage,
    get_flow_speed_value_for_mode,
    get_supported_flow_speed_modes,
    is_checkflow_active,
    is_filtration_flow_active,
    is_flow_safe_to_deactivate,
    is_user_controlled_flow_active,
)

from .gecko_iot_client.models.zone_types import ZoneType, FlowZoneType
from .gecko_iot_client.models.flow_zone import FlowZone, FlowZoneCapabilities

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GeckoConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Gecko fan entities from a config entry."""
    runtime_data = config_entry.runtime_data
    if not runtime_data or not runtime_data.coordinators:
        _LOGGER.error("No coordinators found in runtime_data for config entry %s", config_entry.entry_id)
        return
    created_entity_ids: set[tuple[str, str]] = set()
    def create_discovery_callback(coordinator: GeckoVesselCoordinator):
        def discover_new_fan_entities():
            new_entities = []
            vessel_coordinator: GeckoVesselCoordinator = coordinator
            pump_zones = vessel_coordinator.get_zones_by_type(ZoneType.FLOW_ZONE)
            flow_zones = [zone for zone in pump_zones if isinstance(zone, FlowZone)]
            for zone in flow_zones:
                # Names can collide (or be renamed); discovery identity must use
                # the same stable vessel and zone identifiers as unique_id.
                entity_id = (
                    str(vessel_coordinator.vessel_id),
                    str(zone.id),
                )
                if entity_id not in created_entity_ids:
                    entity = GeckoFan(vessel_coordinator, config_entry, zone)
                    new_entities.append(entity)
                    created_entity_ids.add(entity_id)
                    _LOGGER.debug("Created fan entity for vessel %s, zone %s", vessel_coordinator.vessel_name, zone.id)
            if new_entities:
                async_add_entities(new_entities)
        return discover_new_fan_entities
    for coordinator in runtime_data.coordinators:
        discovery_callback = create_discovery_callback(coordinator)
        discovery_callback()
        coordinator.register_zone_update_callback(discovery_callback)

class GeckoFan(GeckoZoneEntityMixin, GeckoEntityAvailabilityMixin, CoordinatorEntity, FanEntity):
    """Physical pump state with separate manual and automatic demand telemetry."""

    _attr_has_entity_name = True
    _zone_type = ZoneType.FLOW_ZONE

    def __init__(self, coordinator, config_entry, zone: FlowZone) -> None:
        super().__init__(coordinator)
        self._coordinator = coordinator
        self._zone = zone
        self._attr_name = zone.name
        self._attr_unique_id = f"{config_entry.entry_id}_{coordinator.vessel_id}_pump_{zone.id}"
        self._attr_device_info = dr.DeviceInfo(identifiers={(DOMAIN, str(coordinator.vessel_id))})
        self._attr_icon = {
            FlowZoneType.WATERFALL_ZONE: "mdi:waterfall",
            FlowZoneType.BLOWER_ZONE: "mdi:wind-power",
        }.get(zone.type, "mdi:pump")
        self._attr_available = False
        self._attr_speed = None
        self._update_from_zone()

    @property
    def is_on(self):
        return self._attr_is_on

    @property
    def speed_count(self) -> int:
        zone = self._current_zone()
        if zone is None:
            return 1
        steps = get_flow_speed_step_values(zone)
        return len(steps) or (2 if _reports_binary_near_max_speed_encoding(zone) else 1)

    def _update_from_zone(self) -> None:
        zone = self._current_zone()
        if zone is None:
            return
        self._attr_supported_features = FanEntityFeature.TURN_ON | FanEntityFeature.TURN_OFF
        if self.speed_count > 1:
            self._attr_supported_features |= FanEntityFeature.SET_SPEED
        self._attr_is_on = zone.active
        self._attr_percentage = derive_flow_percentage(zone)
        self._attr_speed = derive_flow_speed_mode(zone)
        initiators = zone.initiators
        self._attr_extra_state_attributes = {
            "initiators": None if initiators is None else [getattr(i, "value", i) for i in initiators],
            "manual_demand": is_user_controlled_flow_active(zone, self.coordinator.get_spa_state()),
            "automatic_initiators": sorted(get_non_user_flow_initiators(zone, self.coordinator.get_spa_state())),
            "filtration_active": is_filtration_flow_active(zone, self.coordinator.get_spa_state()),
            "checkflow_active": is_checkflow_active(zone, self.coordinator.get_spa_state()),
            "physical_speed": self._attr_speed,
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_from_zone()
        self.async_write_ha_state()

    async def async_turn_on(self, percentage=None, preset_mode=None, **kwargs) -> None:
        zone = self._current_zone()
        if zone is None:
            return
        if percentage is not None:
            await self.async_set_percentage(percentage)
        elif get_flow_speed_step_values(zone):
            await self.async_set_percentage(1)
        else:
            await self._async_zone_command(zone.activate)

    async def async_set_percentage(self, percentage: int) -> None:
        if percentage <= 0:
            await self.async_turn_off()
            return
        zone = self._current_zone()
        if zone is None:
            return
        steps = get_flow_speed_step_values(zone)
        if steps:
            index = math.ceil(min(100, percentage) * len(steps) / 100) - 1
            speed = steps[max(0, index)]
        elif _reports_binary_near_max_speed_encoding(zone):
            speed = 50 if percentage <= 50 else 100
        else:
            # Without a configured ladder, do not invent numeric command values.
            await self._async_zone_command(zone.activate)
            return
        if len(steps) == 2 and not zone.active and speed == steps[-1] and zone.speed == speed:
            await self._start_low_first(zone, steps[0])
        await self._async_zone_command(zone.set_speed, speed)

    async def _start_low_first(self, zone, low):
        """Adapt @lacroixdavid1's low-first start; require a real device report."""
        started = asyncio.Event()
        before = zone.report_sequence

        @callback
        def reported_running():
            current = self._current_zone()
            if current is zone and current.report_sequence > before and current.reported_active is True:
                started.set()

        remove = self.coordinator.async_add_listener(reported_running)
        try:
            await self._async_zone_command(zone.set_speed, low)
            async with asyncio.timeout(15):
                await started.wait()
            if self._current_zone() is not zone:
                raise HomeAssistantError("Spa reconnected during pump startup; retry the command")
        except TimeoutError as err:
            raise HomeAssistantError("Pump has not confirmed running; it may still start at low speed") from err
        finally:
            remove()

    async def async_turn_off(self, **kwargs) -> None:
        zone = self._current_zone()
        if zone is None:
            return
        try:
            await self._async_zone_command(zone.deactivate)
        except RuntimeError as err:
            raise HomeAssistantError(str(err)) from err

    async def async_set_speed(self, speed: str) -> None:
        """Compatibility entry point; commands use configured values."""
        if speed == "off":
            await self.async_turn_off()
            return
        zone = self._current_zone()
        if zone is None:
            return
        steps = get_flow_speed_step_values(zone)
        if steps:
            index = {"low": 0, "medium": (len(steps) - 1) // 2, "high": len(steps) - 1, "max": len(steps) - 1}.get(speed)
            if index is None:
                raise HomeAssistantError(f"Unsupported pump speed: {speed}")
            await self.async_set_percentage(math.ceil((index + 1) * 100 / len(steps)))
        elif _reports_binary_near_max_speed_encoding(zone) and speed in ("low", "high", "max"):
            await self._async_zone_command(zone.set_speed, 50 if speed == "low" else 100)
        else:
            await self._async_zone_command(zone.activate)
