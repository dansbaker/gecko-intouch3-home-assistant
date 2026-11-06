"""Support for Gecko climate entities (temperature control)."""

from __future__ import annotations

import logging
import math
from typing import Any, ClassVar

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GeckoConfigEntry
from .const import DOMAIN, WATERCARE_SELECTABLE_MODES
from .coordinator import GeckoVesselCoordinator
from .entity import GeckoEntityAvailabilityMixin, GeckoZoneEntityMixin
from .gecko_iot_client.models.temperature_control_zone import (
    TemperatureControlZone,
    TemperatureControlZoneStatus,
)
from .gecko_iot_client.models.zone_types import ZoneType

# Explicit platform concurrency: commands are serialized.
PARALLEL_UPDATES = 1

_LOGGER = logging.getLogger(__name__)


# Maps the device's granular status to Home Assistant's HVACAction.
# TemperatureControlZoneStatus.HEAT_PUMP_ERROR has no HVACAction
# equivalent (HVACAction has no "error" value), so it's mapped to IDLE
# here and surfaced separately instead - see the heat_pump_error extra
# state attribute below.
_HVAC_ACTION_BY_STATUS = {
    TemperatureControlZoneStatus.IDLE: HVACAction.IDLE,
    TemperatureControlZoneStatus.HEATING: HVACAction.HEATING,
    TemperatureControlZoneStatus.COOLING: HVACAction.IDLE,
    TemperatureControlZoneStatus.INVALID: HVACAction.IDLE,
    TemperatureControlZoneStatus.HEAT_PUMP_HEATING: HVACAction.HEATING,
    TemperatureControlZoneStatus.HEAT_PUMP_AND_HEATER_HEATING: HVACAction.HEATING,
    TemperatureControlZoneStatus.HEAT_PUMP_COOLING: HVACAction.COOLING,
    TemperatureControlZoneStatus.HEAT_PUMP_DEFROSTING: HVACAction.DEFROSTING,
    TemperatureControlZoneStatus.HEAT_PUMP_ERROR: HVACAction.IDLE,
}

# Maps the device's granular status to a plain-language heat source,
# for the heat_source extra state attribute below - lets automations
# and dashboards distinguish pure electric heating from heat-pump
# (potentially combined with electric) heating, which HVACAction alone
# can't express.
_HEAT_SOURCE_BY_STATUS = {
    TemperatureControlZoneStatus.IDLE: "none",
    TemperatureControlZoneStatus.HEATING: "electric",
    TemperatureControlZoneStatus.COOLING: "none",
    TemperatureControlZoneStatus.INVALID: "none",
    TemperatureControlZoneStatus.HEAT_PUMP_HEATING: "heat_pump",
    TemperatureControlZoneStatus.HEAT_PUMP_AND_HEATER_HEATING: "heat_pump_and_electric",
    TemperatureControlZoneStatus.HEAT_PUMP_COOLING: "heat_pump",
    TemperatureControlZoneStatus.HEAT_PUMP_DEFROSTING: "heat_pump",
    TemperatureControlZoneStatus.HEAT_PUMP_ERROR: "none",
}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GeckoConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Gecko climate entities from a config entry."""
    runtime = getattr(config_entry, "runtime_data", None)
    coordinators = runtime.coordinators if runtime else []

    # Track which zones have already been added for each coordinator
    added_zones: dict[str, set[int]] = {}

    @callback
    def discover_new_climate_entities(coordinator: GeckoVesselCoordinator) -> None:
        """Discover climate entities for temperature control zones."""
        zones = coordinator.get_zones_by_type(ZoneType.TEMPERATURE_CONTROL_ZONE)

        # Get or create the set of added zone IDs for this coordinator
        vessel_key = f"{coordinator.entry_id}_{coordinator.vessel_id}"
        if vessel_key not in added_zones:
            added_zones[vessel_key] = set()

        entities = []
        for zone in zones:
            # Only add if not already added
            if zone.id not in added_zones[vessel_key]:
                entities.append(GeckoClimate(coordinator, zone))
                added_zones[vessel_key].add(zone.id)

        if entities:
            async_add_entities(entities)
            _LOGGER.debug(
                "Added %d climate entities for vessel %s",
                len(entities),
                coordinator.vessel_name,
            )
        else:
            _LOGGER.debug(
                "No new climate entities to add for vessel %s", coordinator.vessel_name
            )

    # Set up initial entities and register for updates
    for coordinator in coordinators:
        discover_new_climate_entities(coordinator)
        coordinator.register_zone_update_callback(
            lambda coord=coordinator: discover_new_climate_entities(coord)
        )


# Home Assistant 2026.11 moved climate temperatures to the native_* API. The old
# names still work there with a deprecation warning, until 2027.11.
_NATIVE_TEMPERATURE_API = hasattr(ClimateEntity, "native_current_temperature")


class GeckoClimate(
    GeckoZoneEntityMixin,
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    ClimateEntity,
):
    """Representation of a Gecko climate control."""

    _attr_has_entity_name = True
    _attr_translation_key = "thermostat"
    _zone_type = ZoneType.TEMPERATURE_CONTROL_ZONE
    if _NATIVE_TEMPERATURE_API:
        _attr_native_temperature_unit = UnitOfTemperature.CELSIUS
    else:
        _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE | ClimateEntityFeature.PRESET_MODE
    )
    _attr_preset_modes: ClassVar[list[str]] = list(WATERCARE_SELECTABLE_MODES)
    _attr_hvac_modes: ClassVar[list[HVACMode]] = [HVACMode.HEAT]
    _attr_hvac_mode = HVACMode.HEAT
    _attr_target_temperature_step = 0.5

    def __init__(
        self,
        coordinator: GeckoVesselCoordinator,
        zone: TemperatureControlZone,
    ) -> None:
        """Initialize the climate control."""
        super().__init__(coordinator)
        self._zone = zone
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_climate_{zone.id}"
        )
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))}
        )
        self._attr_translation_placeholders = {"zone_id": str(zone.id)}

        # Set temperature limits
        self._attr_min_temp = self._zone.min_temperature_set_point_c
        self._attr_max_temp = self._zone.max_temperature_set_point_c

        # Initialize availability (will be set by async_added_to_hass event registration)
        self._attr_available = False

        # Initialize state from zone
        self._update_from_zone()

    def _update_from_zone(self) -> None:
        """Update state attributes from zone data."""
        zone = self._current_zone()
        if zone is None:
            # Not on the current client: keep the last known state.
            return
        self._attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
        if (
            self.hass is not None
            and getattr(
                self._get_gecko_client_sync(), "operation_mode_controller", None
            )
            is not None
        ):
            self._attr_supported_features |= ClimateEntityFeature.PRESET_MODE
        status = zone.status
        self._attr_hvac_action = _HVAC_ACTION_BY_STATUS.get(status, HVACAction.IDLE)
        self._attr_extra_state_attributes = {
            "eco_mode": zone.mode.eco if zone.mode else None,
            "device_status": status.name if status is not None else None,
            "heat_source": _HEAT_SOURCE_BY_STATUS.get(status, "none"),
            "heat_pump_error": status == TemperatureControlZoneStatus.HEAT_PUMP_ERROR,
        }

        if _NATIVE_TEMPERATURE_API:
            self._attr_native_current_temperature = zone.temperature
            self._attr_native_target_temperature = zone.target_temperature
        else:
            self._attr_current_temperature = zone.temperature
            self._attr_target_temperature = zone.target_temperature
        self._attr_max_temp = zone.max_temperature_set_point_c
        self._attr_min_temp = zone.min_temperature_set_point_c

        _LOGGER.debug(
            "Zone %s: current=%s°C, target=%s°C",
            zone.id,
            zone.temperature,
            zone.target_temperature,
        )

    async def async_added_to_hass(self) -> None:
        """Discover optional Watercare control from the live client."""
        await super().async_added_to_hass()
        self._update_from_zone()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        _LOGGER.debug("Updating climate entity %s", self.entity_id)
        self._update_from_zone()
        self.async_write_ha_state()

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set new target temperature."""
        if (temperature := kwargs.get("temperature")) is None:
            return

        zone = self._require_zone()
        if (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or (isinstance(temperature, float) and not math.isfinite(temperature))
            or zone.min_temperature_set_point_c is None
            or zone.max_temperature_set_point_c is None
            or not zone.min_temperature_set_point_c
            <= temperature
            <= zone.max_temperature_set_point_c
        ):
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="invalid_temperature"
            )
        await self._async_zone_command(zone.set_target_temperature, temperature)

    @property
    def preset_mode(self) -> str | None:
        """Return the current watercare mode."""
        gecko_client = self._get_gecko_client_sync()
        controller = getattr(gecko_client, "operation_mode_controller", None)
        if controller is None:
            return None
        mode_name = controller.mode_name
        return mode_name if mode_name in WATERCARE_SELECTABLE_MODES else None

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set the watercare mode."""
        if preset_mode not in WATERCARE_SELECTABLE_MODES:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_preset_mode",
            )

        gecko_client = self._get_gecko_client_sync()
        controller = getattr(gecko_client, "operation_mode_controller", None)
        if controller is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="watercare_unavailable"
            )

        # Publishing blocks until MQTT delivery is confirmed: keep it off the loop.
        await self._async_zone_command(controller.set_mode_by_name, preset_mode)
        _LOGGER.debug("Set watercare mode to %s for %s", preset_mode, self.entity_id)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        if hvac_mode != HVACMode.HEAT:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_hvac_mode",
            )

        # HEAT mode is the only supported mode and is always active
        _LOGGER.debug(
            "HVAC mode set to HEAT for %s (no action required)", self.entity_id
        )
