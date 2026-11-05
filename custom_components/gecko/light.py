"""Support for Gecko light entities."""

from __future__ import annotations

import logging

from homeassistant.components.light import ColorMode, LightEntity, LightEntityFeature
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GeckoConfigEntry
from .const import DOMAIN
from .coordinator import GeckoVesselCoordinator
from .entity import GeckoEntityAvailabilityMixin, GeckoZoneEntityMixin
from .gecko_iot_client.helpers.lighting import rgbi_payload, split_brightness
from .gecko_iot_client.models.zone_types import ZoneType

# Explicit platform concurrency: commands are serialized.
PARALLEL_UPDATES = 1

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: GeckoConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Gecko light entities from a config entry."""

    # Get runtime data with per-vessel coordinators
    runtime_data = getattr(config_entry, "runtime_data", None)
    if not runtime_data or not runtime_data.coordinators:
        _LOGGER.error(
            "No coordinators found in runtime_data for config entry %s",
            config_entry.entry_id,
        )
        return

    # Track created entities to avoid duplicates
    created_entity_ids: set[tuple[str, str]] = set()

    # Create entity discovery function for each coordinator
    def create_discovery_callback(coordinator: GeckoVesselCoordinator):
        """Create a discovery callback for a specific coordinator."""

        def discover_new_light_entities():
            """Discover new light entities for new zones."""
            new_entities = []

            # Get light zones for this vessel's coordinator (no monitor_id needed)
            light_zones = coordinator.get_zones_by_type(ZoneType.LIGHTING_ZONE)

            for zone in light_zones:
                # Check if entity already exists
                # Vessel names are user-editable and are not guaranteed to be
                # unique.  Key discovery by the stable vessel/zone identifiers
                # so identically named spas do not suppress each other's lights.
                entity_id = (str(coordinator.vessel_id), str(zone.id))
                if entity_id not in created_entity_ids:
                    entity = GeckoLight(coordinator, config_entry, zone)
                    new_entities.append(entity)
                    created_entity_ids.add(entity_id)

            if new_entities:
                async_add_entities(new_entities)

        return discover_new_light_entities

    # Set up entities for each vessel coordinator
    for coordinator in runtime_data.coordinators:
        # Initial entity discovery for this coordinator
        discovery_callback = create_discovery_callback(coordinator)
        discovery_callback()

        # Register callback for dynamic entity creation
        coordinator.register_zone_update_callback(discovery_callback)


class GeckoLight(
    GeckoZoneEntityMixin, GeckoEntityAvailabilityMixin, CoordinatorEntity, LightEntity
):
    """Light controls adapted from PR 57; device reports always win."""

    _attr_has_entity_name = True
    _zone_type = ZoneType.LIGHTING_ZONE

    def __init__(self, coordinator, config_entry, zone) -> None:
        super().__init__(coordinator)
        self._zone = zone
        self._attr_name = zone.name
        self._attr_unique_id = (
            f"{config_entry.entry_id}_{coordinator.vessel_id}_light_{zone.id}"
        )
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))}
        )
        self._known_effects = set()
        self._cached_base_rgb = None
        self._cached_brightness = None
        self._attr_available = False
        self._update_state()

    def _get_zone_state(self):
        return self._current_zone()

    def _update_state(self) -> None:
        zone = self._current_zone()
        if zone is None:
            self._attr_is_on = None
            return
        self._attr_is_on = zone.active
        color_supported = zone.rgbi is not None
        self._attr_supported_color_modes = {
            ColorMode.RGB if color_supported else ColorMode.ONOFF
        }
        self._attr_color_mode = ColorMode.RGB if color_supported else ColorMode.ONOFF
        self._attr_supported_features = LightEntityFeature(0)
        if zone.effect is not None or self._known_effects:
            self._attr_supported_features |= LightEntityFeature.EFFECT
        if color_supported:
            rgb = (zone.rgbi.r, zone.rgbi.g, zone.rgbi.b)
            brightness = max(rgb)
            # Retain full-precision hue only when the report matches it. There
            # is no indefinite previous-color suppression: app changes win.
            predicted = None
            if (
                self._cached_base_rgb is not None
                and self._cached_brightness is not None
            ):
                predicted = tuple(
                    round(value * self._cached_brightness / 255)
                    for value in self._cached_base_rgb
                )
            if rgb != predicted:
                if brightness:
                    self._cached_base_rgb = tuple(
                        min(255, round(value * 255 / brightness)) for value in rgb
                    )
                elif self._cached_base_rgb is None:
                    self._cached_base_rgb = (255, 255, 255)
                self._cached_brightness = brightness
            self._attr_rgb_color = self._cached_base_rgb
            self._attr_brightness = self._cached_brightness
        else:
            self._attr_rgb_color = None
            self._attr_brightness = None
            self._cached_base_rgb = None
            self._cached_brightness = None
        self._attr_effect = zone.effect
        if zone.effect:
            self._known_effects.add(zone.effect)
        self._attr_effect_list = sorted(self._known_effects) or None

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_state()
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs) -> None:
        zone = self._require_zone()
        color = kwargs.get("rgb_color")
        brightness = kwargs.get("brightness")
        if (color is not None or brightness is not None) and zone.rgbi is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="light_color_unsupported"
            )
        effect = kwargs.get("effect")
        if effect is not None:
            await self._async_zone_command(zone.set_effect, effect)
            self._known_effects.add(effect)
        if (color is not None or brightness is not None) and zone.rgbi is not None:
            base = (
                color
                if color is not None
                else (self._cached_base_rgb or (255, 255, 255))
            )
            level = (
                brightness
                if brightness is not None
                else (
                    self._cached_brightness
                    if self._cached_brightness is not None
                    else 255
                )
            )
            normalized, _ = split_brightness(tuple(base))
            payload = rgbi_payload(tuple(base), level)
            await self._async_zone_command(zone.set_color, *payload)
            self._cached_base_rgb = tuple(normalized)
            self._cached_brightness = level
        elif effect is None:
            await self._async_zone_command(zone.activate)

    async def async_turn_off(self, **kwargs) -> None:
        zone = self._require_zone()
        await self._async_zone_command(zone.deactivate)
