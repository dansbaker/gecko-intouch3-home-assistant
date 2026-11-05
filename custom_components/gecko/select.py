"""Watercare selection using current reported state and explicit action errors."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import GeckoConfigEntry
from .const import DOMAIN, WATERCARE_SELECTABLE_MODES
from .coordinator import GeckoVesselCoordinator
from .entity import GeckoEntityAvailabilityMixin

# Serialize commands on this platform; push reports remain independent.
PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: GeckoConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add one Watercare selector per current vessel."""
    runtime = getattr(entry, "runtime_data", None)
    if runtime is None:
        return
    async_add_entities(
        [
            GeckoWatercareSelectEntity(
                coordinator, coordinator.vessel_name, coordinator.vessel_id
            )
            for coordinator in runtime.coordinators
        ]
    )


class GeckoWatercareSelectEntity(
    GeckoEntityAvailabilityMixin, CoordinatorEntity, SelectEntity
):
    """Control supported modes without treating unknown 'Other' as a command."""

    _attr_has_entity_name = True
    _attr_translation_key = "watercare_mode"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_options = WATERCARE_SELECTABLE_MODES

    def __init__(
        self, coordinator: GeckoVesselCoordinator, vessel_name: str, vessel_id: str
    ) -> None:
        super().__init__(coordinator)
        # Preserve the existing identifier so automations and registry entries survive.
        self._attr_unique_id = f"{vessel_id}_watercare_mode"
        self._attr_device_info = dr.DeviceInfo(identifiers={(DOMAIN, str(vessel_id))})
        self._attr_current_option = None
        self._attr_available = False

    def _controller(self):
        return getattr(self._get_gecko_client_sync(), "operation_mode_controller", None)

    @property
    def available(self) -> bool:
        return super().available and self._controller() is not None

    @callback
    def _update_state(self) -> None:
        controller = self._controller()
        mode = controller.mode_name if controller is not None else None
        self._attr_current_option = mode if mode in WATERCARE_SELECTABLE_MODES else None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._update_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        # No detached task may outlive a removed entity or race with newer reports.
        self._update_state()
        self.async_write_ha_state()

    async def async_select_option(self, option: str) -> None:
        if option not in WATERCARE_SELECTABLE_MODES:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="unsupported_watercare_mode"
            )
        controller = self._controller()
        if not self.available or controller is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="watercare_unavailable"
            )
        try:
            await self.hass.async_add_executor_job(controller.set_mode_by_name, option)
        except Exception as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="command_failed"
            ) from err
        # A successful publish is not a new reported mode. Push events update state.
