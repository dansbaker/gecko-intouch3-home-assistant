"""Base entity mixin for Gecko entities."""

from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .coordinator import GeckoVesselCoordinator
from .gecko_iot_client import GeckoIotClient
from .gecko_iot_client.models.events import EventChannel
from .gecko_iot_client.models.zone_types import AbstractZone, ZoneType

_LOGGER = logging.getLogger(__name__)


class GeckoEntityAvailabilityMixin:
    """Mixin to provide availability checking for Gecko entities using gecko_iot_client events."""

    coordinator: GeckoVesselCoordinator
    hass: HomeAssistant
    _attr_available: bool
    _connectivity_callback_registered: bool = False
    _registered_gecko_client: GeckoIotClient | None = None

    _registered_connectivity_callback = None

    @property
    def available(self) -> bool:
        """Read availability without changing subscriptions or other state."""
        return self._check_is_connected()

    @callback
    def _rebind_connectivity(self) -> None:
        """Follow client replacement only while this entity is registered."""
        current_client = self._get_gecko_client_sync()
        if current_client is self._registered_gecko_client:
            return
        self._unsubscribe_connectivity()
        if current_client is None:
            return

        def dispatch(status):
            self.hass.loop.call_soon_threadsafe(
                self._handle_connectivity_update, current_client, status
            )

        current_client.on(EventChannel.CONNECTIVITY_UPDATE, dispatch)
        self._registered_gecko_client = current_client
        self._registered_connectivity_callback = dispatch
        self._connectivity_callback_registered = True

    @callback
    def _unsubscribe_connectivity(self) -> None:
        """Remove exactly the callback installed on the previously bound client."""
        if self._registered_gecko_client is not None:
            self._registered_gecko_client.off(
                EventChannel.CONNECTIVITY_UPDATE, self._registered_connectivity_callback
            )
        self._registered_gecko_client = None
        self._registered_connectivity_callback = None
        self._connectivity_callback_registered = False

    async def async_added_to_hass(self) -> None:
        """Subscribe when HA adds an enabled entity; remove every subscription."""
        await super().async_added_to_hass()  # type: ignore[misc]
        self._rebind_connectivity()
        self.async_on_remove(self._unsubscribe_connectivity)
        self.async_on_remove(
            self.coordinator.async_add_listener(self._rebind_connectivity)
        )
        self._update_availability()

    @callback
    def _handle_connectivity_update(self, client, status) -> None:
        """Ignore callbacks queued before removal or client replacement."""
        if (
            client is not self._registered_gecko_client
            or client is not self._get_gecko_client_sync()
        ):
            return
        self._update_availability()
        self.async_write_ha_state()

    def _update_availability(self) -> None:
        """Keep cached availability for entity initialization compatibility."""
        self._attr_available = self._check_is_connected()

    def _check_is_connected(self) -> bool:
        """Check if the transport, gateway, and vessel are connected."""
        from .connection_manager import GECKO_CONNECTION_MANAGER_KEY

        connection_manager = self.hass.data.get(GECKO_CONNECTION_MANAGER_KEY)
        if not connection_manager:
            return False

        connection = connection_manager.get_connection(self.coordinator.monitor_id)
        return connection.is_fully_connected if connection else False

    def _get_gecko_client_sync(self) -> GeckoIotClient | None:
        """Get gecko client synchronously from connection manager."""
        from .connection_manager import GECKO_CONNECTION_MANAGER_KEY

        connection_manager = self.hass.data.get(GECKO_CONNECTION_MANAGER_KEY)
        if not connection_manager:
            return None

        connection = connection_manager._connections.get(self.coordinator.monitor_id)
        return connection.gecko_client if connection else None


class GeckoZoneEntityMixin:
    """Resolve an entity's zone on the current gecko client, by zone id.

    A reconnect replaces the GeckoIotClient, and the new client builds new
    zone objects. The zone object an entity was created with then belongs to
    a client that is no longer connected: reading it freezes the entity at
    its last state, and commanding it publishes through a dead transport.
    GeckoLight and GeckoFan.async_set_speed already looked their zone up on
    every call; this gives the other zone entities the same rule.
    """

    coordinator: GeckoVesselCoordinator
    _zone: AbstractZone
    _zone_type: ZoneType

    @property
    def available(self):
        return super().available and self._current_zone() is not None

    async def _async_zone_command(self, method, *args):
        """Keep MQTT waits off the loop and surface delivery errors to HA."""
        try:
            return await self.hass.async_add_executor_job(method, *args)
        except (OSError, RuntimeError, ValueError) as err:
            raise HomeAssistantError(str(err)) from err

    def _current_zone(self) -> AbstractZone | None:
        """Return this entity's zone on the current client, and rebind to it.

        Returns None when the current client has no zone with this id. Callers
        then keep the last known state and refuse to command, rather than fall
        back to the replaced client's object.
        """
        zone = next(
            (
                candidate
                for candidate in self.coordinator.get_zones_by_type(self._zone_type)
                if str(candidate.id) == str(self._zone.id)
            ),
            None,
        )
        if zone is not None:
            self._zone = zone
        return zone
