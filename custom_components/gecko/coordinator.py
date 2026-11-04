"""Data update coordinator for Gecko."""

from __future__ import annotations

import asyncio
import inspect
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from aiohttp import ClientResponseError
from homeassistant.exceptions import ConfigEntryAuthFailed
from datetime import timedelta
from typing import Any, Dict, List

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

# Import from geckoIotClient
from .gecko_iot_client.models.zone_types import ZoneType, AbstractZone

from .aws_compat import AwsCrtCompatibilityError
from .const import DOMAIN
from .connection_manager import async_get_connection_manager
from .telemetry import (
    DEVICE_TELEMETRY_KEYS,
    get_device_metadata_candidate_paths,
    get_device_telemetry,
    get_device_telemetry_sources,
    redact_raw_api_payload,
)

_LOGGER = logging.getLogger(__name__)

# Constants
UPDATE_INTERVAL_SECONDS = 30  # seconds between coordinator updates
MAX_CONSECUTIVE_FAILURES = 3  # max failures before attempting reconnect
RECONNECT_DELAY = 1  # seconds to wait before reconnecting
INITIAL_ZONE_TIMEOUT = 60.0  # seconds to wait for initial zone data
MAX_RECONNECT_BACKOFF = 300  # max seconds between reconnect attempts (5 min)


class GeckoVesselCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator for a single Gecko vessel/spa following Home Assistant best practices."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry_id: str,
        vessel_id: str,
        monitor_id: str,
        vessel_name: str,
    ) -> None:
        """Initialize the vessel coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{vessel_id}",
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
        )
        self.entry_id = entry_id
        self.vessel_id = vessel_id
        self.monitor_id = monitor_id
        self.vessel_name = vessel_name
        
        # Store zones for this vessel only (no monitor_id dictionary needed)
        self._zones: Dict[ZoneType, List[AbstractZone]] = {}
        
        # Store real-time state data for this vessel
        self._spa_state: Dict[str, Any] = {}

        # Device telemetry is commonly omitted from shadow delta updates. Keep
        # the last explicitly reported value for each field.
        self._device_telemetry: Dict[str, Any] = {
            key: None for key in DEVICE_TELEMETRY_KEYS
        }
        self._device_telemetry_sources: Dict[str, str | None] = {
            key: None for key in DEVICE_TELEMETRY_KEYS
        }
        self._device_metadata_candidate_paths: set[str] = set()
        self._raw_api_payloads: dict[str, Any] = {}
        
        # Track if this vessel has received initial zone data
        self._has_initial_zones = False
        
        # Event to signal when initial zone data is loaded
        self._initial_zones_loaded_event = asyncio.Event()
        
        # Callbacks for zone updates (for dynamic entity creation)
        self._zone_update_callbacks: list = []
        
        # Simple connection tracking
        self._consecutive_failures = 0
        self._reconnect_attempts = 0
        self._token_refresh_task = None
        self._token_backoff_until = 0.0
        self._token_failures = 0
        self._fresh_broker_url = None
        self._fresh_broker_at = 0.0
        self.waterlab_readings = {}
        self.waterlab_available = False
        self.waterlab_last_success = None
        self._waterlab_next_poll = 0.0
        self._waterlab_poll_disabled = False

    def register_zone_update_callback(self, callback):
        """Register a callback to be called when zone data updates."""
        self._zone_update_callbacks.append(callback)

    async def _async_handle_zone_update(self, data: dict[str, Any]) -> None:
        """Handle zone update in the event loop."""
        # Trigger entity discovery when zones are updated
        self.async_set_updated_data(data)
        
        _LOGGER.debug("Zone data updated for vessel %s", self.vessel_name)

        # Call registered callbacks for dynamic entity creation
        for callback in self._zone_update_callbacks:
            try:
                if callable(callback) and callback is not None:
                    result = callback()
                    # If callback returns a coroutine, await it
                    if inspect.iscoroutine(result):
                        await result
            except Exception as ex:
                _LOGGER.error("Error in zone update callback for vessel %s: %s", self.vessel_name, ex, exc_info=True)

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from Gecko API."""
        try:
            # Check if connection exists and is active
            connection_manager = await async_get_connection_manager(self.hass)
            connection = connection_manager.get_connection(self.monitor_id)
            
            if not connection or not connection.is_connected:
                self._consecutive_failures += 1
                
                # After MAX_CONSECUTIVE_FAILURES, try to reconnect with progressive backoff
                if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    _LOGGER.warning(
                        "Connection lost for %s (%d consecutive failures), attempting reconnect",
                        self.vessel_name,
                        self._consecutive_failures,
                    )
                    await self._simple_reconnect()
                    # Don't reset failures here — only reset on success
            else:
                # Connection is healthy, reset all failure counters
                self._consecutive_failures = 0
                self._reconnect_attempts = 0
            
            # Data will be updated by geckoIotClient callbacks
            return {"status": "active", "vessel_id": self.vessel_id}
        except Exception as exception:
            raise UpdateFailed(f"Error communicating with Gecko API for vessel {self.vessel_name}: {exception}") from exception

    async def _async_update_waterlab(self) -> None:
        """Poll optional read-only chemistry without affecting MQTT availability."""
        from datetime import datetime, timezone
        from aiohttp import ClientError, ClientResponseError
        from homeassistant.exceptions import ConfigEntryAuthFailed
        from .waterlab import extract_readings

        now = self.hass.loop.time()
        if self._waterlab_poll_disabled or now < self._waterlab_next_poll:
            return
        entry = self.hass.config_entries.async_get_entry(self.entry_id)
        if not entry or not getattr(entry, "runtime_data", None) or not entry.data.get("account_id"):
            return
        self._waterlab_next_poll = now + 300
        try:
            async with asyncio.timeout(15):
                detail = await entry.runtime_data.api_client.async_get_vessel_detail(
                    str(entry.data["account_id"]), str(self.vessel_id)
                )
            self.waterlab_readings = extract_readings(detail)
            self.waterlab_available = True
            self.waterlab_last_success = datetime.now(timezone.utc).isoformat()
        except ConfigEntryAuthFailed:
            self.waterlab_available = False
            entry.async_start_reauth(self.hass)
        except ClientResponseError as err:
            self.waterlab_available = False
            # Optional endpoint may not be available for this account/device.
            if err.status in (403, 404):
                self._waterlab_poll_disabled = True
            elif err.status == 429:
                try:
                    delay = max(300, float((err.headers or {}).get("Retry-After", 300)))
                except ValueError:
                    delay = 300
                self._waterlab_next_poll = now + delay
            _LOGGER.debug("Waterlab request unavailable (HTTP %s)", err.status)
        except (ClientError, TimeoutError, ValueError, TypeError):
            self.waterlab_available = False
            _LOGGER.debug("Waterlab request unavailable", exc_info=True)
        for callback in self._zone_update_callbacks:
            try:
                result = callback()
                if inspect.iscoroutine(result):
                    await result
            except Exception:
                _LOGGER.exception("Waterlab entity discovery failed")
        self.async_update_listeners()

    def async_start_waterlab_polling(self, entry) -> None:
        """Use an independent timer so busy MQTT traffic cannot defer chemistry."""
        from homeassistant.helpers.event import async_track_time_interval

        def schedule_poll(_now=None):
            entry.async_create_background_task(
                self.hass, self._async_update_waterlab(), f"Gecko Waterlab {self.vessel_id}"
            )

        from homeassistant.core import callback
        schedule_poll = callback(schedule_poll)
        entry.async_on_unload(async_track_time_interval(self.hass, schedule_poll, timedelta(seconds=300)))
        schedule_poll()

    def get_zones_by_type(self, zone_type: ZoneType) -> List[AbstractZone]:
        """Get zones of a specific type for this vessel (no monitor_id needed)."""
        return self._zones.get(zone_type, [])

    def get_all_zones(self) -> Dict[ZoneType, List[AbstractZone]]:
        """Get all zones for this vessel."""
        return self._zones

    async def _simple_reconnect(self) -> None:
        """Simple reconnection with progressive backoff.

        Uses exponential backoff to avoid hammering the API when it's down.
        The geckoIotClient handles its own token refresh internally, but if
        the connection manager level reconnect is needed (e.g., after the
        transporter gave up), this provides a higher-level retry.
        """
        now = self.hass.loop.time()
        next_allowed = max(getattr(self, "_next_reconnect_time", 0.0), self._token_backoff_until)
        if now < next_allowed:
            _LOGGER.debug(
                "Skipping reconnect for %s; next attempt in %.0fs",
                self.vessel_name,
                next_allowed - now,
            )
            return

        self._reconnect_attempts += 1

        # Progressive backoff: don't retry too aggressively at coordinator level
        # The transporter already has its own backoff, so this is a last-resort retry
        backoff_delay = min(
            30 * (2 ** (self._reconnect_attempts - 1)), MAX_RECONNECT_BACKOFF
        )
        self._next_reconnect_time = now + backoff_delay

        _LOGGER.info(
            "Reconnect attempt %d for %s (next allowed in %.0fs)",
            self._reconnect_attempts,
            self.vessel_name,
            backoff_delay,
        )

        # Don't block the coordinator update with a long sleep — just attempt once
        # The next coordinator update cycle will retry if still disconnected
        try:
            connection_manager = await async_get_connection_manager(self.hass)
            
            # Reconnect - the geckoIotClient will automatically call the token
            # refresh callback to get a fresh URL with new tokens
            success = await connection_manager.async_reconnect_monitor(self.monitor_id)
            
            if success:
                _LOGGER.info("Reconnected %s after %d attempts", self.vessel_name, self._reconnect_attempts)
                self._consecutive_failures = 0
                self._reconnect_attempts = 0
            else:
                _LOGGER.warning(
                    "Failed to reconnect %s (attempt %d) - will retry no sooner than %ds",
                    self.vessel_name,
                    self._reconnect_attempts,
                    backoff_delay,
                )
                
        except Exception as e:
            _LOGGER.error(
                "Failed to reconnect %s (attempt %d): %s",
                self.vessel_name,
                self._reconnect_attempts,
                e,
            )

    async def get_gecko_client(self):
        """Get the gecko client for this vessel's monitor."""
        try:
            connection_manager = await async_get_connection_manager(self.hass)
            connection = connection_manager.get_connection(self.monitor_id)

            if connection and connection.is_connected:
                return connection.gecko_client
            else:
                _LOGGER.warning("No active connection found for vessel %s (monitor %s)", self.vessel_name, self.monitor_id)
                return None

        except Exception as e:
            _LOGGER.error("Failed to get gecko client for vessel %s: %s", self.vessel_name, e)
            return None

    async def _async_request_broker_url(self) -> str | None:
        """Request a token once; called only from the Home Assistant loop."""
        entry = self.hass.config_entries.async_get_entry(self.entry_id)
        if entry is None or entry.runtime_data is None:
            return None
        try:
            data = await entry.runtime_data.api_client.async_get_monitor_livestream(self.monitor_id)
            url = data.get("brokerUrl")
            if not isinstance(url, str) or not url:
                raise ValueError("Gecko returned no broker URL")
            self._fresh_broker_url = url
            self._fresh_broker_at = self.hass.loop.time()
            self._token_failures = 0
            self._token_backoff_until = 0.0
            return url
        except ConfigEntryAuthFailed:
            entry.async_start_reauth(self.hass)
            delay = 300
        except Exception as err:
            self._token_failures += 1
            delay = min(30 * (2 ** min(self._token_failures - 1, 4)), 300)
            if isinstance(err, ClientResponseError) and err.status == 429:
                retry_after = (err.headers or {}).get("Retry-After", "")
                try:
                    delay = max(delay, float(retry_after))
                except (TypeError, ValueError):
                    try:
                        retry_date = parsedate_to_datetime(retry_after)
                        delay = max(delay, (retry_date - datetime.now(timezone.utc)).total_seconds())
                    except (TypeError, ValueError, OverflowError):
                        pass
            _LOGGER.warning("Could not refresh Gecko session for %s; retry in %.0fs: %s", self.vessel_name, delay, err)
        self._token_backoff_until = self.hass.loop.time() + delay
        return None

    async def _async_get_fresh_broker_url(self) -> str | None:
        """Coalesce concurrent worker refreshes and avoid API retry storms."""
        now = self.hass.loop.time()
        if now < self._token_backoff_until:
            return None
        if self._fresh_broker_url and now - self._fresh_broker_at < 5:
            return self._fresh_broker_url
        if self._token_refresh_task is None or self._token_refresh_task.done():
            self._token_refresh_task = self.hass.async_create_task(self._async_request_broker_url())
        return await asyncio.shield(self._token_refresh_task)

    def _create_refresh_token_callback(self, websocket_url: str):
        """Bridge synchronous MQTT workers to a single async token request."""
        def refresh_token_callback(monitor_id=None):
            future = asyncio.run_coroutine_threadsafe(self._async_get_fresh_broker_url(), self.hass.loop)
            try:
                return future.result(timeout=30)
            except TimeoutError:
                future.cancel()
                return None
            except Exception as err:
                _LOGGER.warning("Gecko token refresh failed for %s: %s", self.vessel_name, err)
                return None
        return refresh_token_callback

    async def async_setup_monitor_connection(self, websocket_url: str) -> bool:
        """Set up a connection to this vessel's monitor using the singleton connection manager."""
        try:
            # Get the singleton connection manager
            connection_manager = await async_get_connection_manager(self.hass)
            
            # Create update callback for this vessel's coordinator
            def on_zone_update(updated_zones):
                # Store the updated zones from GeckoIotClient (these have state managers!)
                self._zones = updated_zones
                
                # Mark this vessel as having received zones
                if not self._has_initial_zones:
                    self._has_initial_zones = True
                    if not self._initial_zones_loaded_event.is_set():
                        self._initial_zones_loaded_event.set()
                
                # Schedule the async call to run on the event loop from background thread
                asyncio.run_coroutine_threadsafe(
                    self._async_handle_zone_update({"last_update": "zone_update"}),
                    self.hass.loop
                )

            def on_state_update(state_data):
                self.update_spa_state(state_data)

            def on_configuration_update(configuration):
                self.update_device_telemetry(
                    configuration,
                    source_name="MQTT configuration",
                )
            
            # Create refresh token callback
            refresh_token_callback = self._create_refresh_token_callback(websocket_url)
                
            # Get or create connection with refresh token callback
            await connection_manager.async_get_or_create_connection(
                monitor_id=self.monitor_id,
                websocket_url=websocket_url,
                vessel_name=self.vessel_name,
                update_callback=on_zone_update,
                state_callback=on_state_update,
                configuration_callback=on_configuration_update,
                refresh_token_callback=refresh_token_callback,
            )
            
            return True
            
        except AwsCrtCompatibilityError:
            # Preserve the actionable compatibility failure so setup can defer
            # safely instead of replacing it with a generic ConnectionError.
            raise
        except Exception as e:
            _LOGGER.error("Failed to set up connection for vessel %s: %s", self.vessel_name, e, exc_info=True)
            return False

    async def async_get_operation_mode_status(self):
        """Get operation mode status for this vessel's monitor."""
        gecko_client = await self.get_gecko_client()
        if gecko_client:
            return gecko_client.operation_mode_status
        return None

    def update_spa_state(self, state_data: Dict[str, Any]) -> None:
        """Update spa state data and trigger coordinator update."""
        self._spa_state = state_data
        self.update_device_telemetry(state_data, source_name="MQTT shadow")

        # Schedule the async call to run on the event loop from background thread
        asyncio.run_coroutine_threadsafe(
            self._async_handle_zone_update({"last_update": state_data}),
            self.hass.loop
        )

    def update_device_telemetry(
        self,
        source_data: Dict[str, Any],
        source_name: str = "API payload",
    ) -> None:
        """Retain device telemetry found in state or configuration data."""
        self._raw_api_payloads[source_name] = redact_raw_api_payload(source_data)
        extracted = get_device_telemetry(source_data)
        source_paths = get_device_telemetry_sources(source_data)
        self._device_metadata_candidate_paths.update(
            f"{source_name}: {path}"
            for path in get_device_metadata_candidate_paths(source_data)
        )
        for key, value in extracted.items():
            if value is not None and source_paths[key]:
                self._device_telemetry[key] = value
                self._device_telemetry_sources[key] = (
                    f"{source_name}: {source_paths[key]}"
                )

    async def async_wait_for_initial_zone_data(self, timeout: float = INITIAL_ZONE_TIMEOUT) -> bool:
        """Wait for this vessel to receive its initial zone data."""
        try:
            await asyncio.wait_for(self._initial_zones_loaded_event.wait(), timeout=timeout)
            _LOGGER.debug("Initial zone data loaded for vessel %s within timeout", self.vessel_name)
            return True
        except asyncio.TimeoutError:
            _LOGGER.warning("Timeout waiting for initial zone data for vessel %s", self.vessel_name)
            return False

    def get_spa_state(self) -> Dict[str, Any] | None:
        """Get spa state data for this vessel."""
        return self._spa_state

    def get_device_telemetry(self) -> Dict[str, Any]:
        """Return the latest known RF and EN/CO device telemetry."""
        return self._device_telemetry.copy()

    def get_device_telemetry_source(self, key: str) -> str | None:
        """Return the API payload and field path used for a telemetry value."""
        return self._device_telemetry_sources.get(key)

    def get_device_metadata_candidate_paths(self) -> tuple[str, ...]:
        """Return raw metadata-like API field paths seen for this vessel."""
        return tuple(sorted(self._device_metadata_candidate_paths))

    def get_raw_api_payloads(self) -> dict[str, Any]:
        """Return the latest credential-redacted payload from each API source."""
        return redact_raw_api_payload(self._raw_api_payloads)

    async def async_shutdown(self) -> None:
        """Shutdown coordinator and cleanup resources."""
        _LOGGER.debug("Shutting down coordinator for vessel %s (entry %s)", self.vessel_name, self.entry_id)
        
        try:
            # Connection manager will handle cleanup during Home Assistant shutdown
            # We don't disconnect here as the connection may be shared
            _LOGGER.debug("Coordinator releasing vessel %s (monitor %s)", self.vessel_name, self.monitor_id)
            
        except Exception as ex:
            _LOGGER.warning("Error during coordinator shutdown for vessel %s: %s", self.vessel_name, ex)
        
        if self._token_refresh_task and not self._token_refresh_task.done():
            self._token_refresh_task.cancel()
            await asyncio.gather(self._token_refresh_task, return_exceptions=True)
        self._zones.clear()
        self._spa_state.clear()
        self._device_telemetry.clear()
        self._device_telemetry_sources.clear()
        self._device_metadata_candidate_paths.clear()
        self._raw_api_payloads.clear()
        self._zone_update_callbacks.clear()
