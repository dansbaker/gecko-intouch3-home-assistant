"""DataUpdateCoordinator for Gecko Spa integration."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.config_entries import ConfigEntryAuthFailed, ConfigEntry

# Import our existing Gecko controller
from .gecko_controller import GeckoHotTubController
from .auth0_client import GeckoAuth0Client

_LOGGER = logging.getLogger(__name__)

class GeckoDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the Gecko Spa."""

    def __init__(
        self,
        hass: HomeAssistant,
        oauth_access_token: str,
        oauth_refresh_token: str,
        account_id: int,
        vessel_id: int,
        monitor_id: str,
        vessel_name: str,
        aws_credentials: dict[str, Any],
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name="Gecko Spa",
            update_interval=timedelta(minutes=5),  # Reduce polling - now event-driven
        )
        
        # OAuth tokens for Gecko API
        self.oauth_access_token = oauth_access_token
        self.oauth_refresh_token = oauth_refresh_token
        
        # Device info discovered during setup
        self.account_id = account_id
        self.vessel_id = vessel_id
        self.monitor_id = monitor_id
        self.vessel_name = vessel_name
        
        # AWS credentials for IoT connection
        self.aws_credentials = aws_credentials
        
        # Controller state
        self._controller: GeckoHotTubController | None = None
        self._connected = False
        self.config_entry: ConfigEntry | None = None

    def set_config_entry(self, config_entry: ConfigEntry) -> None:
        """Set the config entry for token updates."""
        self.config_entry = config_entry

    @property
    def controller(self) -> GeckoHotTubController | None:
        """Return the controller instance."""
        return self._controller

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from the Gecko controller."""
        try:
            # Check if tokens need refreshing before doing any operations
            if await self._should_refresh_tokens():
                _LOGGER.info("Tokens need refreshing, attempting refresh...")
                refresh_success = await self.refresh_tokens()
                if not refresh_success:
                    _LOGGER.error("Token refresh failed, may need reauthentication")
                    raise ConfigEntryAuthFailed("OAuth tokens expired and refresh failed")
            
            # Initialize controller if not done
            if not self._controller:
                _LOGGER.info("Initializing Gecko controller for the first time")
                await self._async_setup_controller()
            
            # Check if controller connection is actually working
            if not self._controller.connected:
                _LOGGER.warning("Controller not connected, attempting to reconnect")
                await self._async_setup_controller()
                
            # Get current state from controller
            data = {}
            _LOGGER.debug("Fetching data from Gecko controller")
            
            # Add diagnostic info about controller state
            _LOGGER.debug("Controller instance: %s, Connected: %s", 
                         type(self._controller).__name__ if self._controller else None, 
                         self._connected)
            
            # Get temperature data
            try:
                _LOGGER.debug("📊 Calling controller.get_temperature()...")
                temp_info = await self.hass.async_add_executor_job(self._controller.get_temperature)
                _LOGGER.debug("📊 get_temperature() returned: %s (type: %s)", temp_info, type(temp_info))
                
                if temp_info:
                    _LOGGER.info("🌡️ Temperature data retrieved: current=%s, target=%s, heating=%s", 
                               temp_info.current_temp, temp_info.set_point, temp_info.heating_status)
                    data["temperature"] = {
                        "current_temp": temp_info.current_temp,
                        "target_temp": temp_info.set_point,  # Use set_point instead of target_temp
                        "heating_status": temp_info.heating_status,
                        "unit": "°C"
                    }
                else:
                    _LOGGER.warning("❌ No temperature data available from controller")
                    # Check if controller has shadow state at all
                    if hasattr(self._controller, 'last_shadow_state'):
                        shadow = getattr(self._controller, 'last_shadow_state')
                        _LOGGER.warning("🔍 Controller shadow state: %s (type: %s)", 
                                    shadow, type(shadow) if shadow else None)
                        if shadow:
                            _LOGGER.info("🔍 Shadow state keys: %s", list(shadow.keys()) if isinstance(shadow, dict) else "Not a dict")
                            if isinstance(shadow, dict):
                                _LOGGER.info("🔍 Full shadow state: %s", json.dumps(shadow, indent=2, default=str))
            except Exception as err:
                _LOGGER.warning("❌ Failed to get temperature data: %s", err, exc_info=True)
                
            # Get system status
            try:
                system_status = await self.hass.async_add_executor_job(self._controller.get_system_status)
                if system_status:
                    _LOGGER.debug("System status retrieved")
                    data["system"] = system_status
            except Exception as err:
                _LOGGER.debug("System status not available: %s", err)
                
            # Get shadow state for lights/pumps status
            if hasattr(self._controller, 'last_shadow_state') and self._controller.last_shadow_state:
                shadow = self._controller.last_shadow_state
                _LOGGER.info("🔍 Shadow state available with %d keys: %s", len(shadow), list(shadow.keys()) if isinstance(shadow, dict) else "Not a dict")
                _LOGGER.info("🔍 Full shadow state payload: %s", json.dumps(shadow, indent=2, default=str))
                data["shadow_state"] = shadow
                
                # Extract light status from shadow state properly
                try:
                    lighting_zones = shadow.get('zones', {}).get('lighting', {})
                    if lighting_zones:
                        lights_status = {}
                        any_light_on = False
                        for zone_id, zone_data in lighting_zones.items():
                            is_active = zone_data.get('active', False)
                            lights_status[int(zone_id)] = is_active
                            if is_active:
                                any_light_on = True
                        
                        data["lights"] = lights_status
                        data["lights_on"] = any_light_on
                        _LOGGER.info("💡 Lights status: %s (any on: %s)", lights_status, any_light_on)
                    else:
                        data["lights_on"] = False
                        _LOGGER.info("💡 No lighting zones found")
                except Exception as err:
                    _LOGGER.warning("💡 Failed to parse light status: %s", err)
                    
                # Extract pump/flow status from shadow state properly
                try:
                    flow_zones = shadow.get('zones', {}).get('flow', {})
                    if flow_zones:
                        pumps_status = {}
                        any_pump_on = False
                        for zone_id, zone_data in flow_zones.items():
                            is_active = zone_data.get('active', False)
                            pump_info = {
                                "active": is_active,
                                "speed": zone_data.get('speed', 0),
                                "initiators": zone_data.get('initiators_', [])
                            }
                            pumps_status[int(zone_id)] = pump_info
                            if is_active:
                                any_pump_on = True
                        
                        data["pumps"] = pumps_status
                        data["jets_on"] = any_pump_on
                        _LOGGER.info("🌊 Pumps status: %s (any on: %s)", pumps_status, any_pump_on)
                    else:
                        data["jets_on"] = False
                        _LOGGER.info("🌊 No flow zones found")
                except Exception as err:
                    _LOGGER.warning("🌊 Failed to parse pump status: %s", err)
            else:
                _LOGGER.warning("❌ No shadow state available yet - MQTT data not received")
                    
            _LOGGER.debug("Data update completed with %d keys: %s", len(data), list(data.keys()))
            return data
            
        except Exception as err:
            _LOGGER.error("Error fetching data from Gecko controller: %s", err, exc_info=True)
            self._connected = False
            raise UpdateFailed(f"Error communicating with controller: {err}") from err

    async def _should_refresh_tokens(self) -> bool:
        """Check if OAuth tokens need refreshing based on expiry time."""
        if not self.config_entry:
            return False
            
        token_expires_at = self.config_entry.data.get("oauth_token_expires_at")
        if not token_expires_at:
            # No expiry info, assume we should refresh
            return True
            
        try:
            from datetime import datetime, timedelta
            # Parse the expiry time
            expiry_time = datetime.fromisoformat(token_expires_at)
            # Refresh if token expires within the next 5 minutes
            return datetime.now() >= (expiry_time - timedelta(minutes=5))
        except (ValueError, TypeError):
            # If we can't parse the expiry time, assume refresh is needed
            _LOGGER.warning("Could not parse token expiry time: %s", token_expires_at)
            return True

    async def refresh_tokens(self) -> bool:
        """Refresh the OAuth tokens using the Auth0Client and get new AWS credentials."""
        try:
            _LOGGER.info("Refreshing OAuth tokens for monitor %s", self.monitor_id)
            
            # Use our new Auth0Client for robust token refresh
            auth_client = GeckoAuth0Client(self.hass)
            
            try:
                # Attempt to refresh the existing token
                token_data = await auth_client.refresh_token(self.oauth_refresh_token)
                
                # Update OAuth tokens
                self.oauth_access_token = token_data["access_token"]
                if "refresh_token" in token_data:
                    self.oauth_refresh_token = token_data["refresh_token"]
                
                _LOGGER.info("OAuth tokens refreshed successfully")
                
            except Exception as refresh_error:
                _LOGGER.warning("Token refresh failed: %s", refresh_error)
                # If token refresh fails, we'll need to trigger reauthentication
                # This will be handled by the coordinator's error handling
                return False
                
            # Step 2: Get new AWS credentials with refreshed OAuth token
            from homeassistant.helpers.aiohttp_client import async_get_clientsession
            session = async_get_clientsession(self.hass)
            
            livestream_url = f"https://api.geckowatermonitor.com/v2/monitors/{self.monitor_id}/liveStream"
            headers = {
                "Authorization": f"Bearer {self.oauth_access_token}",
                "Content-Type": "application/json",
            }
            
            async with session.get(livestream_url, headers=headers) as aws_response:
                if aws_response.status == 200:
                    self.aws_credentials = await aws_response.json()
                    _LOGGER.info("AWS credentials refreshed successfully")
                else:
                    _LOGGER.error("Failed to refresh AWS credentials: %s", aws_response.status)
                    return False
            
            # Step 3: Update config entry with new tokens and credentials
            if self.config_entry:
                new_data = dict(self.config_entry.data)
                new_data["oauth_access_token"] = self.oauth_access_token
                new_data["oauth_refresh_token"] = self.oauth_refresh_token
                new_data["aws_credentials"] = self.aws_credentials
                from datetime import datetime, timedelta
                new_data["oauth_token_expires_at"] = (datetime.now() + timedelta(seconds=token_data.get("expires_in", 3600))).isoformat()
                
                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data=new_data
                )
            
            _LOGGER.info("OAuth tokens and AWS credentials refreshed successfully")
            return True
                    
        except Exception as e:
            _LOGGER.error("Token refresh error: %s", e)
            return False

    async def _async_setup_controller(self) -> None:
        """Set up the Gecko controller."""
        try:
            _LOGGER.info("Setting up Gecko controller with monitor_id: %s", self.monitor_id)
            
            if self._controller:
                # Clean up existing controller
                _LOGGER.debug("Cleaning up existing controller connection")
                try:
                    await self.hass.async_add_executor_job(self._controller.__exit__, None, None, None)
                except Exception as cleanup_err:
                    _LOGGER.warning("Error during controller cleanup: %s", cleanup_err)
                    
            # Create new controller using OAuth tokens (preferred method)
            _LOGGER.debug("Creating new Gecko controller instance with OAuth tokens")
            
            self._controller = GeckoHotTubController(
                access_token=self.oauth_access_token,
                refresh_token=self.oauth_refresh_token,
                monitor_id=self.monitor_id
            )
            
            # Connect in executor
            _LOGGER.info("Connecting to Gecko hot tub via AWS IoT...")
            await self.hass.async_add_executor_job(self._controller.__enter__)
            self._connected = True
            _LOGGER.info("Gecko controller connected successfully")
            
            # Register for real-time shadow state updates
            self._controller.register_shadow_callback(self._on_shadow_update)
            _LOGGER.info("Registered for real-time MQTT shadow updates")
            
            # Add diagnostic information about connection
            if hasattr(self._controller, 'mqtt5_client') and self._controller.mqtt5_client:
                _LOGGER.debug("MQTT5 client created successfully")
            else:
                _LOGGER.warning("No MQTT client found on controller")
            
            # Give time for initial shadow state to be received
            _LOGGER.debug("Waiting 5 seconds for initial shadow state...")
            await asyncio.sleep(5)
            
            # Check if shadow state was received
            if hasattr(self._controller, 'last_shadow_state'):
                shadow = getattr(self._controller, 'last_shadow_state')
                if shadow:
                    _LOGGER.info("Initial shadow state received: %d keys", len(shadow) if isinstance(shadow, dict) else 0)
                else:
                    _LOGGER.warning("No shadow state received after connection")
            else:
                _LOGGER.warning("Controller does not have last_shadow_state attribute")
            
        except Exception as err:
            _LOGGER.error("Failed to setup Gecko controller: %s", err, exc_info=True)
            self._connected = False
            
            # Check if this is an authentication error
            error_msg = str(err).lower()
            if any(keyword in error_msg for keyword in ['token', 'auth', 'invalid_grant', 'expired', 'unauthorized']):
                _LOGGER.info("Authentication failed - attempting token refresh...")
                
                # Try to refresh tokens
                if await self.refresh_tokens():
                    _LOGGER.info("Token refresh successful, retrying connection...")
                    # Retry connection with new credentials
                    try:
                        # Update controller with new AWS credentials
                        broker_url = self.aws_credentials.get("brokerUrl")
                        if not broker_url:
                            raise ValueError("No brokerUrl found in refreshed AWS credentials")
                            
                        self._controller = GeckoHotTubController(
                            broker_url=broker_url
                        )
                        await self.hass.async_add_executor_job(self._controller.__enter__)
                        self._connected = True
                        _LOGGER.info("Retry connection successful after token refresh")
                        return
                    except Exception as retry_err:
                        _LOGGER.error("Retry connection failed: %s", retry_err)
                
                _LOGGER.error("Token refresh failed - requires reconfiguration")
                raise ConfigEntryAuthFailed("Authentication failed - please reconfigure with fresh credentials") from err
            
            raise

    def _extract_light_status(self, shadow_state: dict) -> bool:
        """Extract light status from shadow state."""
        # This is a simplified extraction - you may need to adjust based on actual shadow structure
        try:
            # Look for common light indicators in the shadow state
            state_str = str(shadow_state).lower()
            if "light" in state_str:
                return "on" in state_str or "true" in state_str
        except Exception:
            pass
        return False

    def _extract_pump_status(self, shadow_state: dict) -> bool:
        """Extract pump/jets status from shadow state."""
        try:
            # Look for pump indicators
            state_str = str(shadow_state).lower()
            if "pump" in state_str or "jet" in state_str:
                return "on" in state_str or "true" in state_str or "running" in state_str
        except Exception:
            pass
        return False

    async def async_shutdown(self) -> None:
        """Shutdown the coordinator."""
        if self._controller and self._connected:
            try:
                await self.hass.async_add_executor_job(self._controller.__exit__, None, None, None)
                _LOGGER.info("Gecko controller disconnected")
            except Exception as err:
                _LOGGER.error("Error disconnecting controller: %s", err)
            finally:
                self._controller = None
                self._connected = False

    async def async_set_temperature(self, temperature: float) -> None:
        """Set target temperature."""
        if not self._controller or not self._connected:
            raise UpdateFailed("Controller not connected")
            
        try:
            await self.hass.async_add_executor_job(
                self._controller.set_temperature, temperature
            )
            # Trigger immediate update
            await self.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to set temperature: %s", err)
            raise UpdateFailed(f"Failed to set temperature: {err}") from err

    async def async_turn_on_lights(self) -> None:
        """Turn on lights."""
        if not self._controller or not self._connected:
            raise UpdateFailed("Controller not connected")
            
        try:
            await self.hass.async_add_executor_job(self._controller.turn_on_lights)
            # Trigger immediate update
            await self.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to turn on lights: %s", err)
            raise UpdateFailed(f"Failed to turn on lights: {err}") from err

    async def async_turn_off_lights(self) -> None:
        """Turn off lights."""
        if not self._controller or not self._connected:
            raise UpdateFailed("Controller not connected")
            
        try:
            await self.hass.async_add_executor_job(self._controller.turn_off_lights)
            # Trigger immediate update
            await self.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to turn off lights: %s", err)
            raise UpdateFailed(f"Failed to turn off lights: {err}") from err

    async def async_start_pump(self, pump_id: int = 1, speed: int = 75) -> None:
        """Start pump/jets."""
        if not self._controller or not self._connected:
            raise UpdateFailed("Controller not connected")
            
        try:
            await self.hass.async_add_executor_job(
                self._controller.start_pump, pump_id, speed
            )
            # Trigger immediate update
            await self.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to start pump: %s", err)
            raise UpdateFailed(f"Failed to start pump: {err}") from err

    async def async_stop_pump(self, pump_id: int = 1) -> None:
        """Stop pump/jets."""
        if not self._controller or not self._connected:
            raise UpdateFailed("Controller not connected")
            
        try:
            await self.hass.async_add_executor_job(
                self._controller.stop_pump, pump_id
            )
            # Trigger immediate update
            await self.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to stop pump: %s", err)
            raise UpdateFailed(f"Failed to stop pump: {err}") from err

    def _on_shadow_update(self, topic: str, payload: dict) -> None:
        """Handle real-time shadow state updates from MQTT."""
        _LOGGER.info(f"🔔 Real-time shadow update received on topic: {topic}")
        
        # Schedule immediate data refresh in the event loop
        if self.hass:
            self.hass.create_task(self.async_request_refresh())
            _LOGGER.debug("Scheduled immediate entity update due to shadow change")
