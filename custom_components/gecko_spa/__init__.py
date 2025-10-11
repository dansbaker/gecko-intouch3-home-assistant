"""The Gecko Spa integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady, ConfigEntryAuthFailed

from .const import DOMAIN
from .coordinator import GeckoDataUpdateCoordinator
from .version import __version__

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.CLIMATE, Platform.SWITCH]

type GeckoConfigEntry = ConfigEntry[GeckoDataUpdateCoordinator]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Gecko Spa integration via YAML is not supported."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: GeckoConfigEntry) -> bool:
    """Set up Gecko Spa from a config entry."""
    
    try:
        # Get data from the config entry (new format with full API discovery)
        oauth_access_token = entry.data.get("oauth_access_token")
        oauth_refresh_token = entry.data.get("oauth_refresh_token")
        account_id = entry.data.get("account_id")
        vessel_id = entry.data.get("vessel_id")
        monitor_id = entry.data.get("monitor_id")
        vessel_name = entry.data.get("vessel_name", "Unknown Hot Tub")
        aws_credentials = entry.data.get("aws_credentials")
        spa_config = entry.data.get("spa_config", {})
        
        # Validate required fields
        if not oauth_access_token or not oauth_refresh_token:
            _LOGGER.error("No OAuth tokens found in config entry")
            raise ConfigEntryAuthFailed("No OAuth tokens - please reconfigure")
            
        if not account_id or not vessel_id or not monitor_id:
            _LOGGER.error("Missing account/vessel/monitor IDs in config entry")
            raise ConfigEntryAuthFailed("Missing device information - please reconfigure")
            
        if not aws_credentials:
            _LOGGER.error("No AWS credentials found in config entry")
            raise ConfigEntryAuthFailed("No AWS credentials - please reconfigure")
        
        _LOGGER.info("Setting up Gecko integration for %s (account: %s, vessel: %s, monitor: %s)", 
                    vessel_name, account_id, vessel_id, monitor_id)
        
        # Log spa configuration info
        if spa_config:
            accessories = spa_config.get("accessories", {})
            pumps = accessories.get("pumps", {})
            lights = accessories.get("lights", {})
            waterfalls = accessories.get("waterfalls", {})
            blowers = accessories.get("blowers", {})
            _LOGGER.info("Spa configuration: %d pump(s), %d light(s), %d waterfall(s), %d blower(s)",
                        len(pumps), len(lights), len(waterfalls), len(blowers))
        else:
            _LOGGER.warning("No spa configuration found - will use default entities")
        
        # Create the data coordinator
        coordinator = GeckoDataUpdateCoordinator(
            hass,
            oauth_access_token,
            oauth_refresh_token,
            account_id,
            vessel_id,
            monitor_id,
            vessel_name,
            aws_credentials,
            spa_config,
        )
        
        # Set config entry for token updates
        coordinator.set_config_entry(entry)
        
        # Test the connection before proceeding
        _LOGGER.info("Testing Gecko integration connection...")
        try:
            await coordinator._async_setup_controller()
            _LOGGER.info("Gecko integration connection test successful")
        except Exception as ex:
            error_msg = str(ex).lower()
            if any(keyword in error_msg for keyword in ['token', 'auth', 'invalid_grant', 'expired', 'unauthorized']):
                _LOGGER.error("Authentication failed - tokens expired or invalid. Please reconfigure.")
                raise ConfigEntryAuthFailed("Authentication failed - please reconfigure with fresh tokens") from ex
            else:
                # Other connection issues should be treated as temporary
                _LOGGER.warning("Gecko integration connection test failed: %s", ex)
                raise ConfigEntryNotReady(f"Connection test failed: {ex}") from ex
        
        # Store the coordinator in runtime_data (HA 2023.6+ pattern)
        entry.runtime_data = coordinator
        
        # Set up platforms
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        
        _LOGGER.info("Gecko Spa integration setup completed successfully")
        return True
        
    except ConfigEntryAuthFailed:
        _LOGGER.error("Authentication failed - tokens expired or invalid. Please reconfigure.")
        raise
    except ConfigEntryNotReady:
        # Re-raise temporary issues
        raise
    except Exception as ex:
        _LOGGER.error("Unexpected error during setup: %s", ex, exc_info=True)
        raise ConfigEntryNotReady(f"Setup failed: {ex}") from ex


async def async_unload_entry(hass: HomeAssistant, entry: GeckoConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        # Clean up coordinator
        if entry.runtime_data:
            await entry.runtime_data.async_shutdown()
    
    return unload_ok
