"""Config flow for Gecko Spa integration."""
from __future__ import annotations

import base64
from typing import Any
import aiohttp
import asyncio
import json
import voluptuous as vol
from datetime import datetime, timedelta

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv

from .const import DOMAIN
from .auth0_client import GeckoAuth0Client, GeckoAuth0Error, GeckoAuth0InvalidCredentials, GeckoAuth0ConnectionError

import logging
_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
    }
)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Gecko Spa."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initialized by the user."""
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER_DATA_SCHEMA,
                description_placeholders={
                    "setup_instructions": "Enter your Gecko Connect username and password"
                },
            )

        errors = {}

        try:
            info = await self.validate_user_credentials(
                user_input["username"], 
                user_input["password"]
            )
        except CannotConnect:
            errors["base"] = "cannot_connect"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except GeckoAuth0Error:
            errors["base"] = "auth0_error"
        except GeckoAuth0InvalidCredentials:
            errors["base"] = "auth0_auth_error"
        except GeckoAuth0ConnectionError:
            errors["base"] = "auth0_network_error"
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected exception during authentication")
            errors["base"] = "unknown"
        else:
            return self.async_create_entry(title=info["title"], data=info["data"])

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
            description_placeholders={
                "setup_instructions": "Enter your Gecko Connect username and password"
            },
        )

    async def validate_user_credentials(self, username: str, password: str) -> dict[str, Any]:
        """Validate user credentials and discover account/vessel information."""
        
        _LOGGER.info("🔍 Starting Gecko authentication and discovery for user: %s", username)
        
        # Step 1: Authenticate with Auth0
        auth_client = GeckoAuth0Client(self.hass)
        tokens = await auth_client.authenticate(username, password)
        
        access_token = tokens.get("access_token")
        if not access_token:
            raise InvalidAuth("No access token received from authentication")
        
        refresh_token = tokens.get("refresh_token", access_token)
        expires_in = tokens.get("expires_in", 3600)
        
        _LOGGER.info("✅ Authentication successful, starting account discovery...")
        
        # Step 2: Get user account information (existing logic)
        account_info = await self._get_account_info(access_token)
        if not account_info:
            raise InvalidAuth("Failed to get account information - token may be invalid")
        
        account_id = account_info.get("accountId")
        if not account_id:
            raise InvalidAuth("No accountId found in user account response")
        
        _LOGGER.info("✅ Discovered account ID: %s", account_id)
        
        # Step 3: Get vessels for this account (existing logic)
        vessels = await self._get_vessels(access_token, account_id)
        if not vessels:
            raise CannotConnect("No vessels (hot tubs) found for this account")
        
        _LOGGER.info("✅ Found %d vessel(s) for account %s", len(vessels), account_id)
        
        # For now, use the first vessel (we can enhance this later for multi-vessel support)
        vessel = vessels[0]
        vessel_id = vessel.get("vesselId")
        monitor_id = vessel.get("monitorId")
        vessel_name = vessel.get("name", "Unknown Hot Tub")
        
        if not vessel_id or not monitor_id:
            raise CannotConnect("Vessel is missing vesselId or monitorId")
        
        _LOGGER.info("✅ Using vessel: %s (vesselId: %s, monitorId: %s)", vessel_name, vessel_id, monitor_id)
        
        # Step 4: Get spa configuration (NEW - for dynamic entity creation)
        spa_config = await self._get_spa_configuration(access_token, account_id, monitor_id)
        if not spa_config:
            _LOGGER.warning("⚠️ Failed to get spa configuration - will use defaults")
            spa_config = {}
        else:
            accessories = spa_config.get("accessories", {})
            pumps = accessories.get("pumps", {})
            lights = accessories.get("lights", {})
            waterfalls = accessories.get("waterfalls", {})
            blowers = accessories.get("blowers", {})
            _LOGGER.info("✅ Spa configuration: %d pump(s), %d light(s), %d waterfall(s), %d blower(s)",
                        len(pumps), len(lights), len(waterfalls), len(blowers))
        
        # Step 5: Get AWS credentials using the monitor ID (existing logic)
        aws_credentials = await self._get_aws_credentials(access_token, monitor_id)
        if not aws_credentials:
            raise CannotConnect("Failed to get AWS credentials for hot tub connection")
        
        _LOGGER.info("✅ AWS credentials obtained for monitor %s", monitor_id)
        
        # Set unique_id based on vessel_id to prevent duplicate entries
        await self.async_set_unique_id(str(vessel_id))
        self._abort_if_unique_id_configured()
        
        # Return success info with all discovered data
        return {
            "title": f"{vessel_name} ({vessel_id})",
            "data": {
                "oauth_access_token": access_token,
                "oauth_refresh_token": refresh_token,
                "oauth_token_expires_at": (datetime.now() + timedelta(seconds=expires_in)).isoformat(),
                "account_id": account_id,
                "vessel_id": vessel_id,
                "monitor_id": monitor_id,
                "vessel_name": vessel_name,
                "aws_credentials": aws_credentials,
                "spa_config": spa_config,
            },
        }

    async def _get_account_info(self, access_token: str) -> dict[str, Any] | None:
        """Get user account information."""
        url = "https://api.geckowatermonitor.com/v2/users"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        # Decode JWT to get user info
        try:
            # Simple JWT decode without verification (just split and base64 decode)
            header, payload, signature = access_token.split('.')
            # Add padding if needed (safe calculation)
            payload += '=' * (-len(payload) % 4)
            decoded_payload = base64.urlsafe_b64decode(payload)
            token_data = json.loads(decoded_payload)
            user_id = token_data.get("sub")
            # Use a generic email since we may not have it in the access token
            email = "homeassistant@integration.local"
        except Exception as e:
            _LOGGER.error("Failed to decode JWT token: %s", e)
            raise InvalidAuth("Invalid token format")
        
        # Send minimal payload that works based on curl testing
        payload = {
            "user": {
                "userId": user_id,
                "email": email
            },
            "deviceInfo": {
                "deviceId": "gecko-ha-integration",
                "platform": "android",
                "operatingSystem": "android",
                "model": "Home Assistant",
                "manufacturer": "homeassistant",
                "osVersion": "13",
                "appVersion": "3.7.1",
                "appBuild": "168"
            }
        }
        
        _LOGGER.info("🔍 Calling PUT %s to get account info", url)
        
        try:
            session = async_get_clientsession(self.hass)
            async with session.put(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    account = data.get("account", {})
                    _LOGGER.info("✅ Account info retrieved successfully")
                    return account
                else:
                    error_text = await response.text()
                    _LOGGER.error("❌ PUT %s failed with %s: %s", url, response.status, error_text)
                    return None
        except Exception as e:
            _LOGGER.error("❌ Error calling PUT %s: %s", url, e)
            return None

    async def _get_vessels(self, access_token: str, account_id: int) -> list[dict] | None:
        """Get vessels for the account."""
        url = f"https://api.geckowatermonitor.com/v3/accounts/{account_id}/vessels"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        params = {"customActionsVersion": "5"}
        
        _LOGGER.info("🔍 Calling GET %s to get vessels", url)
        
        try:
            session = async_get_clientsession(self.hass)
            async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    vessels = data.get("vessels", [])
                    _LOGGER.info("✅ Found %d vessel(s)", len(vessels))
                    return vessels
                else:
                    error_text = await response.text()
                    _LOGGER.error("❌ GET %s failed with %s: %s", url, response.status, error_text)
                    return None
        except Exception as e:
            _LOGGER.error("❌ Error calling GET %s: %s", url, e)
            return None

    async def _get_spa_configuration(self, access_token: str, account_id: int, monitor_id: str) -> dict[str, Any] | None:
        """Get spa configuration including pumps, lights, and accessories."""
        url = f"https://api.geckowatermonitor.com/accounts/{account_id}/monitors/{monitor_id}/spa-configuration"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        
        _LOGGER.info("🔍 Calling GET %s to get spa configuration", url)
        
        try:
            session = async_get_clientsession(self.hass)
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    _LOGGER.info("✅ Spa configuration retrieved successfully")
                    _LOGGER.debug("🔧 Spa configuration data: %s", data)
                    return data
                else:
                    error_text = await response.text()
                    _LOGGER.error("❌ GET %s failed with %s: %s", url, response.status, error_text)
                    return None
        except Exception as e:
            _LOGGER.error("❌ Error calling GET %s: %s", url, e)
            return None

    async def _get_aws_credentials(self, oauth_access_token: str, monitor_id: str) -> dict[str, Any] | None:
        """Get AWS credentials from the liveStream endpoint."""
        
        session = async_get_clientsession(self.hass)
        
        try:
            headers = {
                "Authorization": f"Bearer {oauth_access_token}",
                "Content-Type": "application/json",
            }
            
            # Get AWS credentials from liveStream endpoint
            livestream_url = f"https://api.geckowatermonitor.com/v2/monitors/{monitor_id}/liveStream"
            
            _LOGGER.info("🔑 Requesting AWS credentials from: %s", livestream_url)
            _LOGGER.debug("🔑 Request headers: %s", {k: v if k != "Authorization" else f"Bearer {oauth_access_token[:20]}..." for k, v in headers.items()})
            
            async with session.get(livestream_url, headers=headers) as response:
                response_text = await response.text()
                
                _LOGGER.info("�� AWS credentials response status: %s", response.status)
                _LOGGER.debug("🔑 Response headers: %s", dict(response.headers))
                
                if response.status == 200:
                    try:
                        aws_data = json.loads(response_text)
                        _LOGGER.info("✅ Successfully obtained AWS credentials")
                        _LOGGER.debug("🔑 AWS response keys: %s", list(aws_data.keys()) if isinstance(aws_data, dict) else "Not a dict")
                        return aws_data
                    except json.JSONDecodeError as e:
                        _LOGGER.error("❌ Failed to parse AWS credentials JSON: %s", e)
                        _LOGGER.debug("🔑 Raw response text: %s", response_text[:500] + "..." if len(response_text) > 500 else response_text)
                        return None
                else:
                    _LOGGER.error("❌ Failed to get AWS credentials: HTTP %s", response.status)
                    _LOGGER.error("🔑 Error response body: %s", response_text[:1000] + "..." if len(response_text) > 1000 else response_text)
                    
                    # Try to parse error as JSON for better debugging
                    try:
                        error_json = json.loads(response_text)
                        _LOGGER.error("🔑 Parsed error JSON: %s", error_json)
                    except json.JSONDecodeError:
                        _LOGGER.debug("🔑 Error response is not JSON")
                    
                    return None
                    
        except Exception as e:
            _LOGGER.error("❌ Exception getting AWS credentials: %s", e)
            _LOGGER.exception("🔑 Full exception details:")
            return None

    async def async_step_reauth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Perform reauth upon an API authentication error."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Dialog that informs the user that reauth is required."""
        if user_input is None:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema({}),
            )
        return await self.async_step_user()


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
