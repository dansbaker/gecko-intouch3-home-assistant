
import logging
from aiohttp import ClientResponseError
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.config_entry_oauth2_flow import OAuth2TokenRequestError

from homeassistant.helpers import config_entry_oauth2_flow
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import API_BASE_URL, AUTH0_URL_BASE
from .gecko_iot_client import GeckoApiClient
from typing import Any

_LOGGER = logging.getLogger(__name__)

class OAuthGeckoApi(GeckoApiClient):
    """Provide gecko authentication tied to an OAuth2 based config entry."""

    def __init__(
        self,
        hass: HomeAssistant,
        oauth_session: config_entry_oauth2_flow.OAuth2Session,
    ) -> None:
        """Initialize OAuthGeckoApi."""
        websession = async_get_clientsession(hass)
        super().__init__(websession,
                         api_url=API_BASE_URL,
                         auth0_url=AUTH0_URL_BASE)
        self._oauth_session = oauth_session

    async def async_get_access_token(self) -> str:
        """Return a valid access token for the Gecko API."""
        if not self._oauth_session.token.get("refresh_token"):
            raise ConfigEntryAuthFailed("Missing refresh token; please re-authenticate Gecko")
        try:
            await self._oauth_session.async_ensure_token_valid()
        except OAuth2TokenRequestError as err:
            if err.status in (400, 401, 403):
                raise ConfigEntryAuthFailed("Gecko login expired; please re-authenticate") from err
            raise
        except ClientResponseError as err:
            if err.status in (401, 403):
                raise ConfigEntryAuthFailed("Gecko login expired; please re-authenticate") from err
            raise
        token = self._oauth_session.token.get("access_token")
        if not token:
            raise ConfigEntryAuthFailed("Missing access token; please re-authenticate Gecko")
        return token
    
class ConfigFlowGeckoApi(GeckoApiClient):
    """Profile gecko authentication before a ConfigEntry exists.

    This implementation directly provides the token without supporting refresh.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        token: str,
    ) -> None:
        """Initialize ConfigFlowGeckoApi."""
        websession = async_get_clientsession(hass)
        super().__init__(websession,
                         api_url=API_BASE_URL,
                         auth0_url=AUTH0_URL_BASE)
        self._token = token

    async def async_get_access_token(self) -> str:
        """Return the access token for the Gecko API."""
        return self._token
