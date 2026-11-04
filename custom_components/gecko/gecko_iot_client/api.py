"""API for Gecko bound to Home Assistant OAuth."""

import logging
from abc import ABC, abstractmethod
from typing import Any

from aiohttp import ClientSession

from .const import API_BASE_URL, AUTH0_BASE_URL

_LOGGER = logging.getLogger(__name__)


class GeckoApiClient(ABC):
    """Provide Gecko authentication tied to an OAuth2 based config entry."""

    def __init__(
        self,
        websession: ClientSession,
        api_url: str = API_BASE_URL,
        auth0_url: str = AUTH0_BASE_URL,
    ) -> None:
        """
        Initialize Gecko auth.

        Args:
            websession: aiohttp ClientSession for making HTTP requests
            api_url: Base URL for Gecko API (default: production API)
            auth0_url: Base URL for Auth0 authentication (default: production Auth0)
        """
        self.websession = websession
        self.api_url = api_url
        self.auth0_url = auth0_url

    @abstractmethod
    async def async_get_access_token(self) -> str:
        """
        Return a valid access token for the Gecko API.

        This method must be implemented by subclasses to provide
        OAuth2 token management.

        Returns:
            Valid access token string
        """

    async def async_get_user_id(self) -> dict[str, Any]:
        """
        Get user information from Auth0 or Gecko API.

        Returns:
            User ID (sub claim) from Auth0

        Raises:
            ValueError: If user ID not found in Auth0 response
        """
        token = await self.async_get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        # Get from Auth0 userinfo
        url = f"{self.auth0_url}/userinfo"
        async with self.websession.get(url, headers=headers) as response:
            response.raise_for_status()
            payload = await response.json()
            _LOGGER.debug("Fetched user info from Auth0")
        try:
            return payload["sub"]
        except KeyError:
            raise ValueError(
                "User ID ('sub') not found in Auth0 response: %s" % payload
            )

    async def async_request(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        """
        Make an authenticated request to the Gecko API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path (e.g., "/v4/accounts/123/vessels")
            **kwargs: Additional arguments to pass to aiohttp request

        Returns:
            JSON response from the API

        Raises:
            aiohttp.ClientResponseError: If the request fails
        """
        access_token = await self.async_get_access_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {access_token}"

        url = f"{self.api_url}{endpoint}"
        _LOGGER.debug("Making %s request to %s", method, endpoint)

        async with self.websession.request(
            method, url, headers=headers, **kwargs
        ) as response:
            response.raise_for_status()
            payload = await response.json()
            return payload

    async def async_get_vessels(self, account_id: str) -> list[dict[str, Any]]:
        """
        Get available vessels for the account.

        Args:
            account_id: Account ID to fetch vessels for

        Returns:
            List of vessel dictionaries
        """
        _LOGGER.debug("Fetching vessels for account")
        data = await self.async_request("GET", f"/v4/accounts/{account_id}/vessels")

        # Check if data is a dict with a 'vessels' key or similar
        if isinstance(data, dict):
            # Try common response wrapper patterns
            if "vessels" in data:
                return data["vessels"]
            elif "data" in data:
                return data["data"] if isinstance(data["data"], list) else []
            elif "results" in data:
                return data["results"] if isinstance(data["results"], list) else []

        return data if isinstance(data, list) else []

    async def async_get_user_info(self, user_id: str) -> dict[str, Any]:
        """
        Get user information from Gecko API.

        Args:
            user_id: User ID to fetch information for

        Returns:
            User information dictionary
        """

        _LOGGER.debug("Fetching user info")

        return await self.async_request("GET", f"/v2/user/{user_id}")

    async def async_get_monitor_livestream(self, monitor_id: str) -> dict[str, Any]:
        """
        Get MQTT livestream connection details for a monitor.

        Args:
            monitor_id: Monitor ID to get livestream details for

        Returns:
            Dictionary with MQTT connection details including endpoint and credentials
        """
        livestream_data = await self.async_request(
            "GET", f"/v1/monitors/{monitor_id}/iot/thirdPartySession"
        )
        _LOGGER.debug("Fetched livestream data")
        return livestream_data
