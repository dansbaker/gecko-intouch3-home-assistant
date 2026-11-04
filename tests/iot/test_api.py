"""
Unit tests for Gecko API client.
"""

import unittest
from unittest.mock import AsyncMock, MagicMock

from aiohttp import ClientSession

from custom_components.gecko.gecko_iot_client.api import GeckoApiClient


class MockGeckoApiClient(GeckoApiClient):
    """Mock implementation of GeckoApiClient for testing."""

    def __init__(
        self, websession, api_url=None, auth0_url=None, access_token="test_token"
    ):
        super().__init__(
            websession,
            api_url or "https://api.test.com",
            auth0_url or "https://auth.test.com",
        )
        self._access_token = access_token

    async def async_get_access_token(self):
        """Return mock access token."""
        return self._access_token


class TestGeckoApiClient(unittest.IsolatedAsyncioTestCase):
    """Test GeckoApiClient functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.websession = MagicMock(spec=ClientSession)
        self.client = MockGeckoApiClient(self.websession)

    async def test_initialization(self):
        """Test client initialization."""
        self.assertEqual(self.client.api_url, "https://api.test.com")
        self.assertEqual(self.client.auth0_url, "https://auth.test.com")
        self.assertEqual(self.client.websession, self.websession)

    async def test_async_get_user_id_success(self):
        """Test getting user ID successfully."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"sub": "user123"})
        mock_response.raise_for_status = MagicMock()

        self.websession.get = MagicMock(return_value=mock_response)
        self.websession.get.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.get.return_value.__aexit__ = AsyncMock()

        user_id = await self.client.async_get_user_id()

        self.assertEqual(user_id, "user123")
        self.websession.get.assert_called_once()
        call_args = self.websession.get.call_args
        self.assertIn("https://auth.test.com/userinfo", call_args[0])
        self.assertEqual(call_args[1]["headers"]["Authorization"], "Bearer test_token")

    async def test_async_get_user_id_missing_sub(self):
        """Test getting user ID when 'sub' is missing."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"other_field": "value"})
        mock_response.raise_for_status = MagicMock()

        self.websession.get = MagicMock(return_value=mock_response)
        self.websession.get.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.get.return_value.__aexit__ = AsyncMock()

        with self.assertRaises(ValueError) as context:
            await self.client.async_get_user_id()

        self.assertIn("User ID ('sub') not found", str(context.exception))

    async def test_async_request_get(self):
        """Test making a GET request."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"data": "test"})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        result = await self.client.async_request("GET", "/test/endpoint")

        self.assertEqual(result, {"data": "test"})
        self.websession.request.assert_called_once()
        call_args = self.websession.request.call_args
        self.assertEqual(call_args[0][0], "GET")
        self.assertIn("https://api.test.com/test/endpoint", call_args[0][1])
        self.assertEqual(call_args[1]["headers"]["Authorization"], "Bearer test_token")

    async def test_async_request_post_with_data(self):
        """Test making a POST request with data."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"success": True})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        result = await self.client.async_request("POST", "/test", json={"key": "value"})

        self.assertEqual(result, {"success": True})
        call_args = self.websession.request.call_args
        self.assertEqual(call_args[0][0], "POST")
        self.assertEqual(call_args[1]["json"], {"key": "value"})

    async def test_async_request_with_custom_headers(self):
        """Test making a request with custom headers."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        await self.client.async_request("GET", "/test", headers={"Custom": "Header"})

        call_args = self.websession.request.call_args
        headers = call_args[1]["headers"]
        self.assertEqual(headers["Authorization"], "Bearer test_token")
        self.assertEqual(headers["Custom"], "Header")

    async def test_async_get_vessels_list_response(self):
        """Test getting vessels when response is a list."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value=[{"id": "vessel1"}, {"id": "vessel2"}]
        )
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        vessels = await self.client.async_get_vessels("account123")

        self.assertEqual(len(vessels), 2)
        self.assertEqual(vessels[0]["id"], "vessel1")

    async def test_async_get_vessels_dict_with_vessels_key(self):
        """Test getting vessels when response is dict with 'vessels' key."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value={"vessels": [{"id": "vessel1"}], "total": 1}
        )
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        vessels = await self.client.async_get_vessels("account123")

        self.assertEqual(len(vessels), 1)
        self.assertEqual(vessels[0]["id"], "vessel1")

    async def test_async_get_vessels_dict_with_data_key(self):
        """Test getting vessels when response is dict with 'data' key."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"data": [{"id": "vessel1"}]})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        vessels = await self.client.async_get_vessels("account123")

        self.assertEqual(len(vessels), 1)

    async def test_async_get_vessels_dict_with_results_key(self):
        """Test getting vessels when response is dict with 'results' key."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={"results": [{"id": "vessel1"}]})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        vessels = await self.client.async_get_vessels("account123")

        self.assertEqual(len(vessels), 1)

    async def test_async_get_vessels_empty_response(self):
        """Test getting vessels with empty response."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(return_value={})
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        vessels = await self.client.async_get_vessels("account123")

        self.assertEqual(vessels, [])

    async def test_async_get_user_info(self):
        """Test getting user info."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value={"name": "Test User", "email": "test@example.com"}
        )
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        user_info = await self.client.async_get_user_info("user123")

        self.assertEqual(user_info["name"], "Test User")
        call_args = self.websession.request.call_args
        self.assertIn("/v2/user/user123", call_args[0][1])

    async def test_async_get_monitor_livestream(self):
        """Test getting monitor livestream data."""
        mock_response = AsyncMock()
        mock_response.json = AsyncMock(
            return_value={"broker_url": "wss://test.com", "token": "abc123"}
        )
        mock_response.raise_for_status = MagicMock()

        self.websession.request = MagicMock(return_value=mock_response)
        self.websession.request.return_value.__aenter__ = AsyncMock(
            return_value=mock_response
        )
        self.websession.request.return_value.__aexit__ = AsyncMock()

        livestream = await self.client.async_get_monitor_livestream("monitor123")

        self.assertEqual(livestream["broker_url"], "wss://test.com")
        call_args = self.websession.request.call_args
        self.assertIn("/v1/monitors/monitor123/iot/thirdPartySession", call_args[0][1])


if __name__ == "__main__":
    unittest.main()
