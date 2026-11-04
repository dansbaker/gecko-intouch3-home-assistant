"""
Unit tests for token manager functionality.
"""

import base64
import json
import unittest
from datetime import datetime, timedelta

from custom_components.gecko.gecko_iot_client.transporters.mqtt.token_manager import TokenManager  # noqa: E402


def _make_jwt_token(exp_timestamp: float) -> str:
    """Create a minimal JWT token with the given expiry timestamp."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp_timestamp}).encode()
    ).rstrip(b"=")
    signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
    return f"{header.decode()}.{payload.decode()}.{signature.decode()}"


def _make_broker_url(token: str) -> str:
    """Create a broker URL with the given token."""
    return (
        f"wss://example.iot.us-east-1.amazonaws.com/mqtt?"
        f"x-amz-customauthorizer-name=MyAuth&"
        f"token={token}&"
        f"x-amz-customauthorizer-signature=sig123"
    )


class TestTokenManagerParsing(unittest.TestCase):
    """Test token parsing from broker URLs."""

    def test_parses_standard_jwt_expiry(self):
        """Test parsing a standard 3-part JWT token."""
        future_exp = (datetime.now() + timedelta(hours=1)).timestamp()
        token = _make_jwt_token(future_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNotNone(manager.expiry)
        # Should be within a second of what we set
        self.assertAlmostEqual(manager.expiry.timestamp(), future_exp, delta=1.0)

    def test_parses_single_part_gecko_token(self):
        """Test parsing a single-part base64-encoded token (Gecko format)."""
        future_exp = (datetime.now() + timedelta(hours=2)).timestamp()
        payload = base64.urlsafe_b64encode(
            json.dumps({"exp": future_exp}).encode()
        ).rstrip(b"=")
        token = payload.decode()
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNotNone(manager.expiry)
        self.assertAlmostEqual(manager.expiry.timestamp(), future_exp, delta=1.0)

    def test_parses_expires_at_claim(self):
        """Test parsing token with 'expiresAt' claim instead of 'exp'."""
        future_exp = (datetime.now() + timedelta(hours=1)).timestamp()
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(
            b"="
        )
        payload = base64.urlsafe_b64encode(
            json.dumps({"expiresAt": future_exp}).encode()
        ).rstrip(b"=")
        signature = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{signature.decode()}"
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNotNone(manager.expiry)

    def test_parses_millisecond_timestamp(self):
        """Test that millisecond timestamps are converted to seconds."""
        future_exp_ms = (datetime.now() + timedelta(hours=1)).timestamp() * 1000
        token = _make_jwt_token(future_exp_ms)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNotNone(manager.expiry)
        # Should be about 1 hour from now, not 1000 hours
        time_to_expiry = (manager.expiry - datetime.now()).total_seconds()
        self.assertGreater(time_to_expiry, 3000)
        self.assertLess(time_to_expiry, 4000)

    def test_handles_missing_token_in_url(self):
        """Test graceful handling when URL has no token parameter."""
        url = "wss://example.iot.us-east-1.amazonaws.com/mqtt?x-amz-customauthorizer-name=MyAuth"

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNone(manager.expiry)

    def test_handles_invalid_token_format(self):
        """Test graceful handling of unparseable token."""
        url = _make_broker_url("not-valid-base64-!!!!")

        manager = TokenManager(url, refresh_buffer_seconds=300)

        # Should not crash, just have no expiry
        self.assertIsNone(manager.expiry)

    def test_handles_token_without_exp_claim(self):
        """Test token that decodes but has no expiry claim."""
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user123", "iat": 12345}).encode()
        ).rstrip(b"=")
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(
            b"="
        )
        signature = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}.{signature.decode()}"
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertIsNone(manager.expiry)


class TestTokenManagerExpiry(unittest.TestCase):
    """Test token expiry detection."""

    def test_is_expired_when_past_expiry(self):
        """Test is_expired returns True for expired token."""
        past_exp = (datetime.now() - timedelta(minutes=5)).timestamp()
        token = _make_jwt_token(past_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertTrue(manager.is_expired())

    def test_is_not_expired_when_future_expiry(self):
        """Test is_expired returns False for valid token."""
        future_exp = (datetime.now() + timedelta(hours=1)).timestamp()
        token = _make_jwt_token(future_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.is_expired())

    def test_is_expired_returns_false_when_no_expiry(self):
        """Test is_expired returns False when expiry couldn't be parsed."""
        url = "wss://example.iot.us-east-1.amazonaws.com/mqtt"
        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.is_expired())

    def test_force_expiry(self):
        """Test force_expiry makes token appear expired."""
        future_exp = (datetime.now() + timedelta(hours=1)).timestamp()
        token = _make_jwt_token(future_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.is_expired())
        manager.force_expiry()
        self.assertTrue(manager.is_expired())


class TestTokenManagerRefreshTiming(unittest.TestCase):
    """Test should_refresh logic."""

    def test_should_refresh_within_buffer(self):
        """Test should_refresh returns True when within buffer period."""
        # Token expires in 200 seconds, buffer is 300 seconds
        near_exp = (datetime.now() + timedelta(seconds=200)).timestamp()
        token = _make_jwt_token(near_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertTrue(manager.should_refresh(is_connected=True))

    def test_should_not_refresh_outside_buffer(self):
        """Test should_refresh returns False when well before buffer."""
        # Token expires in 1 hour, buffer is 300 seconds
        future_exp = (datetime.now() + timedelta(hours=1)).timestamp()
        token = _make_jwt_token(future_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.should_refresh(is_connected=True))

    def test_should_not_refresh_when_disconnected(self):
        """Test should_refresh returns False when not connected."""
        near_exp = (datetime.now() + timedelta(seconds=100)).timestamp()
        token = _make_jwt_token(near_exp)
        url = _make_broker_url(token)

        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.should_refresh(is_connected=False))

    def test_should_not_refresh_when_no_expiry(self):
        """Test should_refresh returns False when expiry is unknown."""
        url = "wss://example.iot.us-east-1.amazonaws.com/mqtt"
        manager = TokenManager(url, refresh_buffer_seconds=300)

        self.assertFalse(manager.should_refresh(is_connected=True))


class TestTokenManagerUpdate(unittest.TestCase):
    """Test broker URL update and re-parsing."""

    def test_update_broker_url_reparses_token(self):
        """Test that updating broker URL re-parses the new token."""
        # Start with token expiring in 1 hour
        exp1 = (datetime.now() + timedelta(hours=1)).timestamp()
        token1 = _make_jwt_token(exp1)
        url1 = _make_broker_url(token1)

        manager = TokenManager(url1, refresh_buffer_seconds=300)
        original_expiry = manager.expiry

        # Update with token expiring in 2 hours
        exp2 = (datetime.now() + timedelta(hours=2)).timestamp()
        token2 = _make_jwt_token(exp2)
        url2 = _make_broker_url(token2)

        manager.update_broker_url(url2)

        self.assertIsNotNone(manager.expiry)
        self.assertGreater(manager.expiry, original_expiry)


if __name__ == "__main__":
    unittest.main()
