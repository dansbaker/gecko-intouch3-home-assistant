"""
Unit tests for custom exceptions.
"""

import unittest

from custom_components.gecko.gecko_iot_client.transporters.exceptions import (
    AuthenticationError,
    ConfigurationError,
    ConfigurationTimeoutError,
    ConnectionError,
    DisconnectionError,
    MqttTransporterError,
    TokenRefreshError,
)


class TestMqttTransporterExceptions(unittest.TestCase):
    """Test custom exception classes."""

    def test_mqtt_transporter_error_base(self):
        """Test MqttTransporterError base exception."""
        error = MqttTransporterError("Test error message")
        self.assertEqual(str(error), "Test error message")
        self.assertIsInstance(error, Exception)

    def test_exception_inheritance(self):
        """Test that all custom exceptions inherit from MqttTransporterError."""
        self.assertTrue(issubclass(ConnectionError, MqttTransporterError))
        self.assertTrue(issubclass(AuthenticationError, MqttTransporterError))
        self.assertTrue(issubclass(TokenRefreshError, MqttTransporterError))
        self.assertTrue(issubclass(DisconnectionError, MqttTransporterError))
        self.assertTrue(issubclass(ConfigurationError, MqttTransporterError))
        self.assertTrue(issubclass(ConfigurationTimeoutError, ConfigurationError))

    def test_connection_error(self):
        """Test ConnectionError exception."""
        error = ConnectionError("Connection failed")
        self.assertEqual(str(error), "Connection failed")
        self.assertIsInstance(error, MqttTransporterError)

    def test_authentication_error(self):
        """Test AuthenticationError exception."""
        error = AuthenticationError("Authentication failed")
        self.assertEqual(str(error), "Authentication failed")
        self.assertIsInstance(error, MqttTransporterError)

    def test_token_refresh_error(self):
        """Test TokenRefreshError exception."""
        error = TokenRefreshError("Token refresh failed")
        self.assertEqual(str(error), "Token refresh failed")
        self.assertIsInstance(error, MqttTransporterError)

    def test_disconnection_error(self):
        """Test DisconnectionError exception."""
        error = DisconnectionError("Disconnection failed")
        self.assertEqual(str(error), "Disconnection failed")
        self.assertIsInstance(error, MqttTransporterError)

    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        error = ConfigurationError("Invalid configuration")
        self.assertEqual(str(error), "Invalid configuration")
        self.assertIsInstance(error, MqttTransporterError)

    def test_configuration_timeout_error(self):
        """Test ConfigurationTimeoutError exception."""
        error = ConfigurationTimeoutError("Configuration timeout")
        self.assertEqual(str(error), "Configuration timeout")
        self.assertIsInstance(error, ConfigurationError)
        self.assertIsInstance(error, MqttTransporterError)

    def test_raise_and_catch_connection_error(self):
        """Test raising and catching ConnectionError."""
        with self.assertRaises(ConnectionError) as context:
            raise ConnectionError("Test connection error")

        self.assertIn("Test connection error", str(context.exception))

    def test_raise_and_catch_authentication_error(self):
        """Test raising and catching AuthenticationError."""
        with self.assertRaises(AuthenticationError) as context:
            raise AuthenticationError("Test auth error")

        self.assertIn("Test auth error", str(context.exception))

    def test_raise_and_catch_configuration_error(self):
        """Test raising and catching ConfigurationError."""
        with self.assertRaises(ConfigurationError) as context:
            raise ConfigurationError("Test configuration error")

        self.assertIn("Test configuration error", str(context.exception))

    def test_raise_and_catch_token_refresh_error(self):
        """Test raising and catching TokenRefreshError."""
        with self.assertRaises(TokenRefreshError) as context:
            raise TokenRefreshError("Test token error")

        self.assertIn("Test token error", str(context.exception))

    def test_catch_as_mqtt_transporter_error(self):
        """Test catching specific errors as MqttTransporterError."""
        with self.assertRaises(MqttTransporterError):
            raise ConnectionError("Connection failed")

        with self.assertRaises(MqttTransporterError):
            raise ConfigurationError("Config failed")

        with self.assertRaises(MqttTransporterError):
            raise TokenRefreshError("Token failed")

    def test_catch_configuration_timeout_as_configuration_error(self):
        """Test catching ConfigurationTimeoutError as ConfigurationError."""
        with self.assertRaises(ConfigurationError):
            raise ConfigurationTimeoutError("Timeout")

    def test_exception_with_no_message(self):
        """Test exceptions with no message."""
        error = MqttTransporterError()
        self.assertIsInstance(error, Exception)

    def test_exception_with_complex_message(self):
        """Test exceptions with complex messages."""
        error = ConnectionError(
            "Failed to connect to broker at wss://example.com:8883 after 3 attempts"
        )
        self.assertIn("wss://example.com:8883", str(error))
        self.assertIn("3 attempts", str(error))


if __name__ == "__main__":
    unittest.main()
