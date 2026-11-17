"""
Custom exceptions for MQTT transporter operations.
"""


class MqttTransporterError(Exception):
    """Base exception class for MQTT transporter errors."""

    pass


class ConnectionError(MqttTransporterError):
    """Raised when connection to MQTT broker fails."""

    pass


class AuthenticationError(MqttTransporterError):
    """Raised when authentication with MQTT broker fails."""

    pass


class TokenRefreshError(MqttTransporterError):
    """Raised when token refresh operation fails."""

    pass


class DisconnectionError(MqttTransporterError):
    """Raised when disconnection from MQTT broker fails."""

    pass


class ConfigurationError(MqttTransporterError):
    """Raised when configuration is invalid or missing."""

    pass


class ConfigurationTimeoutError(ConfigurationError):
    """Raised when configuration request times out."""

    pass
