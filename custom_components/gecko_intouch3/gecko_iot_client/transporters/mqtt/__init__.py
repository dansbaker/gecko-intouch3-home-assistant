"""
MQTT transporter package for Gecko IoT devices.

This package provides MQTT5 connectivity for AWS IoT Core with JWT token authentication,
automatic token refresh, and Gecko-specific shadow operations.

Main exports:
- MqttTransporter: High-level Gecko IoT transporter (primary interface)
- MqttClient: Low-level MQTT protocol client (for advanced use)
"""

from .client import MqttClient
from .transporter import MqttTransporter

__all__ = ["MqttTransporter", "MqttClient"]
