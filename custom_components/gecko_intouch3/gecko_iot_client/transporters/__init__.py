from concurrent.futures import Future
from typing import Any, Dict

_NOT_IMPLEMENTED_MSG = "Subclasses must implement this method"


class AbstractTransporter:
    """
    Abstract base class for transport layer implementations.

    This class defines the interface for communicating with Gecko IoT devices
    through various protocols (MQTT, HTTP, etc.). Concrete implementations
    handle the protocol-specific details while providing a unified interface
    for the client.
    """

    def connect(self):
        """
        Establish connection to the transport medium.

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def disconnect(self):
        """
        Close connection and clean up resources.

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def on_state_change(self, callback):
        """
        Register callback for state change notifications.

        Args:
            callback: Function to call when state changes occur

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def change_state(self, new_state):
        """
        Request a state change on the device.

        Args:
            new_state: The new state to apply

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def load_configuration(self, timeout: float = 30.0):
        """
        Load device configuration from the transport medium.

        Args:
            timeout: Maximum time to wait for configuration response in seconds

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def on_configuration_loaded(self, callback):
        """
        Register callback for configuration load events.

        Args:
            callback: Function to call when configuration is loaded

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def load_state(self):
        """
        Load current device state from the transport medium.

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def on_state_loaded(self, callback):
        """
        Register callback for state load events.

        Args:
            callback: Function to call when state is loaded

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def on_connectivity_change(self, callback):
        """
        Register callback for connectivity changes.

        Args:
            callback: Function to call when connectivity status changes.
                     Callback should accept a boolean (True=connected, False=disconnected).

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def is_connected(self) -> bool:
        """
        Check if the transport is currently connected.

        Returns:
            bool: True if connected, False otherwise

        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    # Generic desired state interface
    def publish_desired_state(self, desired_state: Dict[str, Any]) -> Future:
        """
        Publish desired state updates to the transport medium.

        Args:
            desired_state: Dictionary of desired state structure to publish

        Returns:
            Future that resolves when update is published

        Note:
            The actual transport implementation (MQTT, HTTP, etc.) handles
            the protocol-specific details like topics, payloads, field naming.
            This method is transport-agnostic and doesn't impose any business
            logic about zones, features, or other domain concepts.
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)

    def publish_batch_desired_state(
        self, zone_updates: Dict[str, Dict[str, Dict[str, Any]]]
    ) -> Future:
        """
        Publish desired state updates for multiple zones in a single operation.

        Args:
            zone_updates: Nested dict {zone_type: {zone_id: updates}}

        Returns:
            Future that resolves when batch update is published
        """
        raise NotImplementedError(_NOT_IMPLEMENTED_MSG)
