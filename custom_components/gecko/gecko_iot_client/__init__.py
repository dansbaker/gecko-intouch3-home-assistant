import logging
from typing import Any, Callable, Dict, List

from .api import GeckoApiClient
from .models.connectivity import ConnectivityStatus
from .models.events import EventChannel, EventEmitter
from .models.operation_mode import OperationMode, OperationModeStatus
from .models.operation_mode_controller import OperationModeController
from .models.zone_parser import ZoneConfigurationParser
from .models.zone_types import (
    AbstractZone,
    FlowZone,
    LightingZone,
    TemperatureControlZone,
    ZoneType,
)
from .transporters import AbstractTransporter
from .transporters.exceptions import ConfigurationTimeoutError

# Make key classes available at package level
__all__ = [
    "GeckoIotClient",
    "AbstractTransporter",
    "ConfigurationTimeoutError",
    "AbstractZone",
    "ZoneType",
    "TemperatureControlZone",
    "FlowZone",
    "LightingZone",
    "EventChannel",
    "EventEmitter",
    "ConnectivityStatus",
    "OperationMode",
    "OperationModeStatus",
    "OperationModeController",
    "GeckoApiClient",
]

# Source baseline; this client is distributed with the integration.
__version__ = "3.0.0.dev0"


class GeckoIotClient:
    """
    Main client for interacting with Gecko IoT devices.

    The GeckoIotClient provides a high-level interface for connecting to and controlling
    Gecko IoT devices through various transport protocols (e.g., MQTT via AWS IoT).
    It handles device configuration, state management, and zone control.

    Args:
        idd: Unique identifier for the device/client
        transporter: Transport layer implementation for communication
        config_timeout: Maximum time to wait for configuration loading in seconds (default: 30.0)

    Example:
        >>> from gecko_iot_client import GeckoIotClient
        >>> from gecko_iot_client.transporters.mqtt import MqttTransporter
        >>>
        >>> transporter = MqttTransporter(
        ...     endpoint="your-endpoint.amazonaws.com",
        ...     certificate_path="cert.pem.crt",
        ...     private_key_path="private.pem.key",
        ...     ca_file_path="AmazonRootCA1.pem"
        ... )
        >>>
        >>> with GeckoIotClient("device-123", transporter) as client:
        ...     zones = client.get_zones()
        ...     print(f"Found {len(zones)} zone types")
    """

    def __init__(
        self, idd: str, transporter: AbstractTransporter, config_timeout: float = 5.0
    ):
        self.id = idd
        self.transporter = transporter
        self.config_timeout = config_timeout
        self._zones: Dict[ZoneType, List[AbstractZone]] = {}
        self._zone_parser = ZoneConfigurationParser()
        self._logger = logging.getLogger(self.__class__.__name__)
        self._configuration = None
        self._state = None

        # Event system
        self._event_emitter = EventEmitter()
        self._connectivity_status = ConnectivityStatus()
        self._operation_mode_controller = OperationModeController()

        # State handlers registration for automatic processing
        self._state_handlers = [
            {
                "status_obj": self._connectivity_status,
                "event_channel": EventChannel.CONNECTIVITY_UPDATE,
                "log_formatter": lambda status: (
                    f"Device connectivity changed: gateway={status.gateway_status}, vessel={status.vessel_status}"
                ),
            },
            {
                "status_obj": self._operation_mode_controller,
                "event_channel": EventChannel.OPERATION_MODE_UPDATE,
                "log_formatter": lambda controller: (
                    f"Operation mode changed to: {controller.mode_name} ({controller.operation_mode.value})"
                ),
            },
        ]

        # Set up connectivity monitoring (defined on AbstractTransporter interface)
        self.transporter.on_connectivity_change(
            self._on_transporter_connectivity_change
        )

    def connect(self):
        """
        Establish connection to the device and initialize configuration.

        This method sets up event handlers for configuration and state changes,
        connects to the transport layer, and automatically loads the device
        configuration.

        Raises:
            Exception: If connection or configuration loading fails
        """
        self.transporter.on_configuration_loaded(self._on_configuration_loaded)
        self.transporter.on_state_change(self._on_state_change)
        self.transporter.on_state_loaded(self._on_state_loaded)

        self.transporter.connect()

        self.transporter.load_configuration(timeout=self.config_timeout)

    def __enter__(self):
        """
        Enter the context manager.

        Automatically calls connect() when entering the context.

        Returns:
            GeckoIotClient: Self for use in with statement
        """
        self._logger.info("Entering GeckoIotClient context manager...")
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context manager.

        Automatically calls disconnect() when exiting the context.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred
        """
        self.disconnect()

    @property
    def is_connected(self) -> bool:
        """
        Check if the client is currently connected.

        This checks both MQTT connectivity and device shadow connectivity status.

        Returns:
            bool: True if fully connected (MQTT + gateway + vessel), False otherwise
        """
        return self._connectivity_status.is_fully_connected

    def disconnect(self):
        """
        Disconnect from the device and clean up resources.

        This method properly closes the transport connection and performs
        any necessary cleanup.
        """
        self.transporter.disconnect()

    def _on_transporter_connectivity_change(self, is_connected: bool):
        """
        Handle transporter connectivity changes (transport-agnostic).

        Args:
            is_connected: True if transport is connected, False otherwise
        """
        self._connectivity_status.transport_connected = is_connected
        self._logger.info(f"Transporter connectivity changed: {is_connected}")

        # Emit connectivity update event
        self._event_emitter.emit(
            EventChannel.CONNECTIVITY_UPDATE, self._connectivity_status
        )

    def _process_state_updates(self, state_data: Dict[str, Any]) -> None:
        """
        Process all registered state handlers for the given state data.

        Args:
            state_data: Device shadow state data to process
        """
        for handler in self._state_handlers:
            status_obj = handler["status_obj"]
            event_channel = handler["event_channel"]
            log_formatter = handler["log_formatter"]

            if status_obj.update_from_state_data(state_data):
                self._logger.info(log_formatter(status_obj))
                self._event_emitter.emit(event_channel, status_obj)

        # Apply state updates to zones
        if self._zones:
            try:
                self._zone_parser.apply_state_to_zones(self._zones, state_data)
                self._logger.info("State updates applied to zones")
                self._notify_zone_updates()
            except Exception as e:
                self._logger.error(f"Failed to apply state updates to zones: {e}")

    @property
    def connectivity_status(self) -> ConnectivityStatus:
        """
        Get current connectivity status.

        Returns:
            ConnectivityStatus: Current connectivity including MQTT, gateway, and vessel status
        """
        return self._connectivity_status

    @property
    def operation_mode_controller(self) -> OperationModeController:
        """
        Get the operation mode controller for read/write operations.

        Returns:
            OperationModeController: Controller for operation mode functionality
        """
        return self._operation_mode_controller

    @property
    def operation_mode_status(self) -> OperationModeController:
        """
        Get current operation mode status (legacy property - use operation_mode_controller instead).

        Returns:
            OperationModeController: Current operation mode controller
        """
        return self._operation_mode_controller

    def on(self, channel: EventChannel, callback: Callable) -> None:
        """
        Register a callback for a specific event channel.

        Args:
            channel: The event channel to listen to
            callback: Function to call when the event occurs
        """
        self._event_emitter.on(channel, callback)

    def off(self, channel: EventChannel, callback: Callable) -> None:
        """
        Unregister a callback from a specific event channel.

        Args:
            channel: The event channel to stop listening to
            callback: The callback function to remove
        """
        self._event_emitter.off(channel, callback)

    def _on_configuration_loaded(self, configuration):
        """
        Handle configuration loading and zone parsing.

        Args:
            configuration: Device configuration dictionary
        """
        self._logger.info("Configuration loaded.")
        self._configuration = configuration

        zones_config = configuration.get("zones", {})
        self._logger.debug(f"Raw configuration: {configuration}")

        try:
            self._zones = self._zone_parser.parse_zones_configuration(zones_config)
            # Setup zone control after zones are parsed
            self.setup_zone_control()
        except Exception as e:
            self._logger.error(f"Error during zone parsing: {e}")
            self._zones = {}  # Reset to empty state on failure

        # Automatically load state after configuration is processed
        try:
            self._logger.info("Automatically loading state after configuration...")
            self.transporter.load_state()
        except Exception as e:
            self._logger.error(f"Failed to load state: {e}")

    def _on_state_change(self, new_state):
        """
        Handle state changes.

        Args:
            new_state: New device state dictionary
        """
        self._logger.debug(f"State changed to: {new_state}")

        # Process all state updates using unified handler (includes zone updates)
        self._process_state_updates(new_state)

    def _on_state_loaded(self, state_data):
        """
        Handle state loading from AWS IoT Device Shadow.

        Args:
            state_data: Device shadow state data
        """
        self._logger.info("State loaded from AWS IoT Device Shadow.")
        self._state = state_data
        self._logger.debug(f"State data: {state_data}")

        # Process all state updates using unified handler (includes zone updates)
        self._process_state_updates(state_data)

        # Ensure zone control is set up after state is applied
        if self._zones:
            self.setup_zone_control()

    def get_zones(self) -> Dict[ZoneType, List[AbstractZone]]:
        """
        Return the parsed zones organized by type.

        Returns:
            Dict mapping zone types to lists of zones of that type.
            Returns a copy to prevent external modification.
        """
        return self._zones.copy()

    def get_zones_by_type(self, zone_type: ZoneType) -> List[AbstractZone]:
        """
        Return all zones of a specific type.

        Args:
            zone_type: The type of zones to retrieve

        Returns:
            List of zones matching the specified type
        """
        return self._zones.get(zone_type, [])

    def get_zone_by_id_and_type(
        self, zone_type: ZoneType, zone_id: str
    ) -> AbstractZone:
        """
        Find and return a zone by its type and ID.

        Args:
            zone_type: The type of the zone
            zone_id: The zone ID to search for

        Returns:
            The zone with matching type and ID

        Raises:
            ValueError: If no zone found with the specified type and ID
        """

        zone = next(
            (z for z in self.get_zones_by_type(zone_type) if z.id == zone_id), None
        )

        if not zone:
            raise ValueError(f"No zone found with type {zone_type} and ID: {zone_id}")

        return zone

    def on_zone_update(
        self, callback: Callable[[Dict[ZoneType, List[AbstractZone]]], None]
    ):
        """
        Register callback for zone updates (legacy method).

        This method is maintained for backward compatibility.
        New code should use: client.on(EventChannel.ZONE_UPDATE, callback)

        Args:
            callback: Function that takes a dictionary of zones organized by type
        """
        # Use the new event system internally
        self.on(EventChannel.ZONE_UPDATE, callback)

    def _notify_zone_updates(self):
        """Notify all registered callbacks that zones were updated."""
        self._logger.info("Notifying zone update callbacks")

        # Use the new event system to notify all callbacks
        self._event_emitter.emit(EventChannel.ZONE_UPDATE, self._zones.copy())

    def register_zone_callbacks(self):
        """
        Register callbacks for zone monitoring (legacy method).

        This method is maintained for backward compatibility.
        For new code, use the event system: client.on(EventChannel.ZONE_UPDATE, callback)
        """
        # Set up basic zone monitoring
        for zone_type, zone_list in self._zones.items():
            for zone in zone_list:
                self._logger.debug(f"Zone ready for monitoring: {zone.name}")

        # Register a zone update callback using the new event system for monitoring
        def zone_update_handler(zones: Dict[ZoneType, List[AbstractZone]]):
            self._logger.debug(
                f"Zone update received: {len(zones)} zone types available"
            )

        self.on(EventChannel.ZONE_UPDATE, zone_update_handler)

    def setup_zone_control(self) -> None:
        """
        Set up zone and feature control functionality for publishing desired state updates.
        """

        def _publish_if_connected(publish_func, error_context: str, *args, **kwargs):
            """Helper to publish only if connected, waiting for delivery confirmation."""
            if self.is_connected:
                try:
                    future = publish_func(*args, **kwargs)
                    # Wait for PUBACK to confirm actual delivery to broker
                    future.result(timeout=5.0)
                    self._logger.info(f"✅ Published desired state for {error_context}")
                except TimeoutError:
                    self._logger.error(
                        f"❌ Publish timed out for {error_context} — message may not have been delivered"
                    )
                    raise
                except Exception as e:
                    self._logger.error(
                        f"❌ Failed to publish desired state for {error_context}: {e}"
                    )
                    raise
            else:
                self._logger.error(
                    f"Failed to publish change to {error_context}, not connected."
                )
                raise ConnectionError("Gecko device is not connected")

        # Zone control callback
        def zone_callback(
            zone_type: str, zone_id: str, updates: Dict[str, Any]
        ) -> None:
            # Build the zone structure and use the generic transport method
            desired_state = {"zones": {zone_type: {zone_id: updates}}}
            _publish_if_connected(
                self.transporter.publish_desired_state, f"zone {zone_id}", desired_state
            )

        # Feature control callback (for operation mode, etc.)
        def feature_callback(feature_name: str, updates: Dict[str, Any]) -> None:
            # Build the feature structure and use the generic transport method
            desired_state = {"features": updates}
            _publish_if_connected(
                self.transporter.publish_desired_state, feature_name, desired_state
            )

        # Set callbacks for zones
        for zone_type, zone_list in self._zones.items():
            for zone in zone_list:
                zone.set_publish_callback(zone_callback)

        # Set callback for operation mode
        self._operation_mode_controller.set_publish_callback(feature_callback)

        self._logger.info("Zone and feature control setup completed")

    def list_zones(self) -> List[Dict[str, Any]]:
        """
        Get a simple list of all zones with basic info.

        Returns:
            List of dictionaries with zone information (id, name, type, has_control)
        """
        zones_info = []
        for zone_type, zone_list in self._zones.items():
            for zone in zone_list:
                zone_info = {
                    "id": zone.id,
                    "name": zone.name,
                    "type": zone_type.value,
                    "has_control": zone._publish_callback is not None,
                }
                zones_info.append(zone_info)
        return zones_info
