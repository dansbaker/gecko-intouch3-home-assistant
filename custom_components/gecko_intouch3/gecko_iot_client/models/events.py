"""Event system for Gecko IoT Client notifications."""

import logging
from enum import Enum
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class EventChannel(Enum):
    """Event channels for different types of notifications."""

    CONNECTIVITY_UPDATE = "connectivity_update"
    OPERATION_MODE_UPDATE = "operation_mode_update"
    ZONE_UPDATE = "zone_update"
    SENSOR_UPDATE = "sensor_update"
    STATE_UPDATE = "state_update"
    CONFIGURATION_UPDATE = "configuration_update"


class EventEmitter:
    """
    Event emitter for managing callbacks across different channels.

    This provides a unified way to handle different types of events
    that can occur in the Gecko IoT client.
    """

    def __init__(self):
        self._callbacks: Dict[EventChannel, List[Callable]] = {
            channel: [] for channel in EventChannel
        }
        self._logger = logging.getLogger(self.__class__.__name__)

    def on(self, channel: EventChannel, callback: Callable) -> None:
        """
        Register a callback for a specific event channel.

        Args:
            channel: The event channel to listen to
            callback: Function to call when the event occurs
        """
        if callback not in self._callbacks[channel]:
            self._callbacks[channel].append(callback)
            self._logger.debug(f"Registered callback for {channel.value}")

    def off(self, channel: EventChannel, callback: Callable) -> None:
        """
        Unregister a callback from a specific event channel.

        Args:
            channel: The event channel to stop listening to
            callback: The callback function to remove
        """
        if callback in self._callbacks[channel]:
            self._callbacks[channel].remove(callback)
            self._logger.debug(f"Unregistered callback for {channel.value}")

    def emit(self, channel: EventChannel, data: Any = None) -> None:
        """
        Emit an event to all registered callbacks for a channel.

        Args:
            channel: The event channel to emit to
            data: Optional data to pass to the callbacks
        """
        self._logger.debug(f"Emitting {channel.value} event with data: {data}")

        for callback in self._callbacks[channel]:
            try:
                if data is not None:
                    callback(data)
                else:
                    callback()
            except Exception as e:
                self._logger.error(f"Error in {channel.value} callback: {e}")

    def clear(self, channel: EventChannel | None = None) -> None:
        """
        Clear callbacks for a specific channel or all channels.

        Args:
            channel: Optional specific channel to clear. If None, clears all.
        """
        if channel:
            self._callbacks[channel].clear()
            self._logger.debug(f"Cleared all callbacks for {channel.value}")
        else:
            for ch in EventChannel:
                self._callbacks[ch].clear()
            self._logger.debug("Cleared all callbacks for all channels")
