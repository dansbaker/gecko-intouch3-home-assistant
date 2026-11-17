"""
Connection state manager for MQTT transporter.
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """MQTT connection states."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    CONNECTION_FAILED = "connection_failed"
    DISCONNECTING = "disconnecting"
    CREDENTIAL_REFRESH_FAILED = "credential_refresh_failed"


@dataclass
class ConnectionEvent:
    """Connection state change event."""

    state: ConnectionState
    timestamp: datetime
    message: Optional[str] = None
    error: Optional[Exception] = None


class ConnectionStateManager:
    """Manages connection state and provides reconnection logic."""

    def __init__(
        self,
        reconnect_enabled: bool = True,
        max_reconnect_attempts: int = 5,
        initial_retry_delay: float = 1.0,
        max_retry_delay: float = 60.0,
        backoff_multiplier: float = 2.0,
    ):
        """
        Initialize connection state manager.

        Args:
            reconnect_enabled: Whether automatic reconnection is enabled
            max_reconnect_attempts: Maximum number of reconnection attempts
            initial_retry_delay: Initial delay between reconnection attempts (seconds)
            max_retry_delay: Maximum delay between reconnection attempts (seconds)
            backoff_multiplier: Multiplier for exponential backoff
        """
        self._current_state = ConnectionState.DISCONNECTED
        self._state_lock = threading.Lock()
        self._state_change_callbacks: List[Callable[[ConnectionEvent], None]] = []

        # Reconnection settings
        self._reconnect_enabled = reconnect_enabled
        self._max_reconnect_attempts = max_reconnect_attempts
        self._initial_retry_delay = initial_retry_delay
        self._max_retry_delay = max_retry_delay
        self._backoff_multiplier = backoff_multiplier

        # Reconnection state
        self._reconnect_attempts = 0
        self._reconnect_thread: Optional[threading.Thread] = None
        self._stop_reconnect = threading.Event()
        self._reconnect_callback: Optional[Callable[[], None]] = None

        # Event history
        self._event_history: List[ConnectionEvent] = []
        self._max_history_size = 100

    def add_state_change_callback(self, callback: Callable[[ConnectionEvent], None]):
        """Add a callback to be notified of state changes."""
        with self._state_lock:
            if callback not in self._state_change_callbacks:
                self._state_change_callbacks.append(callback)

    def remove_state_change_callback(self, callback: Callable[[ConnectionEvent], None]):
        """Remove a state change callback."""
        with self._state_lock:
            if callback in self._state_change_callbacks:
                self._state_change_callbacks.remove(callback)

    def set_reconnect_callback(self, callback: Callable[[], None]):
        """Set the callback function to call when attempting reconnection."""
        self._reconnect_callback = callback

    def get_current_state(self) -> ConnectionState:
        """Get the current connection state."""
        with self._state_lock:
            return self._current_state

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self.get_current_state() == ConnectionState.CONNECTED

    def is_connecting(self) -> bool:
        """Check if currently connecting or reconnecting."""
        state = self.get_current_state()
        return state in (ConnectionState.CONNECTING, ConnectionState.RECONNECTING)

    def set_state(
        self, new_state: ConnectionState, message: str = None, error: Exception = None
    ):
        """
        Set the connection state and notify callbacks.

        Args:
            new_state: The new connection state
            message: Optional message describing the state change
            error: Optional error that caused the state change
        """
        with self._state_lock:
            old_state = self._current_state
            self._current_state = new_state

        # Create event
        event = ConnectionEvent(
            state=new_state, timestamp=datetime.now(), message=message, error=error
        )

        # Add to history
        self._add_to_history(event)

        # Log state change
        if error:
            logger.error(
                f"Connection state changed: {old_state.value} -> {new_state.value}, error: {error}"
            )
        else:
            logger.info(
                f"Connection state changed: {old_state.value} -> {new_state.value}"
            )
            if message:
                logger.info(f"State change message: {message}")

        # Handle automatic reconnection
        if new_state == ConnectionState.CONNECTION_FAILED and self._reconnect_enabled:
            self._start_reconnection()
        elif new_state == ConnectionState.CONNECTED:
            # Reset reconnection attempts on successful connection
            self._reconnect_attempts = 0
            self._stop_reconnection()
        elif new_state == ConnectionState.DISCONNECTED:
            self._stop_reconnection()

        # Notify callbacks
        self._notify_callbacks(event)

    def _add_to_history(self, event: ConnectionEvent):
        """Add event to history, maintaining max size."""
        self._event_history.append(event)
        if len(self._event_history) > self._max_history_size:
            self._event_history.pop(0)

    def get_event_history(self) -> List[ConnectionEvent]:
        """Get the connection event history."""
        return self._event_history.copy()

    def _notify_callbacks(self, event: ConnectionEvent):
        """Notify all registered callbacks of state change."""
        for callback in self._state_change_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")

    def _start_reconnection(self):
        """Start the automatic reconnection process."""
        if not self._reconnect_callback:
            logger.warning("No reconnect callback set, cannot attempt reconnection")
            return

        if self._reconnect_attempts >= self._max_reconnect_attempts:
            logger.error(
                f"Maximum reconnection attempts ({self._max_reconnect_attempts}) exceeded"
            )
            self.set_state(
                ConnectionState.DISCONNECTED,
                f"Reconnection failed after {self._max_reconnect_attempts} attempts",
            )
            return

        # Stop any existing reconnection thread
        self._stop_reconnection()

        logger.info(
            f"Starting reconnection attempt {self._reconnect_attempts + 1}/{self._max_reconnect_attempts}"
        )

        self._stop_reconnect.clear()
        self._reconnect_thread = threading.Thread(
            target=self._reconnect_loop, daemon=True
        )
        self._reconnect_thread.start()

    def _reconnect_loop(self):
        """Background thread for handling reconnection attempts."""
        while (
            not self._stop_reconnect.is_set()
            and self._reconnect_attempts < self._max_reconnect_attempts
        ):
            try:
                # Calculate delay with exponential backoff
                delay = min(
                    self._initial_retry_delay
                    * (self._backoff_multiplier**self._reconnect_attempts),
                    self._max_retry_delay,
                )

                logger.info(
                    f"Waiting {delay:.1f} seconds before reconnection attempt..."
                )
                if self._stop_reconnect.wait(delay):
                    break  # Stop event was set

                self._reconnect_attempts += 1

                # Set reconnecting state
                self.set_state(
                    ConnectionState.RECONNECTING,
                    f"Attempt {self._reconnect_attempts}/{self._max_reconnect_attempts}",
                )

                # Attempt reconnection
                logger.info(
                    f"Attempting reconnection ({self._reconnect_attempts}/{self._max_reconnect_attempts})"
                )

                if self._reconnect_callback:
                    self._reconnect_callback()

                # Wait a bit to see if connection succeeds
                time.sleep(2)

                # Check if we're now connected
                if self.is_connected():
                    logger.info("Reconnection successful")
                    break

            except Exception as e:
                logger.error(f"Error during reconnection attempt: {e}")

        # If we've exhausted attempts, set final state
        if (
            self._reconnect_attempts >= self._max_reconnect_attempts
            and not self.is_connected()
        ):
            self.set_state(
                ConnectionState.DISCONNECTED, "All reconnection attempts failed"
            )

    def _stop_reconnection(self):
        """Stop the automatic reconnection process."""
        if self._reconnect_thread and self._reconnect_thread.is_alive():
            logger.info("Stopping reconnection process...")
            self._stop_reconnect.set()
            self._reconnect_thread.join(timeout=2)
            if self._reconnect_thread.is_alive():
                logger.warning("Reconnection thread did not stop gracefully")

    def enable_reconnection(self):
        """Enable automatic reconnection."""
        self._reconnect_enabled = True
        logger.info("Automatic reconnection enabled")

    def disable_reconnection(self):
        """Disable automatic reconnection."""
        self._reconnect_enabled = False
        self._stop_reconnection()
        logger.info("Automatic reconnection disabled")

    def is_reconnection_enabled(self) -> bool:
        """Check if automatic reconnection is enabled."""
        return self._reconnect_enabled

    def reset_reconnect_attempts(self):
        """Reset the reconnection attempt counter."""
        self._reconnect_attempts = 0
        logger.info("Reconnection attempts reset")

    def get_reconnect_attempts(self) -> int:
        """Get the current number of reconnection attempts."""
        return self._reconnect_attempts

    def cleanup(self):
        """Clean up resources."""
        logger.info("Cleaning up connection state manager...")
        self._stop_reconnection()

        with self._state_lock:
            self._state_change_callbacks.clear()

        self._event_history.clear()
        self._reconnect_callback = None

        logger.info("Connection state manager cleanup complete")
