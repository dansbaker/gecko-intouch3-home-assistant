"""
Token manager for handling AWS IoT token refresh and expiration.
"""

import logging
import threading
from datetime import datetime, timedelta
from typing import Callable, Optional

from .exceptions import TokenRefreshError

logger = logging.getLogger(__name__)


class TokenManager:
    """Manages AWS IoT tokens with automatic refresh capabilities."""

    def __init__(
        self,
        token_refresh_callback: Callable[[], dict],
        refresh_threshold_minutes: int = 15,
    ):
        """
        Initialize the token manager.

        Args:
            token_refresh_callback: Function that returns new token data
            refresh_threshold_minutes: How many minutes before expiry to refresh
        """
        self._token_refresh_callback = token_refresh_callback
        self._refresh_threshold = timedelta(minutes=refresh_threshold_minutes)
        self._current_token = None
        self._token_expiry = None
        self._refresh_thread = None
        self._stop_refresh = threading.Event()
        self._token_lock = threading.Lock()
        self._refresh_listeners = []

    def add_refresh_listener(self, callback: Callable[[dict], None]):
        """Add a callback to be notified when token is refreshed."""
        self._refresh_listeners.append(callback)

    def remove_refresh_listener(self, callback: Callable[[dict], None]):
        """Remove a token refresh listener."""
        if callback in self._refresh_listeners:
            self._refresh_listeners.remove(callback)

    def set_token(self, token_data: dict):
        """
        Set the current token and start refresh monitoring.

        Args:
            token_data: Dictionary containing token and expiry information
                       Expected keys: 'access_token', 'expires_in' or 'expires_at'
        """
        with self._token_lock:
            self._current_token = token_data

            # Calculate expiry time
            if "expires_at" in token_data:
                self._token_expiry = datetime.fromisoformat(token_data["expires_at"])
            elif "expires_in" in token_data:
                self._token_expiry = datetime.now() + timedelta(
                    seconds=token_data["expires_in"]
                )
            else:
                # Default to 1 hour if no expiry info
                self._token_expiry = datetime.now() + timedelta(hours=1)
                logger.warning("No expiry information in token, defaulting to 1 hour")

        self._start_refresh_monitoring()
        logger.info(f"Token set with expiry: {self._token_expiry}")

    def get_current_token(self) -> Optional[dict]:
        """Get the current token data."""
        with self._token_lock:
            return self._current_token.copy() if self._current_token else None

    def is_token_valid(self) -> bool:
        """Check if the current token is valid and not expired."""
        with self._token_lock:
            if not self._current_token or not self._token_expiry:
                return False
            return datetime.now() < self._token_expiry

    def needs_refresh(self) -> bool:
        """Check if token needs to be refreshed based on threshold."""
        with self._token_lock:
            if not self._token_expiry:
                return True
            return datetime.now() >= (self._token_expiry - self._refresh_threshold)

    def refresh_token(self) -> dict:
        """
        Manually refresh the token.

        Returns:
            New token data

        Raises:
            TokenRefreshError: If refresh fails
        """
        try:
            logger.info("Refreshing token...")
            new_token = self._token_refresh_callback()

            if not new_token:
                raise TokenRefreshError("Token refresh callback returned None")

            self.set_token(new_token)

            # Notify listeners
            for listener in self._refresh_listeners:
                try:
                    listener(new_token)
                except Exception as e:
                    logger.error(f"Error notifying token refresh listener: {e}")

            logger.info("Token refreshed successfully")
            return new_token

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise TokenRefreshError(f"Failed to refresh token: {e}")

    def _start_refresh_monitoring(self):
        """Start the background thread for token refresh monitoring."""
        if self._refresh_thread and self._refresh_thread.is_alive():
            self.stop_refresh_monitoring()

        self._stop_refresh.clear()
        self._refresh_thread = threading.Thread(
            target=self._refresh_monitor_loop, daemon=True
        )
        self._refresh_thread.start()
        logger.info("Token refresh monitoring started")

    def _refresh_monitor_loop(self):
        """Background loop to monitor and refresh tokens."""
        while not self._stop_refresh.is_set():
            try:
                if self.needs_refresh():
                    logger.info("Token needs refresh, attempting refresh...")
                    self.refresh_token()

                # Check every 30 seconds
                self._stop_refresh.wait(30)

            except TokenRefreshError as e:
                logger.error(f"Token refresh failed in monitor loop: {e}")
                # Wait longer before retrying on failure
                self._stop_refresh.wait(300)  # 5 minutes
            except Exception as e:
                logger.error(f"Unexpected error in token refresh monitor: {e}")
                self._stop_refresh.wait(60)

    def stop_refresh_monitoring(self):
        """Stop the background token refresh monitoring."""
        if self._refresh_thread:
            logger.info("Stopping token refresh monitoring...")
            self._stop_refresh.set()
            self._refresh_thread.join(timeout=5)
            if self._refresh_thread.is_alive():
                logger.warning("Token refresh thread did not stop gracefully")

    def cleanup(self):
        """Clean up resources."""
        self.stop_refresh_monitoring()
        with self._token_lock:
            self._current_token = None
            self._token_expiry = None
        self._refresh_listeners.clear()
        logger.info("Token manager cleaned up")
