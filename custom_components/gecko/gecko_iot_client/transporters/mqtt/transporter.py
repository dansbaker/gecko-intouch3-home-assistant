"""
Gecko-specific MQTT transporter implementation.

This module provides the MqttTransporter class which implements the AbstractTransporter
interface with Gecko IoT-specific logic for configuration loading, state management,
and AWS IoT shadow operations.
"""

import json
import logging
import threading
import time
import uuid
from concurrent.futures import Future
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from .. import AbstractTransporter
from ..exceptions import ConfigurationError, ConnectionError
from .callback_registry import CallbackRegistry
from .client import MqttClient
from .constants import CONNECTION_TIMEOUT, NOT_CONNECTED_ERROR
from .reconnection_handler import ReconnectionHandler
from .token_manager import TokenManager
from .utils import complete_future_safely, notify_callbacks_safely, parse_json_safely

logger = logging.getLogger(__name__)


class MqttTransporter(AbstractTransporter):
    """
    Gecko-specific MQTT transporter.

    Responsibilities:
    - Gecko topic structure (config, state, shadow)
    - Token refresh and expiration management
    - Configuration and state loading
    - AbstractTransporter interface implementation
    - Reconnection logic with token refresh

    This class contains all Gecko IoT business logic and delegates
    MQTT protocol operations to MqttClient.
    """

    def __init__(
        self,
        broker_url: str,
        monitor_id: str,
        token_refresh_callback: Optional[Callable[[str], Optional[str]]] = None,
        token_refresh_buffer_seconds: int = 300,
    ):
        """
        Initialize MQTT transporter with Gecko-specific logic.

        Args:
            broker_url: WebSocket URL with embedded JWT token
            monitor_id: Device monitor identifier
            token_refresh_callback: Function to get new broker URL with fresh token.
                Should return None if refresh failed (e.g., API unavailable).
            token_refresh_buffer_seconds: Seconds before expiry to refresh token
        """
        if not broker_url or not monitor_id:
            raise ConfigurationError("Both broker_url and monitor_id are required")

        self._broker_url = broker_url
        self._monitor_id = monitor_id
        self._token_refresh_callback = token_refresh_callback
        self._token_refresh_buffer = token_refresh_buffer_seconds

        # Helper components
        self._token_manager = TokenManager(broker_url, token_refresh_buffer_seconds)
        self._reconnection_handler = ReconnectionHandler()
        self._callback_registry = CallbackRegistry()

        # MQTT client - delegates all MQTT operations
        self._mqtt_client = MqttClient(
            on_connected=self._on_mqtt_connected,
            on_message=None,  # We use specific handlers only
        )

        # State management
        self._is_refreshing_token = False
        self._is_reconnecting = False
        self._state_lock = threading.RLock()

        # Loading state
        self._config_future: Optional[Future] = None
        self._state_future: Optional[Future] = None
        self._subscriptions_setup = False

        # Threading for expiry monitoring
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop_event = threading.Event()

        # Track consecutive refresh failures for progressive backoff
        self._consecutive_refresh_failures = 0

        # Track pending refresh retry thread to prevent unbounded spawning
        self._pending_refresh_retry: Optional[threading.Thread] = None

    # ========================================================================
    # AbstractTransporter Interface
    # ========================================================================

    def connect(self, **kwargs):
        """Connect using preformatted WebSocket URL with expiration management."""
        self._monitor_stop_event.clear()

        if self._mqtt_client.is_connected():
            logger.debug("Already connected")
            return

        # Check if token is already expired before attempting connection
        if self._token_manager.is_expired():
            logger.warning("Token expired, refreshing before connection")
            if self._token_refresh_callback:
                self._refresh_token_before_connect()

        try:
            # Generate unique client ID
            client_id = f"ha-{self._monitor_id}-{uuid.uuid4().hex}"

            # Connect via MQTT client
            self._mqtt_client.connect(
                broker_url=self._broker_url,
                client_id=client_id,
                timeout=kwargs.get("timeout", CONNECTION_TIMEOUT),
            )

            # Start expiry monitoring after successful connection
            if self._token_refresh_callback and self._token_manager.expiry:
                self._start_expiry_monitoring()

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            raise ConnectionError(f"Connection failed: {e}")

    def disconnect(self):
        """Disconnect and cleanup."""
        # Stop monitoring first
        self._monitor_stop_event.set()
        self._stop_expiry_monitoring()

        # Disconnect MQTT client
        self._mqtt_client.disconnect()

        # Clear subscription and reconnection state
        with self._state_lock:
            self._subscriptions_setup = False
            self._is_reconnecting = False

        logger.info("Transporter disconnected successfully")

    def is_connected(self) -> bool:
        """Check if connected to broker."""
        return self._mqtt_client.is_connected()

    def update_broker_url(self, new_broker_url: str) -> None:
        """
        Update broker URL with a fresh token.

        This is useful when reusing an existing connection that needs a token refresh.
        The method updates the broker URL and token manager without disconnecting.

        Args:
            new_broker_url: New WebSocket URL with fresh JWT token
        """
        if not new_broker_url:
            logger.warning("Attempted to update with empty broker URL")
            return

        logger.debug("Updating broker URL with fresh token")
        self._broker_url = new_broker_url
        self._token_manager.update_broker_url(new_broker_url)
        logger.debug(f"Token expiry updated to: {self._token_manager.expiry}")

    def load_configuration(self, timeout: float = 30.0):
        """Load configuration from AWS IoT."""
        if not self._mqtt_client.is_connected():
            raise ConnectionError(NOT_CONNECTED_ERROR)

        if self._config_future and not self._config_future.done():
            logger.debug("Configuration request already in progress")
            return

        # Wait for subscriptions to be ready (set up by connection callback)
        wait_start = time.time()
        while not self._subscriptions_setup and (time.time() - wait_start) < timeout:
            logger.debug("Waiting for subscriptions to be ready...")
            time.sleep(0.1)

        if not self._subscriptions_setup:
            raise ConfigurationError("Subscriptions not ready within timeout")

        logger.debug(f"Loading configuration for monitor_id: {self._monitor_id}")

        # Retry logic: the first config request may time out if the broker
        # hasn't fully routed subscriptions yet. A retry typically succeeds
        # quickly once the connection is fully stabilized.
        max_attempts = 3
        per_attempt_timeout = timeout
        last_error = None

        for attempt in range(1, max_attempts + 1):
            # Create future BEFORE publishing request to avoid race condition
            # where response arrives before future exists
            self._config_future = Future()

            topic = self._build_topic("config/get")

            try:
                logger.debug(
                    f"Publishing configuration request to: {topic} "
                    f"(attempt {attempt}/{max_attempts})"
                )
                publish_future = self._mqtt_client.publish(topic, "{}")

                # Wait for publish to complete
                try:
                    publish_future.result(timeout=5.0)
                    logger.debug("Configuration request published")
                except Exception as e:
                    logger.error(f"Failed to publish configuration request: {e}")
                    raise ConfigurationError(f"Failed to publish config request: {e}")

                logger.debug(
                    f"Waiting for configuration response "
                    f"(timeout: {per_attempt_timeout:.1f}s, attempt {attempt}/{max_attempts})"
                )

                # Wait for response
                result = self._config_future.result(timeout=per_attempt_timeout)
                logger.debug("Configuration loaded successfully")
                return result

            except TimeoutError:
                self._config_future = None
                last_error = TimeoutError(
                    f"Timed out waiting for configuration response on attempt "
                    f"{attempt}/{max_attempts} after {per_attempt_timeout:.1f}s"
                )
                if attempt < max_attempts:
                    logger.warning(
                        f"Configuration request timed out (attempt {attempt}/{max_attempts}), retrying..."
                    )
                else:
                    logger.error(
                        f"Configuration loading failed after {max_attempts} attempts"
                    )
            except Exception as e:
                self._config_future = None
                logger.error(f"Configuration loading failed: {e}")
                raise ConfigurationError(f"Configuration loading failed: {e}")

        raise ConfigurationError(f"Configuration loading failed: {last_error}")

    def load_state(self):
        """Load state from AWS IoT shadow."""
        if not self._mqtt_client.is_connected():
            raise ConnectionError(NOT_CONNECTED_ERROR)

        if self._state_future and not self._state_future.done():
            logger.debug("State request already in progress")
            return

        logger.debug(f"Loading state for monitor_id: {self._monitor_id}")

        self._state_future = Future()
        topic = self._build_topic("shadow/name/state/get")

        try:
            self._mqtt_client.publish(topic, "{}")
            logger.debug("State request sent")

        except Exception as e:
            self._state_future = None
            logger.error(f"State loading failed: {e}")
            raise ConfigurationError(f"State loading failed: {e}")

    def publish_desired_state(self, desired_state: Dict[str, Any]) -> Future:
        """Publish desired state update to AWS IoT shadow."""
        if not self._mqtt_client.is_connected():
            raise ConnectionError(NOT_CONNECTED_ERROR)

        payload = {"state": {"desired": desired_state}}
        topic = self._build_topic("shadow/name/state/update")
        return self._mqtt_client.publish(topic, json.dumps(payload))

    def publish_batch_desired_state(
        self, zone_updates: Dict[str, Dict[str, Dict[str, Any]]]
    ) -> Future:
        """Publish batch desired state updates for multiple zones."""
        desired_state = {"zones": zone_updates}
        return self.publish_desired_state(desired_state)

    def on_configuration_loaded(self, callback):
        """Register config callback."""
        self._callback_registry.register("config", callback)

    def on_state_loaded(self, callback):
        """Register state callback."""
        self._callback_registry.register("state", callback)

    def on_state_change(self, callback):
        """Register state change callback."""
        self._callback_registry.register("state_update", callback)

    def on_connectivity_change(self, callback):
        """Register connectivity change callback."""
        self._callback_registry.register("connectivity", callback)

    def change_state(self, new_state):
        """Change state (placeholder for interface compliance)."""
        notify_callbacks_safely(
            self._callback_registry.get_callbacks("state_update"), new_state
        )

    # ========================================================================
    # Gecko-Specific Logic
    # ========================================================================

    def _build_topic(self, path: str) -> str:
        """Build AWS IoT topic for this monitor."""
        return f"$aws/things/{self._monitor_id}/{path}"

    def _refresh_token_before_connect(self) -> None:
        """Refresh token before initial connection attempt."""
        if not self._token_refresh_callback:
            return

        try:
            new_broker_url = self._token_refresh_callback(self._monitor_id)
            if new_broker_url:
                self._broker_url = new_broker_url
                self._token_manager.update_broker_url(new_broker_url)
                with self._state_lock:
                    self._consecutive_refresh_failures = 0
                logger.debug("Token refreshed successfully before connection")
            else:
                with self._state_lock:
                    self._consecutive_refresh_failures += 1
                logger.error(
                    "Token refresh callback returned None before connection - "
                    "API may be unavailable"
                )
                # Schedule a retry so the monitor loop doesn't get stuck
                self._schedule_refresh_retry()
        except Exception as e:
            with self._state_lock:
                self._consecutive_refresh_failures += 1
            logger.error(f"Failed to refresh expired token before connection: {e}")
            self._schedule_refresh_retry()

    def _setup_subscriptions(self):
        """Setup essential AWS IoT subscriptions."""
        if self._subscriptions_setup:
            logger.debug("Subscriptions already set up")
            return

        logger.debug(f"Setting up subscriptions for monitor_id: {self._monitor_id}")

        topics = [
            (self._build_topic("config/get/accepted"), self._on_config_response),
            (self._build_topic("config/get/rejected"), self._on_config_rejected),
            (
                self._build_topic("shadow/name/state/get/accepted"),
                self._on_state_response,
            ),
            (
                self._build_topic("shadow/name/state/get/rejected"),
                self._on_state_rejected,
            ),
            (
                self._build_topic("shadow/name/state/update/documents"),
                self._on_state_document_update,
            ),
            (
                self._build_topic("shadow/name/state/update/rejected"),
                self._on_state_update_rejected,
            ),
        ]

        successful_subscriptions = 0
        for topic, handler in topics:
            try:
                logger.debug(f"Subscribing to: {topic}")
                self._mqtt_client.subscribe(topic, handler)
                successful_subscriptions += 1
            except Exception as e:
                logger.error(f"Failed to subscribe to {topic}: {e}")

        if successful_subscriptions > 0:
            self._subscriptions_setup = True
            logger.debug(
                f"Set up {successful_subscriptions}/{len(topics)} subscriptions"
            )

        else:
            logger.error("Failed to set up any subscriptions")
            raise ConnectionError("Failed to establish subscriptions")

    # ========================================================================
    # Token Refresh and Expiry Monitoring
    # ========================================================================

    def _start_expiry_monitoring(self):
        """Start monitoring token expiry in background thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._monitor_stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._expiry_monitor_loop, daemon=True
        )
        self._monitor_thread.start()
        logger.debug("Started token expiry monitoring")

    def _stop_expiry_monitoring(self):
        """Stop token expiry monitoring."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_stop_event.set()
            self._monitor_thread.join(timeout=5)
            logger.debug("Stopped token expiry monitoring")

    def _expiry_monitor_loop(self):
        """Background thread loop to monitor token expiry."""
        while not self._monitor_stop_event.is_set():
            try:
                # Check if we're in a failure state — if so, don't trigger
                # another refresh here; _schedule_refresh_retry handles the backoff
                with self._state_lock:
                    already_refreshing = self._is_refreshing_token
                    has_failures = self._consecutive_refresh_failures > 0

                if (
                    not already_refreshing
                    and not has_failures
                    and self._should_refresh_token()
                ):
                    logger.info("Token approaching expiry, initiating refresh...")
                    self._handle_token_refresh()

                # Check every 10 seconds for more responsive refresh
                self._monitor_stop_event.wait(10)

            except Exception as e:
                logger.error(f"Error in expiry monitoring: {e}")
                self._monitor_stop_event.wait(60)  # Back off on error

    def _should_refresh_token(self) -> bool:
        """Check if token needs refreshing."""
        return self._token_manager.should_refresh(self._mqtt_client.is_connected())

    def _handle_token_refresh(self):
        """Handle token refresh and reconnection."""
        if not self._token_refresh_callback:
            logger.warning("No token refresh callback configured")
            return

        with self._state_lock:
            self._is_refreshing_token = True

        try:
            self._log_token_refresh_timing()
            new_broker_url = self._invoke_refresh_callback()

            if not new_broker_url:
                self._handle_refresh_callback_failure()
                return

            self._apply_refreshed_token(new_broker_url)

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            with self._state_lock:
                self._consecutive_refresh_failures += 1
                self._is_refreshing_token = False
            self._schedule_refresh_retry()

    def _log_token_refresh_timing(self) -> None:
        """Log timing information for token refresh."""
        expiry = self._token_manager.expiry
        if expiry:
            time_to_expiry = (expiry - datetime.now()).total_seconds()
            logger.info(f"Refreshing token ({time_to_expiry:.1f}s until expiry)...")
        else:
            logger.info("Refreshing token...")

    def _invoke_refresh_callback(self) -> Optional[str]:
        """Invoke the token refresh callback and log duration."""
        callback_start = datetime.now()
        new_broker_url = self._token_refresh_callback(self._monitor_id)
        callback_duration = (datetime.now() - callback_start).total_seconds()
        logger.debug(f"Token refresh callback completed in {callback_duration:.1f}s")
        return new_broker_url

    def _handle_refresh_callback_failure(self) -> None:
        """Handle token refresh callback returning None."""
        with self._state_lock:
            self._consecutive_refresh_failures += 1
            failure_count = self._consecutive_refresh_failures
        logger.warning(
            "Token refresh callback returned None (attempt %d) - "
            "API may be unavailable, will retry with backoff",
            failure_count,
        )
        with self._state_lock:
            self._is_refreshing_token = False
        self._schedule_refresh_retry()

    def _apply_refreshed_token(self, new_broker_url: str) -> None:
        """Apply a successfully refreshed token and reconnect."""
        with self._state_lock:
            self._consecutive_refresh_failures = 0

        old_broker_url = self._broker_url
        self._broker_url = new_broker_url
        self._token_manager.update_broker_url(new_broker_url)

        self._reconnection_handler.on_success()
        logger.debug("Token updated, establishing new connection")

        try:
            client_id = f"ha-{self._monitor_id}-{uuid.uuid4().hex}"

            if self._mqtt_client.is_connected():
                logger.debug(
                    "Disconnecting old connection before token refresh reconnect"
                )
                self._mqtt_client.disconnect()

            self._mqtt_client.connect(broker_url=self._broker_url, client_id=client_id)

            with self._state_lock:
                self._subscriptions_setup = False

            self._mqtt_client.clear_intentional_disconnect_flag()
            logger.debug("Token refreshed with minimal downtime")

            with self._state_lock:
                self._is_refreshing_token = False

        except Exception as e:
            logger.error(f"Reconnection after token refresh failed: {e}")
            self._broker_url = old_broker_url
            with self._state_lock:
                self._is_refreshing_token = False
            self._schedule_reconnect()

    def _schedule_refresh_retry(self):
        """Schedule a token refresh retry with progressive backoff.

        Unlike _schedule_reconnect which tries to reconnect with the current (possibly stale)
        broker URL, this method specifically retries the token refresh callback after a delay.
        Uses progressive backoff based on consecutive failures to avoid hammering the API
        when it's down for maintenance.

        Only one pending retry is allowed at a time — if a retry is already scheduled,
        this call is a no-op.
        """
        # Guard against multiple concurrent retry threads
        if (
            self._pending_refresh_retry is not None
            and self._pending_refresh_retry.is_alive()
        ):
            logger.debug("Refresh retry already scheduled, skipping duplicate")
            return

        # Progressive backoff: 30s, 60s, 120s, 240s, 300s (max 5 min)
        base_delay = 30.0
        max_delay = 300.0
        with self._state_lock:
            failures = self._consecutive_refresh_failures
        delay = min(base_delay * (2 ** (failures - 1)), max_delay)

        logger.info(
            "Scheduling token refresh retry in %.0fs (failure #%d)",
            delay,
            failures,
        )

        retry_thread = threading.Thread(
            target=self._delayed_refresh_retry,
            args=(delay, failures),
            daemon=True,
        )
        self._pending_refresh_retry = retry_thread
        retry_thread.start()

    def _delayed_refresh_retry(self, delay: float, failure_count: int) -> None:
        """Execute a delayed token refresh retry (runs in background thread)."""
        if self._monitor_stop_event.is_set():
            return
        self._monitor_stop_event.wait(delay)
        if self._monitor_stop_event.is_set():
            return

        # Cap total consecutive failures to prevent infinite retry chains
        # when network is completely unavailable
        with self._state_lock:
            if self._consecutive_refresh_failures >= 10:
                logger.warning(
                    "Token refresh failed %d consecutive times, giving up. "
                    "Will resume on next successful connection.",
                    self._consecutive_refresh_failures,
                )
                return

        logger.info(
            "Retrying token refresh (attempt %d)...",
            failure_count + 1,
        )
        self._handle_token_refresh()

    def _schedule_token_refresh_then_reconnect(self) -> None:
        """Refresh the token immediately and reconnect with the fresh URL.

        Called when connection is lost and the token is already expired or expiring.
        Instead of reconnecting with a stale URL (which will just fail repeatedly),
        this refreshes the token first so the reconnection uses a valid broker URL.
        """
        # Guard against concurrent calls (e.g., rapid disconnect events)
        with self._state_lock:
            if self._is_refreshing_token or self._is_reconnecting:
                logger.debug(
                    "Skipping token-refresh-then-reconnect: already refreshing=%s, reconnecting=%s",
                    self._is_refreshing_token,
                    self._is_reconnecting,
                )
                return

        refresh_thread = threading.Thread(
            target=self._do_token_refresh_then_reconnect,
            daemon=True,
        )
        refresh_thread.start()

    def _do_token_refresh_then_reconnect(self) -> None:
        """Refresh token and reconnect (runs in background thread)."""
        if self._monitor_stop_event.is_set():
            return

        # Brief delay to let the disconnect settle
        time.sleep(1.0)

        if self._monitor_stop_event.is_set():
            return

        # Guard against concurrent refresh attempts (e.g., rapid disconnect events)
        with self._state_lock:
            if self._is_refreshing_token:
                logger.debug("Token refresh already in progress, skipping duplicate")
                return

        logger.info("Refreshing token after disconnect...")
        self._handle_token_refresh()

    def _schedule_reconnect(self):
        """Schedule reconnection with exponential backoff."""
        # Prevent concurrent reconnection cycles
        with self._state_lock:
            if self._is_reconnecting:
                logger.debug("Reconnection already in progress, skipping")
                return
            self._is_reconnecting = True

        if not self._reconnection_handler.should_attempt():
            self._handle_max_reconnect_attempts_reached()
            return

        delay = self._reconnection_handler.get_delay()
        attempt_num = self._reconnection_handler.on_attempt()

        logger.debug(f"Scheduling reconnection attempt {attempt_num} in {delay}s")

        reconnect_thread = threading.Thread(
            target=self._delayed_reconnect,
            args=(delay, attempt_num),
            daemon=True,
        )
        reconnect_thread.start()

    def _handle_max_reconnect_attempts_reached(self) -> None:
        """Handle exhaustion of reconnection attempts with cooldown."""
        logger.warning(
            "Max reconnection attempts reached, will retry after cooldown period. "
            "If this persists, token may be expired - forcing token refresh."
        )
        self._reconnection_handler.on_success()

        with self._state_lock:
            self._is_reconnecting = False

        if self._token_refresh_callback:
            cooldown_thread = threading.Thread(
                target=self._delayed_cooldown_refresh,
                daemon=True,
            )
            cooldown_thread.start()

    def _delayed_cooldown_refresh(self) -> None:
        """Wait for cooldown period then force a token refresh (runs in background)."""
        self._monitor_stop_event.wait(300)  # Interruptible 5 minute cooldown
        if self._monitor_stop_event.is_set():
            return

        # Respect the failure cap — don't keep retrying forever
        with self._state_lock:
            if self._consecutive_refresh_failures >= 10:
                logger.warning(
                    "Cooldown refresh skipped: %d consecutive failures, giving up.",
                    self._consecutive_refresh_failures,
                )
                return

        logger.info("Cooldown period ended, forcing token refresh")
        self._handle_token_refresh()

    def _delayed_reconnect(self, delay: float, attempt_num: int) -> None:
        """Execute a delayed reconnection attempt (runs in background thread)."""
        time.sleep(delay)
        if self._monitor_stop_event.is_set():
            with self._state_lock:
                self._is_reconnecting = False
            return
        try:
            client_id = f"ha-{self._monitor_id}-{uuid.uuid4().hex}"
            self._mqtt_client.connect(broker_url=self._broker_url, client_id=client_id)
            logger.debug("Reconnection successful")
            self._reconnection_handler.on_success()
            with self._state_lock:
                self._is_reconnecting = False
                self._subscriptions_setup = False

        except Exception as e:
            logger.error(f"Reconnection attempt {attempt_num} failed: {e}")
            with self._state_lock:
                self._is_reconnecting = False
            self._schedule_reconnect()

    # ========================================================================
    # MQTT Client Callbacks
    # ========================================================================

    def _on_mqtt_connected(self, connected: bool):
        """Handle MQTT connection status changes."""
        logger.debug(f"MQTT connection status changed: {connected}")

        if connected:
            self._handle_connection_established()
        else:
            self._handle_connection_lost()

    def _handle_connection_established(self) -> None:
        """Handle successful MQTT connection event."""
        self._reconnection_handler.on_success()

        # Reset failure counter so refresh retries resume after a network recovery
        with self._state_lock:
            self._consecutive_refresh_failures = 0

        # Schedule subscription setup in background to avoid blocking lifecycle callback
        setup_thread = threading.Thread(
            target=self._setup_after_connection, daemon=True
        )
        setup_thread.start()

        with self._state_lock:
            is_refreshing = self._is_refreshing_token

        if is_refreshing:
            logger.debug("Suppressing connectivity callback during token refresh")
            return

        self._callback_registry.notify("connectivity", True)

    def _setup_after_connection(self) -> None:
        """Setup subscriptions and load state after connection (runs in background)."""
        # Brief delay to ensure MQTT client is fully ready for subscriptions
        time.sleep(0.5)

        logger.debug("Setting up subscriptions after connection")
        with self._state_lock:
            self._subscriptions_setup = False

        try:
            self._setup_subscriptions()
            logger.debug("Loading initial state after connection")
            try:
                self.load_state()
            except Exception as e:
                logger.warning(f"Failed to load initial state after connection: {e}")
        except Exception as e:
            logger.error(f"Failed to setup subscriptions after connection: {e}")

    def _handle_connection_lost(self) -> None:
        """Handle MQTT disconnection event."""
        with self._state_lock:
            is_refreshing = self._is_refreshing_token
            is_reconnecting = self._is_reconnecting

        # Schedule reconnect if not already refreshing/reconnecting
        if (
            not is_refreshing
            and not is_reconnecting
            and self._token_refresh_callback
            and not self._monitor_stop_event.is_set()
        ):
            if self._token_manager.is_expired() or self._token_manager.should_refresh(
                False
            ):
                logger.info(
                    "Token expired/expiring on disconnect, refreshing token before reconnect"
                )
                self._token_manager.force_expiry()
                # Refresh the token first so reconnection uses a valid URL
                self._schedule_token_refresh_then_reconnect()
            else:
                logger.info("Unexpected disconnection, scheduling reconnection...")
                self._schedule_reconnect()

        # Suppress callbacks during refresh or reconnection
        if is_refreshing:
            logger.debug("Suppressing disconnection callback during token refresh")
            return

        if is_reconnecting:
            logger.debug("Suppressing disconnection callback during reconnection")
            return

        self._callback_registry.notify("connectivity", False)

    # ========================================================================
    # Message Handlers for Gecko Topics
    # ========================================================================

    def _on_config_response(self, topic: str, payload: str):
        """Handle configuration response."""
        logger.debug("Configuration response received")

        config = parse_json_safely(payload)
        if config:
            config = config.get("configuration", {}).get("configuration", {})
            notify_callbacks_safely(
                self._callback_registry.get_callbacks("config"), config
            )
            complete_future_safely(self._config_future, config)
        else:
            logger.error("Failed to parse configuration response")
            if self._config_future and not self._config_future.done():
                self._config_future.set_exception(
                    ConfigurationError("Invalid JSON in configuration response")
                )

    def _on_config_rejected(self, topic: str, payload: str):
        """Handle configuration request rejection."""
        logger.warning(f"Configuration request rejected on topic: {topic}")
        logger.warning(f"Rejection payload: {payload}")
        if self._config_future and not self._config_future.done():
            self._config_future.set_exception(
                ConfigurationError(f"Configuration rejected: {payload}")
            )

    def _on_state_response(self, topic: str, payload: str):
        """Handle state response."""
        logger.debug("State response received")
        state = parse_json_safely(payload)

        if state:
            notify_callbacks_safely(
                self._callback_registry.get_callbacks("state"), state
            )
            complete_future_safely(self._state_future, state)
        else:
            logger.error("Failed to parse state response")
            if self._state_future and not self._state_future.done():
                self._state_future.set_exception(
                    ConfigurationError("Invalid JSON in state response")
                )

    def _on_state_rejected(self, topic: str, payload: str):
        """Handle state request rejection."""
        logger.warning(f"State request rejected: {payload}")
        if self._state_future and not self._state_future.done():
            self._state_future.set_exception(
                ConfigurationError(f"State rejected: {payload}")
            )

    def _on_state_document_update(self, topic: str, payload: str):
        """Handle state document update notifications."""
        logger.debug("State document update received")
        document = parse_json_safely(payload)

        if document:
            # Extract current state from document structure
            current_state = document.get("current", {}).get("state", {})
            logger.debug("Extracted state from document")

            notify_callbacks_safely(
                self._callback_registry.get_callbacks("state_update"),
                {"state": current_state},
            )
        else:
            logger.error("Failed to parse state document update")

    def _on_state_update_rejected(self, topic: str, payload: str):
        """Handle state update rejection."""
        logger.warning(f"State update rejected: {payload}")
