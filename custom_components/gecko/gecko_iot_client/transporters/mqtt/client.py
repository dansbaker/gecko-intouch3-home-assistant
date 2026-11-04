"""Low-level MQTT client for AWS IoT Core."""

import logging
import threading
import time
import urllib.parse
from concurrent.futures import Future
from typing import Callable, Dict, Optional

from awscrt import mqtt5
from awsiot import mqtt5_client_builder

from ..exceptions import ConfigurationError, ConnectionError
from .constants import CONNECTION_TIMEOUT, PUBLISH_TIMEOUT, SUBSCRIPTION_TIMEOUT

logger = logging.getLogger(__name__)

# Type alias
MessageHandler = Callable[[str, str], None]  # (topic, payload)


class MqttClient:
    """
    Low-level MQTT client for AWS IoT Core.

    Responsibilities:
    - Connection/disconnection to AWS IoT MQTT broker
    - Publishing messages
    - Subscribing to topics
    - Message routing to handlers
    - Connection lifecycle callbacks

    This class handles pure MQTT protocol concerns without any
    Gecko-specific business logic.
    """

    def __init__(
        self,
        on_connected: Optional[Callable[[bool], None]] = None,
        on_message: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Initialize MQTT client.

        Args:
            on_connected: Callback for connection status changes (bool: connected)
            on_message: Default callback for messages without specific handlers
        """
        self._on_connected_callback = on_connected
        self._on_default_message_callback = on_message

        # MQTT client state
        self._client: Optional[mqtt5.Client] = None
        self._connected = False
        self._intentional_disconnect = False
        self._lock = threading.RLock()

        # Topic handlers for message routing
        self._topic_handlers: Dict[str, MessageHandler] = {}

    def is_connected(self) -> bool:
        """
        Check if connected to broker.

        Returns:
            True if currently connected to MQTT broker
        """
        with self._lock:
            return self._connected

    def connect(
        self, broker_url: str, client_id: str, timeout: int = CONNECTION_TIMEOUT
    ) -> None:
        """
        Connect to AWS IoT MQTT broker.

        Args:
            broker_url: WebSocket URL with embedded JWT token and auth params
            client_id: Unique client identifier
            timeout: Connection timeout in seconds
        """
        with self._lock:
            if self._connected:
                logger.debug("Already connected")
                return

            self._intentional_disconnect = False

        try:
            # Parse WebSocket URL for connection parameters
            endpoint, auth_params = self._parse_websocket_url(broker_url)

            # Build MQTT5 client with AWS IoT custom authorizer
            self._client = mqtt5_client_builder.direct_with_custom_authorizer(
                endpoint=endpoint,
                auth_authorizer_name=auth_params["authorizer"],
                auth_username="",
                auth_password=b"",
                auth_token_key_name="token",
                auth_token_value=auth_params["token"],
                auth_authorizer_signature=auth_params["signature"],
                client_id=client_id,
                clean_start=True,
                keep_alive_secs=30,
                on_lifecycle_connection_success=self._on_connection_success,
                on_lifecycle_connection_failure=self._on_connection_failure,
                on_lifecycle_disconnection=self._on_disconnection,
                on_publish_received=self._on_message_received,
            )

            logger.debug(f"Connecting to AWS IoT at {endpoint}")
            if self._client is None:
                raise ConfigurationError("Failed to create MQTT client (returned None)")
            self._client.start()

            # Wait for connection
            if not self._wait_for_connection(timeout=timeout):
                raise ConnectionError("Connection timeout")

            with self._lock:
                self._connected = True

            logger.debug("Connected to AWS IoT")

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            with self._lock:
                self._connected = False
            if self._client:
                try:
                    self._client.stop()
                except Exception:
                    pass
                self._client = None
            raise ConnectionError(f"Connection failed: {e}")

    def disconnect(self) -> None:
        """Disconnect from broker (intentional disconnect)."""
        with self._lock:
            if not self._connected or not self._client:
                return
            self._intentional_disconnect = True
            client = self._client

        try:
            logger.debug("Disconnecting from AWS IoT")
            client.stop()

            # Wait for disconnection
            start_time = time.time()
            while self._connected and (time.time() - start_time) < 5:
                time.sleep(0.1)

            with self._lock:
                self._connected = False
                self._client = None
                self._topic_handlers.clear()

            logger.debug("Disconnected successfully")

        except Exception as e:
            logger.error(f"Disconnect error: {e}")
            with self._lock:
                self._connected = False
                self._client = None

    def publish(
        self, topic: str, payload: str, timeout: float = PUBLISH_TIMEOUT
    ) -> Future:
        """
        Publish message to a topic.

        Args:
            topic: MQTT topic
            payload: Message payload (string)
            timeout: Publish timeout in seconds

        Returns:
            Future for the publish operation
        """
        if not self._client:
            raise ConnectionError("Client not initialized")

        packet = mqtt5.PublishPacket(
            topic=topic, payload=payload.encode("utf-8"), qos=mqtt5.QoS.AT_LEAST_ONCE
        )

        return self._client.publish(packet)

    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """
        Subscribe to a topic with a message handler.

        Args:
            topic: MQTT topic to subscribe to
            handler: Callback function(topic, payload)
        """
        if not self._client:
            raise ConnectionError("Client not available")

        # Register handler first
        self._topic_handlers[topic] = handler

        # Subscribe to topic
        packet = mqtt5.SubscribePacket(
            subscriptions=[
                mqtt5.Subscription(topic_filter=topic, qos=mqtt5.QoS.AT_LEAST_ONCE)
            ]
        )

        future = self._client.subscribe(packet)
        try:
            future.result(timeout=SUBSCRIPTION_TIMEOUT)
            logger.debug(f"Subscribed to {topic}")
        except Exception as e:
            logger.error(f"Subscription failed for {topic}: {e}")
            # Remove handler on failure
            self._topic_handlers.pop(topic, None)
            raise

    def clear_intentional_disconnect_flag(self) -> None:
        """Clear the intentional disconnect flag after reconnection."""
        with self._lock:
            self._intentional_disconnect = False

    # Internal methods

    def _parse_websocket_url(self, url: str) -> tuple:
        """
        Parse WebSocket URL to extract AWS IoT connection parameters.

        Args:
            url: WebSocket URL with embedded JWT token and auth params

        Returns:
            Tuple of (endpoint, auth_params dict)

        Raises:
            ConfigurationError: If URL is malformed or missing required parameters
        """
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            endpoint = parsed_url.netloc
            auth_name = query_params.get("x-amz-customauthorizer-name", [None])[0]
            token = query_params.get("token", [None])[0]
            signature = query_params.get("x-amz-customauthorizer-signature", [None])[0]

            if not auth_name or not token or not signature:
                raise ConfigurationError(
                    "Missing required custom authorizer parameters in URL"
                )

            signature = urllib.parse.unquote(signature)

            auth_params = {
                "authorizer": auth_name,
                "token": token,
                "signature": signature,
            }

            logger.debug(f"Parsed endpoint: {endpoint}")
            return endpoint, auth_params

        except Exception as e:
            raise ConfigurationError(f"Failed to parse WebSocket URL: {e}")

    def _wait_for_connection(self, timeout: int = 10) -> bool:
        """
        Wait for connection establishment.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if connected within timeout, False otherwise
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._connected:
                return True
            time.sleep(0.1)
        return False

    # Lifecycle callbacks

    def _on_connection_success(self, connack_packet: mqtt5.LifecycleConnectSuccessData):
        """
        Handle successful connection.

        Args:
            connack_packet: Connection acknowledgment packet data
        """
        logger.debug("Connection successful")
        with self._lock:
            self._connected = True
        if self._on_connected_callback:
            self._on_connected_callback(True)

    def _on_connection_failure(self, connack_packet: mqtt5.LifecycleConnectFailureData):
        """
        Handle connection failure.

        Args:
            connack_packet: Connection failure packet data
        """
        logger.error("Connection failed")
        with self._lock:
            self._connected = False
        if self._on_connected_callback:
            self._on_connected_callback(False)

    def _on_disconnection(self, disconnect_packet: mqtt5.LifecycleDisconnectData):
        """
        Handle disconnection.

        Args:
            disconnect_packet: Disconnection packet data
        """
        logger.debug("Disconnected")

        with self._lock:
            was_intentional = self._intentional_disconnect
            self._connected = False

        # Only notify if it was unexpected
        if not was_intentional and self._on_connected_callback:
            self._on_connected_callback(False)

    def _on_message_received(self, publish_data):
        """
        Route incoming messages to handlers or default callback.

        Args:
            publish_data: Published message data from MQTT broker
        """
        try:
            topic = publish_data.publish_packet.topic
            payload = (
                publish_data.publish_packet.payload.decode("utf-8")
                if publish_data.publish_packet.payload
                else ""
            )

            logger.info(f"Received message on topic: {topic}")
            logger.debug(f"Registered handlers: {list(self._topic_handlers.keys())}")

            # Try specific handler first
            handler = self._topic_handlers.get(topic)
            if handler:
                logger.info(f"Routing message to registered handler for {topic}")
                try:
                    handler(topic, payload)
                except Exception as e:
                    logger.error(f"Handler error for {topic}: {e}")
            elif self._on_default_message_callback:
                # Fall back to default callback
                logger.info(f"Routing message to default callback for {topic}")
                self._on_default_message_callback(topic, payload)
            else:
                logger.warning(f"No handler registered for topic '{topic}'")

        except Exception as e:
            logger.error(f"Error in message handler: {e}")
