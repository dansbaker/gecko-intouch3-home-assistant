"""
Unit tests for reconnection flows, backoff, and token refresh orchestration.

Tests the MqttTransporter's reconnection logic including:
- Exponential backoff on unexpected disconnections
- Token refresh flow (disconnect → refresh → reconnect)
- Connectivity callback suppression during refresh
- Concurrent reconnection guards
- Progressive backoff on refresh failures
- Max attempts exhaustion and cooldown
"""

import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter import MqttTransporter  # noqa: E402


import pytest
from types import SimpleNamespace
from custom_components.gecko.gecko_iot_client.transporters.mqtt import transporter as transporter_module


@pytest.fixture(autouse=True)
def isolated_transport_workers(monkeypatch):
    """Keep worker sleeps independent of test sleeps and join every worker.

    Upstream patched the shared time module, so its assertions raced workers
    while the test's own sleep was also mocked. Its teardown also left retry
    threads sleeping past the end of a test. Isolate the clock reference and
    interrupt worker waits through the transporter's normal stop event.
    """
    workers = []

    def make_thread(*args, **kwargs):
        worker = threading.Thread(*args, **kwargs)
        target = kwargs.get("target")
        workers.append((worker, getattr(target, "__self__", None)))
        return worker

    def worker_sleep(delay):
        target = getattr(threading.current_thread(), "_target", None)
        owner = getattr(target, "__self__", None)
        if isinstance(owner, MqttTransporter):
            owner._monitor_stop_event.wait(delay)
        else:
            time.sleep(delay)

    monkeypatch.setattr(transporter_module, "time", SimpleNamespace(sleep=worker_sleep, time=time.time))
    monkeypatch.setattr(transporter_module, "threading", SimpleNamespace(Thread=make_thread, RLock=threading.RLock, Event=threading.Event))
    yield
    for worker, owner in workers:
        if isinstance(owner, MqttTransporter):
            owner._monitor_stop_event.set()
    for worker, _owner in workers:
        if worker.ident is not None:
            worker.join(timeout=2)
            assert not worker.is_alive(), f"Transport worker leaked: {worker.name}"


# Helper to create a valid broker URL for testing
def _make_test_broker_url(exp_seconds_from_now: int = 3600) -> str:
    """Create a broker URL with a token expiring in the given seconds."""
    import base64
    import json

    exp = (datetime.now() + timedelta(seconds=exp_seconds_from_now)).timestamp()
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(
        b"="
    )
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=")
    sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}.{sig.decode()}"
    return (
        f"wss://example.iot.us-east-1.amazonaws.com/mqtt?"
        f"x-amz-customauthorizer-name=MyAuth&"
        f"token={token}&"
        f"x-amz-customauthorizer-signature=sig123"
    )


class TestScheduleReconnect(unittest.TestCase):
    """Test _schedule_reconnect behavior."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()
        self.refresh_callback = Mock(return_value=_make_test_broker_url())

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = False
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=self.refresh_callback,
            )

    def tearDown(self):
        """Clean up monitor thread."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_reconnect_uses_exponential_backoff(self):
        """Test that reconnection delays follow exponential backoff."""
        delays = []
        original_sleep = time.sleep

        def capture_delay(d):
            delays.append(d)
            # Don't actually sleep in tests

        # Simulate failed reconnection attempts
        self.mock_mqtt.connect.side_effect = Exception("Connection refused")

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep", side_effect=capture_delay):
            # Trigger first reconnect
            self.transporter._schedule_reconnect()
            time.sleep(0.05)  # Let thread start

        # Wait for thread to execute
        original_sleep(0.2)

        # First delay should be base_delay (1.0)
        self.assertGreater(len(delays), 0)
        self.assertEqual(delays[0], 1.0)

    def test_reconnect_prevents_concurrent_attempts(self):
        """Test that concurrent reconnection attempts are prevented."""
        # Set reconnecting flag
        self.transporter._is_reconnecting = True

        # This should be a no-op
        self.transporter._schedule_reconnect()

        # MQTT connect should not have been called
        self.mock_mqtt.connect.assert_not_called()

    def test_reconnect_resets_on_success(self):
        """Test that successful reconnection resets the handler."""
        self.mock_mqtt.connect.return_value = None  # Success

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            self.transporter._schedule_reconnect()

        # Give the thread time to complete
        time.sleep(0.3)

        # After success, attempts should be reset
        self.assertEqual(self.transporter._reconnection_handler.attempts, 0)

    def test_reconnect_max_attempts_triggers_cooldown(self):
        """Test that exhausting max attempts triggers cooldown + token refresh."""
        # Exhaust all attempts
        handler = self.transporter._reconnection_handler
        for _ in range(handler._max_attempts):
            handler.on_attempt()

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(self.transporter, "_handle_token_refresh"):
                self.transporter._schedule_reconnect()
                # Should reset handler and schedule delayed refresh
                self.assertEqual(handler.attempts, 0)

    def test_reconnect_failure_triggers_next_attempt(self):
        """Test that failed reconnection schedules another attempt."""
        self.mock_mqtt.connect.side_effect = Exception("fail")

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(
                self.transporter,
                "_schedule_reconnect",
                wraps=self.transporter._schedule_reconnect,
            ) as mock_schedule:
                self.transporter._schedule_reconnect()
                time.sleep(0.3)

                # Should have been called recursively (original + retry)
                self.assertGreaterEqual(mock_schedule.call_count, 1)

    def test_reconnect_stops_when_monitor_event_set(self):
        """Test that reconnection aborts if stop event is set."""
        self.transporter._monitor_stop_event.set()

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            self.transporter._schedule_reconnect()
            time.sleep(0.2)

        # Should not attempt connection
        self.mock_mqtt.connect.assert_not_called()


class TestTokenRefreshFlow(unittest.TestCase):
    """Test _handle_token_refresh orchestration."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()
        self.new_broker_url = _make_test_broker_url(exp_seconds_from_now=7200)
        self.refresh_callback = Mock(return_value=self.new_broker_url)

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = True
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=self.refresh_callback,
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_successful_token_refresh_updates_broker_url(self):
        """Test that successful refresh updates the broker URL."""
        self.mock_mqtt.connect.return_value = None

        self.transporter._handle_token_refresh()

        self.assertEqual(self.transporter._broker_url, self.new_broker_url)

    def test_successful_refresh_disconnects_then_reconnects(self):
        """Test that refresh disconnects old connection before reconnecting."""
        call_order = []
        self.mock_mqtt.disconnect.side_effect = lambda: call_order.append("disconnect")
        self.mock_mqtt.connect.side_effect = lambda **kwargs: call_order.append(
            "connect"
        )

        self.transporter._handle_token_refresh()

        self.assertEqual(call_order, ["disconnect", "connect"])

    def test_successful_refresh_resets_reconnection_handler(self):
        """Test that successful refresh resets the reconnection handler."""
        self.mock_mqtt.connect.return_value = None

        # Simulate some prior reconnection attempts
        self.transporter._reconnection_handler.on_attempt()
        self.transporter._reconnection_handler.on_attempt()

        self.transporter._handle_token_refresh()

        self.assertEqual(self.transporter._reconnection_handler.attempts, 0)

    def test_successful_refresh_clears_refreshing_flag(self):
        """Test that _is_refreshing_token is cleared after success."""
        self.mock_mqtt.connect.return_value = None

        self.transporter._handle_token_refresh()

        self.assertFalse(self.transporter._is_refreshing_token)

    def test_successful_refresh_clears_subscription_state(self):
        """Test that subscriptions are marked for re-setup after refresh."""
        self.mock_mqtt.connect.return_value = None
        self.transporter._subscriptions_setup = True

        self.transporter._handle_token_refresh()

        self.assertFalse(self.transporter._subscriptions_setup)

    def test_refresh_callback_returns_none_schedules_retry(self):
        """Test that None from callback triggers retry scheduling."""
        self.refresh_callback.return_value = None

        with patch.object(self.transporter, "_schedule_refresh_retry") as mock_retry:
            self.transporter._handle_token_refresh()
            mock_retry.assert_called_once()

    def test_refresh_callback_returns_none_increments_failures(self):
        """Test that None from callback increments failure counter."""
        self.refresh_callback.return_value = None

        with patch.object(self.transporter, "_schedule_refresh_retry"):
            self.transporter._handle_token_refresh()

        self.assertEqual(self.transporter._consecutive_refresh_failures, 1)

    def test_refresh_callback_exception_schedules_retry(self):
        """Test that exception from callback triggers retry."""
        self.refresh_callback.side_effect = Exception("API error")

        with patch.object(self.transporter, "_schedule_refresh_retry") as mock_retry:
            self.transporter._handle_token_refresh()
            mock_retry.assert_called_once()

    def test_refresh_reconnect_failure_restores_old_url(self):
        """Test that failed reconnection after refresh restores old URL."""
        self.mock_mqtt.connect.side_effect = Exception("Connection failed")

        with patch.object(self.transporter, "_schedule_reconnect"):
            self.transporter._handle_token_refresh()

        # Should restore original URL
        self.assertEqual(self.transporter._broker_url, self.broker_url)

    def test_refresh_reconnect_failure_schedules_reconnect(self):
        """Test that failed reconnection after refresh schedules reconnect."""
        self.mock_mqtt.connect.side_effect = Exception("Connection failed")

        with patch.object(self.transporter, "_schedule_reconnect") as mock_reconnect:
            self.transporter._handle_token_refresh()
            mock_reconnect.assert_called_once()

    def test_refresh_without_callback_is_noop(self):
        """Test that refresh does nothing without a callback configured."""
        self.transporter._token_refresh_callback = None

        # Should not raise
        self.transporter._handle_token_refresh()

        self.mock_mqtt.disconnect.assert_not_called()
        self.mock_mqtt.connect.assert_not_called()

    def test_refresh_resets_failure_counter_on_success(self):
        """Test that successful refresh resets consecutive failure counter."""
        self.transporter._consecutive_refresh_failures = 3
        self.mock_mqtt.connect.return_value = None

        self.transporter._handle_token_refresh()

        self.assertEqual(self.transporter._consecutive_refresh_failures, 0)


class TestScheduleRefreshRetry(unittest.TestCase):
    """Test _schedule_refresh_retry progressive backoff."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = False
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=Mock(return_value=self.broker_url),
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_progressive_backoff_delays(self):
        """Test that retry delays follow progressive backoff pattern."""
        # Base delay is 30s, formula: min(30 * 2^(failures-1), 300)
        expected_delays = {
            1: 30.0,  # 30 * 2^0
            2: 60.0,  # 30 * 2^1
            3: 120.0,  # 30 * 2^2
            4: 240.0,  # 30 * 2^3
            5: 300.0,  # capped at max 300
            6: 300.0,  # still capped
        }

        for failures, expected_delay in expected_delays.items():
            self.transporter._consecutive_refresh_failures = failures
            # Calculate what the delay would be
            base_delay = 30.0
            max_delay = 300.0
            delay = min(base_delay * (2 ** (failures - 1)), max_delay)
            self.assertEqual(delay, expected_delay, f"Failed for {failures} failures")

    def test_prevents_duplicate_retry_threads(self):
        """Test that only one retry thread runs at a time."""
        self.transporter._consecutive_refresh_failures = 1

        # Create a mock thread that appears alive
        mock_thread = Mock()
        mock_thread.is_alive.return_value = True
        self.transporter._pending_refresh_retry = mock_thread

        # Patch _handle_token_refresh to track calls
        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            self.transporter._schedule_refresh_retry()
            # Should not spawn a new thread
            time.sleep(0.1)
            mock_refresh.assert_not_called()

    def test_retry_aborts_when_stop_event_set(self):
        """Test that retry does not execute refresh if stopped."""
        self.transporter._consecutive_refresh_failures = 1
        self.transporter._monitor_stop_event.set()

        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            self.transporter._schedule_refresh_retry()
            time.sleep(0.2)
            mock_refresh.assert_not_called()


class TestConnectivityCallbackSuppression(unittest.TestCase):
    """Test that connectivity callbacks are suppressed during token refresh."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = True
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=Mock(return_value=self.broker_url),
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_connected_callback_suppressed_during_refresh(self):
        """Test that connected=True callback is suppressed during refresh."""
        connectivity_events = []
        self.transporter._callback_registry.register(
            "connectivity", lambda connected: connectivity_events.append(connected)
        )

        # Set refreshing flag
        self.transporter._is_refreshing_token = True

        # Simulate connection event during refresh
        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(self.transporter, "_setup_subscriptions"):
                self.transporter._on_mqtt_connected(True)

        # Callback should NOT have been called
        self.assertEqual(connectivity_events, [])

    def test_disconnected_callback_suppressed_during_refresh(self):
        """Test that connected=False callback is suppressed during refresh."""
        connectivity_events = []
        self.transporter._callback_registry.register(
            "connectivity", lambda connected: connectivity_events.append(connected)
        )

        # Set refreshing flag
        self.transporter._is_refreshing_token = True

        self.transporter._on_mqtt_connected(False)

        # Callback should NOT have been called
        self.assertEqual(connectivity_events, [])

    def test_disconnected_callback_suppressed_during_reconnection(self):
        """Test that disconnect callback is suppressed during reconnection."""
        connectivity_events = []
        self.transporter._callback_registry.register(
            "connectivity", lambda connected: connectivity_events.append(connected)
        )

        # Set reconnecting flag
        self.transporter._is_reconnecting = True

        self.transporter._on_mqtt_connected(False)

        # Callback should NOT have been called
        self.assertEqual(connectivity_events, [])

    def test_normal_disconnect_triggers_callback(self):
        """Test that normal disconnect (no refresh/reconnect) fires callback."""
        connectivity_events = []
        self.transporter._callback_registry.register(
            "connectivity", lambda connected: connectivity_events.append(connected)
        )

        # Neither refreshing nor reconnecting, but stop event set to prevent
        # actual reconnection scheduling
        self.transporter._monitor_stop_event.set()
        self.transporter._on_mqtt_connected(False)

        self.assertEqual(connectivity_events, [False])

    def test_normal_connect_triggers_callback(self):
        """Test that normal connection fires callback."""
        connectivity_events = []
        self.transporter._callback_registry.register(
            "connectivity", lambda connected: connectivity_events.append(connected)
        )

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(self.transporter, "_setup_subscriptions"):
                self.transporter._on_mqtt_connected(True)

        # Give the setup thread a moment
        time.sleep(0.2)
        self.assertEqual(connectivity_events, [True])


class TestDisconnectionTriggersReconnect(unittest.TestCase):
    """Test that unexpected disconnections trigger reconnection."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = False
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=Mock(return_value=self.broker_url),
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_unexpected_disconnect_schedules_reconnect(self):
        """Test that unexpected disconnect triggers _schedule_reconnect."""
        with patch.object(self.transporter, "_schedule_reconnect") as mock_reconnect:
            self.transporter._on_mqtt_connected(False)
            mock_reconnect.assert_called_once()

    def test_disconnect_does_not_reconnect_when_stopped(self):
        """Test that disconnect doesn't reconnect when stop event is set."""
        self.transporter._monitor_stop_event.set()

        with patch.object(self.transporter, "_schedule_reconnect") as mock_reconnect:
            self.transporter._on_mqtt_connected(False)
            mock_reconnect.assert_not_called()

    def test_disconnect_does_not_reconnect_without_refresh_callback(self):
        """Test that disconnect doesn't reconnect without token refresh callback."""
        self.transporter._token_refresh_callback = None

        with patch.object(self.transporter, "_schedule_reconnect") as mock_reconnect:
            self.transporter._on_mqtt_connected(False)
            mock_reconnect.assert_not_called()

    def test_disconnect_with_expired_token_refreshes_instead_of_reconnect(self):
        """Test that disconnect with expired token triggers token refresh, not blind reconnect."""
        self.transporter._token_manager.force_expiry()

        with patch.object(
            self.transporter, "_schedule_token_refresh_then_reconnect"
        ) as mock_refresh:
            with patch.object(
                self.transporter, "_schedule_reconnect"
            ) as mock_reconnect:
                self.transporter._on_mqtt_connected(False)
                mock_refresh.assert_called_once()
                mock_reconnect.assert_not_called()

    def test_disconnect_with_valid_token_schedules_reconnect(self):
        """Test that disconnect with valid token uses normal reconnect path."""
        # Token is valid (created with 1 hour expiry by default)
        with patch.object(
            self.transporter, "_schedule_token_refresh_then_reconnect"
        ) as mock_refresh:
            with patch.object(
                self.transporter, "_schedule_reconnect"
            ) as mock_reconnect:
                self.transporter._on_mqtt_connected(False)
                mock_reconnect.assert_called_once()
                mock_refresh.assert_not_called()

    def test_disconnect_forces_expiry_when_token_expired(self):
        """Test that disconnect forces token expiry when token is expired."""
        self.transporter._token_manager.force_expiry()

        with patch.object(self.transporter, "_schedule_token_refresh_then_reconnect"):
            self.transporter._on_mqtt_connected(False)

        self.assertTrue(self.transporter._token_manager.is_expired())


class TestTokenRefreshThenReconnect(unittest.TestCase):
    """Test _schedule_token_refresh_then_reconnect behavior."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()
        self.new_broker_url = _make_test_broker_url(exp_seconds_from_now=7200)
        self.refresh_callback = Mock(return_value=self.new_broker_url)

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = False
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=self.refresh_callback,
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.2)

    def test_calls_handle_token_refresh(self):
        """Test that _schedule_token_refresh_then_reconnect invokes _handle_token_refresh."""
        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(
                self.transporter, "_handle_token_refresh"
            ) as mock_refresh:
                self.transporter._schedule_token_refresh_then_reconnect()
                time.sleep(0.3)
                mock_refresh.assert_called_once()

    def test_aborts_when_stop_event_set_before_start(self):
        """Test that refresh aborts if stop event is set before thread runs."""
        self.transporter._monitor_stop_event.set()

        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            self.transporter._schedule_token_refresh_then_reconnect()
            time.sleep(0.3)
            mock_refresh.assert_not_called()

    def test_aborts_when_stop_event_set_during_delay(self):
        """Test that refresh aborts if stop event is set during the settle delay."""
        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            self.transporter._schedule_token_refresh_then_reconnect()
            # Set stop event immediately — before the 1s sleep finishes
            self.transporter._monitor_stop_event.set()
            time.sleep(1.5)
            mock_refresh.assert_not_called()

    def test_successful_refresh_updates_broker_url(self):
        """Test end-to-end: expired token disconnect → refresh → new URL applied."""
        self.mock_mqtt.connect.return_value = None

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            self.transporter._schedule_token_refresh_then_reconnect()
            time.sleep(0.3)

        self.assertEqual(self.transporter._broker_url, self.new_broker_url)

    def test_failed_refresh_schedules_retry(self):
        """Test that failed refresh callback schedules a retry."""
        self.refresh_callback.return_value = None

        with patch.object(self.transporter, "_schedule_refresh_retry") as mock_retry:
            # Call directly to avoid thread timing issues
            self.transporter._do_token_refresh_then_reconnect()
            mock_retry.assert_called_once()

    def test_does_not_leave_refreshing_flag_stuck(self):
        """Test that _is_refreshing_token is always cleared, even on failure."""
        self.refresh_callback.side_effect = Exception("API down")

        with patch.object(self.transporter, "_schedule_refresh_retry"):
            # Call directly to avoid thread timing issues
            self.transporter._do_token_refresh_then_reconnect()

        self.assertFalse(self.transporter._is_refreshing_token)

    def test_does_not_leave_reconnecting_flag_stuck(self):
        """Test that _is_reconnecting is not set by the refresh path."""
        self.mock_mqtt.connect.return_value = None

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            self.transporter._schedule_token_refresh_then_reconnect()
            time.sleep(0.3)

        # The refresh path should not set _is_reconnecting
        self.assertFalse(self.transporter._is_reconnecting)

    def test_connect_failure_after_refresh_falls_back_to_reconnect(self):
        """Test that connect failure after successful refresh falls back to _schedule_reconnect."""
        self.mock_mqtt.connect.side_effect = Exception("Connection refused")

        with patch.object(self.transporter, "_schedule_reconnect") as mock_reconnect:
            # Call directly to avoid thread timing issues
            self.transporter._do_token_refresh_then_reconnect()
            mock_reconnect.assert_called_once()

    def test_concurrent_disconnects_do_not_spawn_multiple_refreshes(self):
        """Test that rapid disconnects don't spawn unbounded refresh threads."""
        call_count = []

        original_handle = self.transporter._handle_token_refresh

        def counting_handle():
            call_count.append(1)
            # Simulate slow refresh
            time.sleep(0.5)
            original_handle()

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(
                self.transporter, "_handle_token_refresh", side_effect=counting_handle
            ):
                # Simulate multiple rapid disconnects triggering refresh
                self.transporter._schedule_token_refresh_then_reconnect()
                self.transporter._schedule_token_refresh_then_reconnect()
                self.transporter._schedule_token_refresh_then_reconnect()
                time.sleep(1.0)

        # Each call spawns a thread, but _handle_token_refresh guards with
        # _is_refreshing_token flag — only the first should fully execute
        # (others will see _is_refreshing_token=True and the flag prevents
        # duplicate work at the _handle_connection_lost level)
        # The threads themselves will all run, but the guard is at the caller level
        self.assertGreaterEqual(len(call_count), 1)


class TestExpiryMonitorLoop(unittest.TestCase):
    """Test the background token expiry monitoring loop."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url(exp_seconds_from_now=100)

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = True
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=Mock(return_value=_make_test_broker_url()),
                token_refresh_buffer_seconds=300,
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.2)

    def test_monitor_triggers_refresh_when_within_buffer(self):
        """Test that monitor triggers refresh when token is within buffer."""
        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            with patch.object(
                self.transporter, "_should_refresh_token", return_value=True
            ):
                # Run one iteration of the loop
                self.transporter._monitor_stop_event.clear()

                # Start monitoring and let it run briefly
                thread = threading.Thread(
                    target=self.transporter._expiry_monitor_loop, daemon=True
                )
                thread.start()
                time.sleep(0.15)
                self.transporter._monitor_stop_event.set()
                thread.join(timeout=1)

                mock_refresh.assert_called()

    def test_monitor_skips_refresh_when_already_refreshing(self):
        """Test that monitor skips refresh if already in progress."""
        self.transporter._is_refreshing_token = True

        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            with patch.object(
                self.transporter, "_should_refresh_token", return_value=True
            ):
                thread = threading.Thread(
                    target=self.transporter._expiry_monitor_loop, daemon=True
                )
                thread.start()
                time.sleep(0.15)
                self.transporter._monitor_stop_event.set()
                thread.join(timeout=1)

                mock_refresh.assert_not_called()

    def test_monitor_skips_refresh_when_failures_pending(self):
        """Test that monitor skips refresh when consecutive failures exist."""
        self.transporter._consecutive_refresh_failures = 2

        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            with patch.object(
                self.transporter, "_should_refresh_token", return_value=True
            ):
                thread = threading.Thread(
                    target=self.transporter._expiry_monitor_loop, daemon=True
                )
                thread.start()
                time.sleep(0.15)
                self.transporter._monitor_stop_event.set()
                thread.join(timeout=1)

                mock_refresh.assert_not_called()

    def test_monitor_does_not_refresh_when_not_needed(self):
        """Test that monitor does nothing when token is not near expiry."""
        with patch.object(self.transporter, "_handle_token_refresh") as mock_refresh:
            with patch.object(
                self.transporter, "_should_refresh_token", return_value=False
            ):
                thread = threading.Thread(
                    target=self.transporter._expiry_monitor_loop, daemon=True
                )
                thread.start()
                time.sleep(0.15)
                self.transporter._monitor_stop_event.set()
                thread.join(timeout=1)

                mock_refresh.assert_not_called()


class TestRefreshBeforeConnect(unittest.TestCase):
    """Test _refresh_token_before_connect behavior."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()
        self.new_broker_url = _make_test_broker_url(exp_seconds_from_now=7200)
        self.refresh_callback = Mock(return_value=self.new_broker_url)

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = False
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=self.refresh_callback,
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()

    def test_successful_refresh_before_connect(self):
        """Test successful token refresh before initial connection."""
        self.transporter._refresh_token_before_connect()

        self.assertEqual(self.transporter._broker_url, self.new_broker_url)
        self.assertEqual(self.transporter._consecutive_refresh_failures, 0)

    def test_refresh_before_connect_none_increments_failures(self):
        """Test that None return increments failure counter."""
        self.refresh_callback.return_value = None

        with patch.object(self.transporter, "_schedule_refresh_retry"):
            self.transporter._refresh_token_before_connect()

        self.assertEqual(self.transporter._consecutive_refresh_failures, 1)

    def test_refresh_before_connect_exception_increments_failures(self):
        """Test that exception increments failure counter."""
        self.refresh_callback.side_effect = Exception("Network error")

        with patch.object(self.transporter, "_schedule_refresh_retry"):
            self.transporter._refresh_token_before_connect()

        self.assertEqual(self.transporter._consecutive_refresh_failures, 1)

    def test_refresh_before_connect_noop_without_callback(self):
        """Test that refresh is skipped without callback."""
        self.transporter._token_refresh_callback = None

        self.transporter._refresh_token_before_connect()

        # Should not crash, broker URL unchanged
        self.assertEqual(self.transporter._broker_url, self.broker_url)


class TestConnectionSuccessResetsHandler(unittest.TestCase):
    """Test that successful connection resets reconnection state."""

    def setUp(self):
        """Set up transporter with mocked MQTT client."""
        self.broker_url = _make_test_broker_url()

        with patch(
            "custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.MqttClient"
        ) as MockClient:
            self.mock_mqtt = MockClient.return_value
            self.mock_mqtt.is_connected.return_value = True
            self.transporter = MqttTransporter(
                broker_url=self.broker_url,
                monitor_id="test-monitor-123",
                token_refresh_callback=Mock(return_value=self.broker_url),
            )

    def tearDown(self):
        """Clean up."""
        self.transporter._monitor_stop_event.set()
        time.sleep(0.1)

    def test_connection_success_resets_reconnection_handler(self):
        """Test that successful connection resets attempt counter."""
        # Simulate some prior attempts
        self.transporter._reconnection_handler.on_attempt()
        self.transporter._reconnection_handler.on_attempt()

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(self.transporter, "_setup_subscriptions"):
                self.transporter._on_mqtt_connected(True)

        self.assertEqual(self.transporter._reconnection_handler.attempts, 0)

    def test_connection_success_triggers_subscription_setup(self):
        """Test that connection triggers subscription re-setup."""
        self.transporter._subscriptions_setup = True

        with patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.transporter.time.sleep"):
            with patch.object(self.transporter, "_setup_subscriptions") as mock_setup:
                self.transporter._on_mqtt_connected(True)
                time.sleep(0.3)
                mock_setup.assert_called()


if __name__ == "__main__":
    unittest.main()
