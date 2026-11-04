"""
Unit tests for publish delivery confirmation in GeckoIotClient.

Tests that _publish_if_connected waits for the Future result (PUBACK)
before logging success, and correctly handles timeout/failure scenarios.
"""

import unittest
from concurrent.futures import Future
from unittest.mock import MagicMock, patch

from custom_components.gecko.gecko_iot_client import GeckoIotClient
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType
from custom_components.gecko.gecko_iot_client.transporters import AbstractTransporter


class TestPublishConfirmation(unittest.TestCase):
    """Test that publish operations wait for delivery confirmation."""

    def setUp(self):
        """Set up a GeckoIotClient with a mocked transporter."""
        self.transporter = MagicMock(spec=AbstractTransporter)
        self.client = GeckoIotClient("test-device", self.transporter)

        # Create a mock zone to trigger publish
        self.mock_zone = MagicMock()
        self.mock_zone.id = "1"
        self.mock_zone.name = "Test Zone"
        self.client._zones = {ZoneType.TEMPERATURE_CONTROL_ZONE: [self.mock_zone]}

        # Set up operation mode controller
        self.client._operation_mode_controller = MagicMock()

    def _setup_connected(self):
        """Configure client to appear fully connected."""
        self.client._connectivity_status.transport_connected = True
        self.client._connectivity_status.gateway_status = "CONNECTED"
        self.client._connectivity_status.vessel_status = "RUNNING"

    def _setup_disconnected(self):
        """Configure client to appear disconnected."""
        self.client._connectivity_status.transport_connected = False
        self.client._connectivity_status.gateway_status = "UNKNOWN"
        self.client._connectivity_status.vessel_status = "UNKNOWN"

    def test_publish_success_waits_for_future(self):
        """Test that successful publish waits for Future result before logging success."""
        self._setup_connected()

        # Create a Future that resolves successfully
        future = Future()
        future.set_result(None)
        self.transporter.publish_desired_state.return_value = future

        # Set up zone control and trigger a publish via zone callback
        self.client.setup_zone_control()

        # Get the zone callback that was registered
        zone_callback = self.mock_zone.set_publish_callback.call_args[0][0]

        # Trigger publish
        with patch.object(self.client._logger, "info") as mock_info:
            zone_callback("temperature_control", "1", {"target_temperature": 38})

        # Verify publish was called with correct desired state
        self.transporter.publish_desired_state.assert_called_once_with(
            {"zones": {"temperature_control": {"1": {"target_temperature": 38}}}}
        )

        # Verify success was logged
        mock_info.assert_any_call("✅ Published desired state for zone 1")

    def test_publish_timeout_logs_error(self):
        """Test that a publish timeout is detected and logged as an error."""
        self._setup_connected()

        # Create a Future that will timeout (never resolves)
        future = Future()
        self.transporter.publish_desired_state.return_value = future

        self.client.setup_zone_control()
        zone_callback = self.mock_zone.set_publish_callback.call_args[0][0]

        # Patch future.result to raise TimeoutError
        with patch.object(future, "result", side_effect=TimeoutError()):
            with patch.object(self.client._logger, "error") as mock_error:
                with patch.object(self.client._logger, "info") as mock_info:
                    with self.assertRaises(TimeoutError):
                        zone_callback(
                            "temperature_control", "1", {"target_temperature": 38}
                        )

        # Verify timeout error was logged
        mock_error.assert_called_once_with(
            "❌ Publish timed out for zone 1 — message may not have been delivered"
        )

        # Verify success was NOT logged
        success_calls = [
            call
            for call in mock_info.call_args_list
            if "Published desired state" in str(call)
        ]
        self.assertEqual(len(success_calls), 0)

    def test_publish_exception_logs_error(self):
        """Test that a publish exception is caught and logged."""
        self._setup_connected()

        # Create a Future that raises an exception
        future = Future()
        future.set_exception(ConnectionError("Connection lost"))
        self.transporter.publish_desired_state.return_value = future

        self.client.setup_zone_control()
        zone_callback = self.mock_zone.set_publish_callback.call_args[0][0]

        with patch.object(self.client._logger, "error") as mock_error:
            with patch.object(self.client._logger, "info") as mock_info:
                with self.assertRaises(ConnectionError):
                    zone_callback("temperature_control", "1", {"target_temperature": 38})

        # Verify error was logged
        mock_error.assert_called_once_with(
            "❌ Failed to publish desired state for zone 1: Connection lost"
        )

        # Verify success was NOT logged
        success_calls = [
            call
            for call in mock_info.call_args_list
            if "Published desired state" in str(call)
        ]
        self.assertEqual(len(success_calls), 0)

    def test_publish_when_disconnected_logs_error(self):
        """Test that publishing when disconnected logs an error without calling transporter."""
        self._setup_disconnected()

        self.client.setup_zone_control()
        zone_callback = self.mock_zone.set_publish_callback.call_args[0][0]

        with patch.object(self.client._logger, "error") as mock_error:
            with self.assertRaises(ConnectionError):
                zone_callback("temperature_control", "1", {"target_temperature": 38})

        # Verify not-connected error was logged
        mock_error.assert_called_once_with(
            "Failed to publish change to zone 1, not connected."
        )

        # Verify transporter was never called
        self.transporter.publish_desired_state.assert_not_called()

    def test_feature_publish_success(self):
        """Test that feature (operation mode) publish also waits for confirmation."""
        self._setup_connected()

        future = Future()
        future.set_result(None)
        self.transporter.publish_desired_state.return_value = future

        self.client.setup_zone_control()

        # Get the feature callback registered on operation mode controller
        feature_callback = (
            self.client._operation_mode_controller.set_publish_callback.call_args[0][0]
        )

        with patch.object(self.client._logger, "info") as mock_info:
            feature_callback("operationMode", {"operationMode": 2})

        # Verify publish was called with feature structure
        self.transporter.publish_desired_state.assert_called_once_with(
            {"features": {"operationMode": 2}}
        )

        mock_info.assert_any_call("✅ Published desired state for operationMode")

    def test_feature_publish_timeout(self):
        """Test that feature publish timeout is handled correctly."""
        self._setup_connected()

        future = Future()
        self.transporter.publish_desired_state.return_value = future

        self.client.setup_zone_control()
        feature_callback = (
            self.client._operation_mode_controller.set_publish_callback.call_args[0][0]
        )

        with patch.object(future, "result", side_effect=TimeoutError()):
            with patch.object(self.client._logger, "error") as mock_error:
                with self.assertRaises(TimeoutError):
                    feature_callback("operationMode", {"operationMode": 2})

        mock_error.assert_called_once_with(
            "❌ Publish timed out for operationMode — message may not have been delivered"
        )

    def test_publish_calls_future_result_with_timeout(self):
        """Test that future.result() is called with the 5-second timeout."""
        self._setup_connected()

        future = MagicMock()
        future.result.return_value = None
        self.transporter.publish_desired_state.return_value = future

        self.client.setup_zone_control()
        zone_callback = self.mock_zone.set_publish_callback.call_args[0][0]

        zone_callback("temperature_control", "1", {"target_temperature": 38})

        # Verify future.result was called with timeout=5.0
        future.result.assert_called_once_with(timeout=5.0)


if __name__ == "__main__":
    unittest.main()
