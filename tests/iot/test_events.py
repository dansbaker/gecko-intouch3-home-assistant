"""
Unit tests for event system functionality.
"""

import unittest
from unittest.mock import Mock, patch

from custom_components.gecko.gecko_iot_client.models.events import EventChannel, EventEmitter


class TestEventChannel(unittest.TestCase):
    """Test EventChannel enum."""

    def test_event_channel_values(self):
        """Test that all event channel values are correct."""
        self.assertEqual(EventChannel.CONNECTIVITY_UPDATE.value, "connectivity_update")
        self.assertEqual(
            EventChannel.OPERATION_MODE_UPDATE.value, "operation_mode_update"
        )
        self.assertEqual(EventChannel.ZONE_UPDATE.value, "zone_update")
        self.assertEqual(EventChannel.SENSOR_UPDATE.value, "sensor_update")
        self.assertEqual(EventChannel.STATE_UPDATE.value, "state_update")
        self.assertEqual(
            EventChannel.CONFIGURATION_UPDATE.value, "configuration_update"
        )


class TestEventEmitter(unittest.TestCase):
    """Test EventEmitter functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.emitter = EventEmitter()

    def test_initialization(self):
        """Test EventEmitter initialization."""
        self.assertIsNotNone(self.emitter._callbacks)
        # All channels should have empty callback lists
        for channel in EventChannel:
            self.assertEqual(len(self.emitter._callbacks[channel]), 0)

    def test_on_register_callback(self):
        """Test registering a callback."""
        callback = Mock()
        self.emitter.on(EventChannel.CONNECTIVITY_UPDATE, callback)

        self.assertIn(
            callback, self.emitter._callbacks[EventChannel.CONNECTIVITY_UPDATE]
        )

    def test_on_register_multiple_callbacks(self):
        """Test registering multiple callbacks for same channel."""
        callback1 = Mock()
        callback2 = Mock()

        self.emitter.on(EventChannel.ZONE_UPDATE, callback1)
        self.emitter.on(EventChannel.ZONE_UPDATE, callback2)

        callbacks = self.emitter._callbacks[EventChannel.ZONE_UPDATE]
        self.assertEqual(len(callbacks), 2)
        self.assertIn(callback1, callbacks)
        self.assertIn(callback2, callbacks)

    def test_on_duplicate_callback_not_added(self):
        """Test that duplicate callbacks are not added."""
        callback = Mock()

        self.emitter.on(EventChannel.STATE_UPDATE, callback)
        self.emitter.on(EventChannel.STATE_UPDATE, callback)

        callbacks = self.emitter._callbacks[EventChannel.STATE_UPDATE]
        self.assertEqual(len(callbacks), 1)

    def test_off_unregister_callback(self):
        """Test unregistering a callback."""
        callback = Mock()

        self.emitter.on(EventChannel.SENSOR_UPDATE, callback)
        self.emitter.off(EventChannel.SENSOR_UPDATE, callback)

        self.assertNotIn(callback, self.emitter._callbacks[EventChannel.SENSOR_UPDATE])

    def test_off_callback_not_registered(self):
        """Test unregistering a callback that was never registered."""
        callback = Mock()

        # Should not raise an error
        self.emitter.off(EventChannel.CONFIGURATION_UPDATE, callback)

    def test_emit_with_data(self):
        """Test emitting an event with data."""
        callback = Mock()
        test_data = {"key": "value"}

        self.emitter.on(EventChannel.CONNECTIVITY_UPDATE, callback)
        self.emitter.emit(EventChannel.CONNECTIVITY_UPDATE, test_data)

        callback.assert_called_once_with(test_data)

    def test_emit_without_data(self):
        """Test emitting an event without data."""
        callback = Mock()

        self.emitter.on(EventChannel.OPERATION_MODE_UPDATE, callback)
        self.emitter.emit(EventChannel.OPERATION_MODE_UPDATE)

        callback.assert_called_once_with()

    def test_emit_multiple_callbacks(self):
        """Test emitting to multiple callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        test_data = "test"

        self.emitter.on(EventChannel.ZONE_UPDATE, callback1)
        self.emitter.on(EventChannel.ZONE_UPDATE, callback2)
        self.emitter.emit(EventChannel.ZONE_UPDATE, test_data)

        callback1.assert_called_once_with(test_data)
        callback2.assert_called_once_with(test_data)

    def test_emit_no_callbacks(self):
        """Test emitting when no callbacks are registered."""
        # Should not raise an error
        self.emitter.emit(EventChannel.STATE_UPDATE, "data")

    def test_emit_callback_exception_handling(self):
        """Test that exceptions in callbacks are caught and logged."""
        callback1 = Mock(side_effect=Exception("Test error"))
        callback2 = Mock()

        self.emitter.on(EventChannel.SENSOR_UPDATE, callback1)
        self.emitter.on(EventChannel.SENSOR_UPDATE, callback2)

        with patch.object(self.emitter._logger, "error") as mock_logger:
            self.emitter.emit(EventChannel.SENSOR_UPDATE, "data")

            # First callback should have raised exception
            callback1.assert_called_once_with("data")
            # Second callback should still be called
            callback2.assert_called_once_with("data")
            # Error should be logged
            mock_logger.assert_called_once()

    def test_clear_specific_channel(self):
        """Test clearing callbacks for a specific channel."""
        callback1 = Mock()
        callback2 = Mock()

        self.emitter.on(EventChannel.CONNECTIVITY_UPDATE, callback1)
        self.emitter.on(EventChannel.ZONE_UPDATE, callback2)

        self.emitter.clear(EventChannel.CONNECTIVITY_UPDATE)

        self.assertEqual(
            len(self.emitter._callbacks[EventChannel.CONNECTIVITY_UPDATE]), 0
        )
        self.assertEqual(len(self.emitter._callbacks[EventChannel.ZONE_UPDATE]), 1)

    def test_clear_all_channels(self):
        """Test clearing callbacks for all channels."""
        callback1 = Mock()
        callback2 = Mock()

        self.emitter.on(EventChannel.CONNECTIVITY_UPDATE, callback1)
        self.emitter.on(EventChannel.ZONE_UPDATE, callback2)

        self.emitter.clear()

        for channel in EventChannel:
            self.assertEqual(len(self.emitter._callbacks[channel]), 0)

    def test_clear_empty_channel(self):
        """Test clearing an already empty channel."""
        # Should not raise an error
        self.emitter.clear(EventChannel.STATE_UPDATE)

    def test_logging_on_register(self):
        """Test that callback registration is logged."""
        callback = Mock()
        with patch.object(self.emitter._logger, "debug") as mock_debug:
            self.emitter.on(EventChannel.CONNECTIVITY_UPDATE, callback)
            # Check that debug logging occurred
            mock_debug.assert_called()

    def test_logging_on_unregister(self):
        """Test that callback unregistration is logged."""
        callback = Mock()
        self.emitter.on(EventChannel.ZONE_UPDATE, callback)
        with patch.object(self.emitter._logger, "debug") as mock_debug:
            self.emitter.off(EventChannel.ZONE_UPDATE, callback)
            # Check that debug logging occurred
            mock_debug.assert_called()

    def test_logging_on_emit(self):
        """Test that event emission is logged."""
        with patch.object(self.emitter._logger, "debug") as mock_debug:
            self.emitter.emit(EventChannel.STATE_UPDATE, {"test": "data"})
            # Check that debug logging occurred
            mock_debug.assert_called()

    def test_callback_with_complex_data(self):
        """Test emitting with complex data structures."""
        callback = Mock()
        complex_data = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "number": 42,
        }

        self.emitter.on(EventChannel.CONFIGURATION_UPDATE, callback)
        self.emitter.emit(EventChannel.CONFIGURATION_UPDATE, complex_data)

        callback.assert_called_once_with(complex_data)


if __name__ == "__main__":
    unittest.main()
