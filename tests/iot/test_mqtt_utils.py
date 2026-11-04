"""
Unit tests for MQTT utility functions.
"""

import unittest
from concurrent.futures import Future
from unittest.mock import Mock, patch

from custom_components.gecko.gecko_iot_client.transporters.mqtt.utils import (  # noqa: E402
    complete_future_safely,
    notify_callbacks_safely,
    parse_json_safely,
)


class TestParseJsonSafely(unittest.TestCase):
    """Test parse_json_safely function."""

    def test_parse_valid_json(self):
        """Test parsing valid JSON."""
        payload = '{"key": "value", "number": 42}'
        result = parse_json_safely(payload)
        self.assertEqual(result, {"key": "value", "number": 42})

    def test_parse_empty_string(self):
        """Test parsing empty string returns empty dict."""
        result = parse_json_safely("")
        self.assertEqual(result, {})

    def test_parse_none(self):
        """Test parsing None returns empty dict."""
        result = parse_json_safely(None)
        self.assertEqual(result, {})

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns None."""
        payload = '{"invalid": json}'
        result = parse_json_safely(payload)
        self.assertIsNone(result)

    def test_parse_complex_json(self):
        """Test parsing complex nested JSON."""
        payload = '{"nested": {"key": "value"}, "list": [1, 2, 3]}'
        result = parse_json_safely(payload)
        expected = {"nested": {"key": "value"}, "list": [1, 2, 3]}
        self.assertEqual(result, expected)

    @patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.utils.logger")
    def test_parse_logs_error(self, mock_logger):
        """Test that parsing errors are logged."""
        payload = "not valid json"
        parse_json_safely(payload)
        mock_logger.error.assert_called_once()


class TestCompleteFutureSafely(unittest.TestCase):
    """Test complete_future_safely function."""

    def test_complete_with_result(self):
        """Test completing future with result."""
        future = Future()
        result = {"data": "test"}

        complete_future_safely(future, result=result)

        self.assertTrue(future.done())
        self.assertEqual(future.result(), result)

    def test_complete_with_exception(self):
        """Test completing future with exception."""
        future = Future()
        error = ValueError("Test error")

        complete_future_safely(future, error=error)

        self.assertTrue(future.done())
        with self.assertRaises(ValueError):
            future.result()

    def test_complete_already_done_future(self):
        """Test completing an already done future does nothing."""
        future = Future()
        future.set_result("first result")

        # Should not raise an error
        complete_future_safely(future, result="second result")

        # Should still have first result
        self.assertEqual(future.result(), "first result")

    def test_complete_none_future(self):
        """Test completing None future does nothing."""
        # Should not raise an error
        complete_future_safely(None, result="test")

    def test_complete_with_none_result(self):
        """Test completing future with None result."""
        future = Future()

        complete_future_safely(future, result=None)

        self.assertTrue(future.done())
        self.assertIsNone(future.result())

    def test_complete_with_default_result(self):
        """Test completing future with default result (None)."""
        future = Future()

        complete_future_safely(future)

        self.assertTrue(future.done())
        self.assertIsNone(future.result())


class TestNotifyCallbacksSafely(unittest.TestCase):
    """Test notify_callbacks_safely function."""

    def test_notify_single_callback(self):
        """Test notifying a single callback."""
        callback = Mock()
        data = {"test": "data"}

        notify_callbacks_safely([callback], data)

        callback.assert_called_once_with(data)

    def test_notify_multiple_callbacks(self):
        """Test notifying multiple callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        callback3 = Mock()
        data = "test data"

        notify_callbacks_safely([callback1, callback2, callback3], data)

        callback1.assert_called_once_with(data)
        callback2.assert_called_once_with(data)
        callback3.assert_called_once_with(data)

    def test_notify_empty_callback_list(self):
        """Test notifying with empty callback list."""
        # Should not raise an error
        notify_callbacks_safely([], "data")

    @patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.utils.logger")
    def test_notify_callback_exception_handling(self, mock_logger):
        """Test that exceptions in callbacks are caught."""
        callback1 = Mock(side_effect=Exception("Test error"))
        callback2 = Mock()
        data = "test"

        notify_callbacks_safely([callback1, callback2], data)

        # First callback should have been called and raised exception
        callback1.assert_called_once_with(data)
        # Second callback should still be called
        callback2.assert_called_once_with(data)
        # Error should be logged
        mock_logger.error.assert_called_once()

    @patch("custom_components.gecko.gecko_iot_client.transporters.mqtt.utils.logger")
    def test_notify_all_callbacks_fail(self, mock_logger):
        """Test when all callbacks raise exceptions."""
        callback1 = Mock(side_effect=ValueError("Error 1"))
        callback2 = Mock(side_effect=TypeError("Error 2"))

        notify_callbacks_safely([callback1, callback2], "data")

        # Both callbacks should have been attempted
        callback1.assert_called_once()
        callback2.assert_called_once()
        # Both errors should be logged
        self.assertEqual(mock_logger.error.call_count, 2)

    def test_notify_with_none_data(self):
        """Test notifying callbacks with None data."""
        callback = Mock()

        notify_callbacks_safely([callback], None)

        callback.assert_called_once_with(None)

    def test_notify_with_complex_data(self):
        """Test notifying callbacks with complex data."""
        callback = Mock()
        data = {"nested": {"key": "value"}, "list": [1, 2, 3]}

        notify_callbacks_safely([callback], data)

        callback.assert_called_once_with(data)


if __name__ == "__main__":
    unittest.main()
