"""
Unit tests for callback registry functionality.
"""

import unittest
from unittest.mock import Mock

from custom_components.gecko.gecko_iot_client.transporters.mqtt.callback_registry import (  # noqa: E402
    CallbackRegistry,
)


class TestCallbackRegistry(unittest.TestCase):
    """Test CallbackRegistry functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry = CallbackRegistry()

    def test_initialization(self):
        """Test registry initialization."""
        self.assertIsNotNone(self.registry._callbacks)
        self.assertEqual(len(self.registry._callbacks), 0)

    def test_register_callback(self):
        """Test registering a callback."""
        callback = Mock()
        self.registry.register("test_category", callback)

        callbacks = self.registry.get_callbacks("test_category")
        self.assertEqual(len(callbacks), 1)
        self.assertIn(callback, callbacks)

    def test_register_multiple_callbacks_same_category(self):
        """Test registering multiple callbacks for same category."""
        callback1 = Mock()
        callback2 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category1", callback2)

        callbacks = self.registry.get_callbacks("category1")
        self.assertEqual(len(callbacks), 2)
        self.assertIn(callback1, callbacks)
        self.assertIn(callback2, callbacks)

    def test_register_duplicate_callback(self):
        """Test that duplicate callbacks are not added."""
        callback = Mock()

        self.registry.register("category1", callback)
        self.registry.register("category1", callback)

        callbacks = self.registry.get_callbacks("category1")
        self.assertEqual(len(callbacks), 1)

    def test_register_callbacks_different_categories(self):
        """Test registering callbacks for different categories."""
        callback1 = Mock()
        callback2 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category2", callback2)

        callbacks1 = self.registry.get_callbacks("category1")
        callbacks2 = self.registry.get_callbacks("category2")

        self.assertEqual(len(callbacks1), 1)
        self.assertEqual(len(callbacks2), 1)
        self.assertIn(callback1, callbacks1)
        self.assertIn(callback2, callbacks2)

    def test_get_callbacks_nonexistent_category(self):
        """Test getting callbacks for nonexistent category."""
        callbacks = self.registry.get_callbacks("nonexistent")
        self.assertEqual(callbacks, [])

    def test_get_callbacks_returns_copy(self):
        """Test that get_callbacks returns a copy for thread safety."""
        callback = Mock()
        self.registry.register("category1", callback)

        callbacks1 = self.registry.get_callbacks("category1")
        callbacks2 = self.registry.get_callbacks("category1")

        # Should be equal but not the same object
        self.assertEqual(callbacks1, callbacks2)
        self.assertIsNot(callbacks1, callbacks2)

    def test_notify_single_callback(self):
        """Test notifying a single callback."""
        callback = Mock()
        self.registry.register("category1", callback)

        test_data = {"key": "value"}
        self.registry.notify("category1", test_data)

        callback.assert_called_once_with(test_data)

    def test_notify_multiple_callbacks(self):
        """Test notifying multiple callbacks."""
        callback1 = Mock()
        callback2 = Mock()
        callback3 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category1", callback2)
        self.registry.register("category1", callback3)

        test_data = "test"
        self.registry.notify("category1", test_data)

        callback1.assert_called_once_with(test_data)
        callback2.assert_called_once_with(test_data)
        callback3.assert_called_once_with(test_data)

    def test_notify_nonexistent_category(self):
        """Test notifying nonexistent category does nothing."""
        # Should not raise an error
        self.registry.notify("nonexistent", "data")

    def test_notify_with_callback_exception(self):
        """Test that exceptions in callbacks don't stop other callbacks."""
        callback1 = Mock(side_effect=Exception("Test error"))
        callback2 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category1", callback2)

        # Should not raise an error
        self.registry.notify("category1", "data")

        # Both callbacks should have been called
        callback1.assert_called_once_with("data")
        callback2.assert_called_once_with("data")

    def test_clear_specific_category(self):
        """Test clearing callbacks for a specific category."""
        callback1 = Mock()
        callback2 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category2", callback2)

        self.registry.clear("category1")

        callbacks1 = self.registry.get_callbacks("category1")
        callbacks2 = self.registry.get_callbacks("category2")

        self.assertEqual(len(callbacks1), 0)
        self.assertEqual(len(callbacks2), 1)

    def test_clear_all_categories(self):
        """Test clearing all categories."""
        callback1 = Mock()
        callback2 = Mock()

        self.registry.register("category1", callback1)
        self.registry.register("category2", callback2)

        self.registry.clear()

        callbacks1 = self.registry.get_callbacks("category1")
        callbacks2 = self.registry.get_callbacks("category2")

        self.assertEqual(len(callbacks1), 0)
        self.assertEqual(len(callbacks2), 0)

    def test_clear_nonexistent_category(self):
        """Test clearing nonexistent category does nothing."""
        # Should not raise an error
        self.registry.clear("nonexistent")

    def test_thread_safety_get_callbacks(self):
        """Test that modifying returned list doesn't affect registry."""
        callback = Mock()
        self.registry.register("category1", callback)

        callbacks = self.registry.get_callbacks("category1")
        callbacks.clear()

        # Original registry should still have the callback
        callbacks_after = self.registry.get_callbacks("category1")
        self.assertEqual(len(callbacks_after), 1)


if __name__ == "__main__":
    unittest.main()
