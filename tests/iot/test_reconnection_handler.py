"""
Unit tests for reconnection handler functionality.
"""

import unittest

from custom_components.gecko.gecko_iot_client.transporters.mqtt.reconnection_handler import (  # noqa: E402
    ReconnectionHandler,
)


class TestReconnectionHandler(unittest.TestCase):
    """Test ReconnectionHandler functionality."""

    def test_default_initialization(self):
        """Test default initialization."""
        handler = ReconnectionHandler()
        self.assertEqual(handler.attempts, 0)
        self.assertTrue(handler.should_attempt())

    def test_custom_initialization(self):
        """Test initialization with custom parameters."""
        handler = ReconnectionHandler(max_attempts=5, base_delay=2.0, max_delay=60.0)
        self.assertEqual(handler._max_attempts, 5)
        self.assertEqual(handler._base_delay, 2.0)
        self.assertEqual(handler._max_delay, 60.0)

    def test_should_attempt_initial(self):
        """Test should_attempt returns True initially."""
        handler = ReconnectionHandler(max_attempts=3)
        self.assertTrue(handler.should_attempt())

    def test_should_attempt_after_attempts(self):
        """Test should_attempt after some attempts."""
        handler = ReconnectionHandler(max_attempts=3)

        handler.on_attempt()
        self.assertTrue(handler.should_attempt())

        handler.on_attempt()
        self.assertTrue(handler.should_attempt())

        handler.on_attempt()
        self.assertFalse(handler.should_attempt())

    def test_should_attempt_at_max(self):
        """Test should_attempt when at max attempts."""
        handler = ReconnectionHandler(max_attempts=2)

        handler.on_attempt()
        handler.on_attempt()

        self.assertFalse(handler.should_attempt())

    def test_get_delay_exponential_backoff(self):
        """Test exponential backoff delay calculation."""
        handler = ReconnectionHandler(base_delay=1.0, max_delay=100.0)

        # First attempt: 1.0 * 2^0 = 1.0
        self.assertEqual(handler.get_delay(), 1.0)

        # Second attempt: 1.0 * 2^1 = 2.0
        handler.on_attempt()
        self.assertEqual(handler.get_delay(), 2.0)

        # Third attempt: 1.0 * 2^2 = 4.0
        handler.on_attempt()
        self.assertEqual(handler.get_delay(), 4.0)

        # Fourth attempt: 1.0 * 2^3 = 8.0
        handler.on_attempt()
        self.assertEqual(handler.get_delay(), 8.0)

    def test_get_delay_max_cap(self):
        """Test that delay is capped at max_delay."""
        handler = ReconnectionHandler(base_delay=10.0, max_delay=50.0)

        # Simulate many attempts to exceed max_delay
        for _ in range(10):
            handler.on_attempt()

        delay = handler.get_delay()
        self.assertLessEqual(delay, 50.0)
        self.assertEqual(delay, 50.0)

    def test_on_attempt_increments_counter(self):
        """Test that on_attempt increments the attempt counter."""
        handler = ReconnectionHandler()

        self.assertEqual(handler.attempts, 0)

        attempt_num = handler.on_attempt()
        self.assertEqual(attempt_num, 1)
        self.assertEqual(handler.attempts, 1)

        attempt_num = handler.on_attempt()
        self.assertEqual(attempt_num, 2)
        self.assertEqual(handler.attempts, 2)

    def test_on_success_resets_counter(self):
        """Test that on_success resets the attempt counter."""
        handler = ReconnectionHandler()

        handler.on_attempt()
        handler.on_attempt()
        handler.on_attempt()

        self.assertEqual(handler.attempts, 3)

        handler.on_success()

        self.assertEqual(handler.attempts, 0)
        self.assertTrue(handler.should_attempt())

    def test_attempts_property(self):
        """Test the attempts property."""
        handler = ReconnectionHandler()

        self.assertEqual(handler.attempts, 0)

        handler.on_attempt()
        self.assertEqual(handler.attempts, 1)

        handler.on_attempt()
        self.assertEqual(handler.attempts, 2)

    def test_full_reconnection_cycle(self):
        """Test a full reconnection cycle."""
        handler = ReconnectionHandler(max_attempts=3, base_delay=1.0)

        # Attempt 1
        self.assertTrue(handler.should_attempt())
        delay1 = handler.get_delay()
        handler.on_attempt()
        self.assertEqual(delay1, 1.0)

        # Attempt 2
        self.assertTrue(handler.should_attempt())
        delay2 = handler.get_delay()
        handler.on_attempt()
        self.assertEqual(delay2, 2.0)

        # Attempt 3
        self.assertTrue(handler.should_attempt())
        delay3 = handler.get_delay()
        handler.on_attempt()
        self.assertEqual(delay3, 4.0)

        # No more attempts
        self.assertFalse(handler.should_attempt())

        # Success resets
        handler.on_success()
        self.assertTrue(handler.should_attempt())
        self.assertEqual(handler.get_delay(), 1.0)

    def test_zero_max_attempts(self):
        """Test behavior with zero max attempts."""
        handler = ReconnectionHandler(max_attempts=0)
        self.assertFalse(handler.should_attempt())

    def test_large_number_of_attempts(self):
        """Test with large number of attempts."""
        handler = ReconnectionHandler(
            max_attempts=100, base_delay=1.0, max_delay=1000.0
        )

        for i in range(50):
            self.assertTrue(handler.should_attempt())
            handler.on_attempt()

        # Delay should be capped at max_delay
        self.assertEqual(handler.get_delay(), 1000.0)


if __name__ == "__main__":
    unittest.main()
