"""
Unit tests for OperationModeController functionality.
"""

import unittest
from unittest.mock import Mock

from custom_components.gecko.gecko_iot_client.models.operation_mode import OperationMode
from custom_components.gecko.gecko_iot_client.models.operation_mode_controller import (
    OperationModeController,
)


class TestOperationModeController(unittest.TestCase):
    """Test OperationModeController functionality."""

    def test_default_initialization(self):
        """Test default initialization of OperationModeController."""
        controller = OperationModeController()
        self.assertEqual(controller.operation_mode, OperationMode.OTHER)
        self.assertEqual(controller.mode_name, "Other")
        self.assertFalse(controller.is_energy_saving)
        self.assertIsNone(controller._publish_callback)

    def test_set_publish_callback(self):
        """Test setting publish callback."""
        callback = Mock()
        controller = OperationModeController()
        controller.set_publish_callback(callback)
        self.assertEqual(controller._publish_callback, callback)

    def test_from_state_data_valid(self):
        """Test creating OperationModeController from valid state data."""
        state_data = {"state": {"reported": {"features": {"operationMode": 2}}}}

        controller = OperationModeController.from_state_data(state_data)
        self.assertEqual(controller.operation_mode, OperationMode.SAVINGS)

    def test_from_state_data_invalid(self):
        """Test creating OperationModeController from invalid state data."""
        controller = OperationModeController.from_state_data({})
        self.assertEqual(controller.operation_mode, OperationMode.OTHER)

    def test_update_from_state_data_changed(self):
        """Test updating from state data when mode changes."""
        controller = OperationModeController()

        state_data = {"state": {"reported": {"features": {"operationMode": 4}}}}

        changed = controller.update_from_state_data(state_data)
        self.assertTrue(changed)
        self.assertEqual(controller.operation_mode, OperationMode.WEEKENDER)

    def test_update_from_state_data_unchanged(self):
        """Test updating from state data when mode doesn't change."""
        controller = OperationModeController()
        controller.operation_mode = OperationMode.SAVINGS

        state_data = {"state": {"reported": {"features": {"operationMode": 2}}}}

        changed = controller.update_from_state_data(state_data)
        self.assertFalse(changed)

    def test_set_mode_with_callback(self):
        """Test setting mode triggers publish callback."""
        callback = Mock()
        controller = OperationModeController()
        controller.set_publish_callback(callback)

        controller.set_mode(OperationMode.AWAY)

        callback.assert_called_once_with("operationMode", {"operationMode": 0})

    def test_set_mode_without_callback(self):
        """Test setting mode without publish callback."""
        controller = OperationModeController()

        # Should not raise an error, but will log a warning
        controller.set_mode(OperationMode.STANDARD)

    def test_set_mode_all_modes(self):
        """Test setting all operation modes."""
        callback = Mock()
        controller = OperationModeController()
        controller.set_publish_callback(callback)

        modes = [
            (OperationMode.AWAY, 0),
            (OperationMode.STANDARD, 1),
            (OperationMode.SAVINGS, 2),
            (OperationMode.SUPER_SAVINGS, 3),
            (OperationMode.WEEKENDER, 4),
            (OperationMode.OTHER, 5),
        ]

        for mode, expected_value in modes:
            with self.subTest(mode=mode):
                callback.reset_mock()
                controller.set_mode(mode)
                callback.assert_called_once_with(
                    "operationMode", {"operationMode": expected_value}
                )

    def test_mode_name_property(self):
        """Test mode_name property returns correct names."""
        controller = OperationModeController()

        test_cases = [
            (OperationMode.AWAY, "Away"),
            (OperationMode.STANDARD, "Standard"),
            (OperationMode.SAVINGS, "Savings"),
            (OperationMode.SUPER_SAVINGS, "Super Savings"),
            (OperationMode.WEEKENDER, "Weekender"),
            (OperationMode.OTHER, "Other"),
        ]

        for mode, expected_name in test_cases:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertEqual(controller.mode_name, expected_name)

    def test_is_energy_saving_property(self):
        """Test is_energy_saving property."""
        controller = OperationModeController()

        # Energy saving modes
        energy_saving = [
            OperationMode.AWAY,
            OperationMode.SAVINGS,
            OperationMode.SUPER_SAVINGS,
        ]
        for mode in energy_saving:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertTrue(controller.is_energy_saving)

        # Non-energy saving modes
        non_energy_saving = [
            OperationMode.STANDARD,
            OperationMode.WEEKENDER,
            OperationMode.OTHER,
        ]
        for mode in non_energy_saving:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertFalse(controller.is_energy_saving)

    def test_to_dict(self):
        """Test dictionary conversion."""
        controller = OperationModeController()
        controller.operation_mode = OperationMode.SAVINGS
        result = controller.to_dict()

        expected = {
            "operation_mode": "SAVINGS",
            "operation_mode_value": 2,
            "mode_name": "Savings",
            "is_energy_saving": True,
        }

        self.assertEqual(result, expected)

    def test_repr(self):
        """Test string representation."""
        controller = OperationModeController()
        controller.operation_mode = OperationMode.AWAY
        repr_str = repr(controller)
        self.assertIn("AWAY", repr_str)
        self.assertIn("0", repr_str)


if __name__ == "__main__":
    unittest.main()

    def test_set_mode_invalid_type(self):
        """Test setting mode with invalid type."""
        controller = OperationModeController()

        with self.assertRaises(ValueError):
            controller.set_mode("AWAY")  # Should be OperationMode enum

    def test_set_mode_by_name(self):
        """Test setting mode by name."""
        callback = Mock()
        controller = OperationModeController()
        controller.set_publish_callback(callback)

        controller.set_mode_by_name("AWAY")
        callback.assert_called_with("operationMode", {"operationMode": 0})

        callback.reset_mock()
        controller.set_mode_by_name("standard")  # Case insensitive
        callback.assert_called_with("operationMode", {"operationMode": 1})

    def test_set_mode_by_name_invalid(self):
        """Test setting mode by invalid name."""
        controller = OperationModeController()

        with self.assertRaises(ValueError) as context:
            controller.set_mode_by_name("INVALID_MODE")

        self.assertIn("Unknown operation mode name", str(context.exception))

    def test_set_mode_by_value(self):
        """Test setting mode by numeric value."""
        callback = Mock()
        controller = OperationModeController()
        controller.set_publish_callback(callback)

        controller.set_mode_by_value(2)
        callback.assert_called_with("operationMode", {"operationMode": 2})

    def test_mode_name_property(self):
        """Test mode_name property returns correct names."""
        controller = OperationModeController()

        test_cases = [
            (OperationMode.AWAY, "Away"),
            (OperationMode.STANDARD, "Standard"),
            (OperationMode.SAVINGS, "Savings"),
            (OperationMode.SUPER_SAVINGS, "Super Savings"),
            (OperationMode.WEEKENDER, "Weekender"),
            (OperationMode.OTHER, "Other"),
        ]

        for mode, expected_name in test_cases:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertEqual(controller.mode_name, expected_name)

    def test_is_energy_saving_property(self):
        """Test is_energy_saving property."""
        controller = OperationModeController()

        # Energy saving modes
        energy_saving = [
            OperationMode.AWAY,
            OperationMode.SAVINGS,
            OperationMode.SUPER_SAVINGS,
        ]
        for mode in energy_saving:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertTrue(controller.is_energy_saving)

        # Non-energy saving modes
        non_energy_saving = [
            OperationMode.STANDARD,
            OperationMode.WEEKENDER,
            OperationMode.OTHER,
        ]
        for mode in non_energy_saving:
            with self.subTest(mode=mode):
                controller.operation_mode = mode
                self.assertFalse(controller.is_energy_saving)

    def test_to_dict(self):
        """Test dictionary conversion."""
        controller = OperationModeController()
        controller.operation_mode = OperationMode.SAVINGS
        result = controller.to_dict()

        expected = {
            "operation_mode": "SAVINGS",
            "operation_mode_value": 2,
            "mode_name": "Savings",
            "is_energy_saving": True,
        }

        self.assertEqual(result, expected)

    def test_repr(self):
        """Test string representation."""
        controller = OperationModeController()
        controller.operation_mode = OperationMode.AWAY
        repr_str = repr(controller)
        self.assertIn("AWAY", repr_str)
        self.assertIn("0", repr_str)


if __name__ == "__main__":
    unittest.main()
