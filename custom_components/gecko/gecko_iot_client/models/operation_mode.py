"""Operation mode (watercare) model for Gecko IoT devices."""

import logging
from enum import Enum
from typing import Any, Dict

logger = logging.getLogger(__name__)


class OperationMode(Enum):
    """Enum for operation modes (watercare modes)."""

    AWAY = 0
    STANDARD = 1
    SAVINGS = 2
    SUPER_SAVINGS = 3
    WEEKENDER = 4
    OTHER = 5  # for unknown or unsupported modes

    @classmethod
    def from_value(cls, value: Any) -> "OperationMode":
        """
        Convert a value to OperationMode enum.

        Args:
            value: The value to convert (int, str, or OperationMode)

        Returns:
            OperationMode enum value, defaults to OTHER for unknown values
        """
        if isinstance(value, cls):
            return value

        try:
            # Try to convert to int if it's a string
            if isinstance(value, str):
                value = int(value)

            # Look up the enum by value
            for mode in cls:
                if mode.value == value:
                    return mode

        except (ValueError, TypeError):
            logger.warning(
                f"Invalid operation mode value: {value}, defaulting to OTHER"
            )

        return cls.OTHER


class OperationModeStatus:
    """Data structure for operation mode (watercare) status information."""

    def __init__(self, operation_mode: OperationMode = OperationMode.OTHER):
        """
        Initialize operation mode status.

        Args:
            operation_mode: Current operation mode
        """
        self.operation_mode = operation_mode

    @classmethod
    def from_state_data(cls, state_data: Dict[str, Any]) -> "OperationModeStatus":
        """
        Create OperationModeStatus from device shadow state data.

        Args:
            state_data: The device shadow state data from AWS IoT

        Returns:
            OperationModeStatus object with extracted operation mode info
        """
        try:
            # Look for operation mode information in reported state
            reported = state_data.get("state", {}).get("reported", {})
            features = reported.get("features", {})

            # Extract operation mode
            operation_mode_value = features.get("operationMode", 5)  # Default to OTHER
            operation_mode = OperationMode.from_value(operation_mode_value)

            logger.debug(
                f"Extracted operation mode from state: {operation_mode_value} -> {operation_mode}"
            )

            return cls(operation_mode=operation_mode)

        except Exception as e:
            logger.warning(f"Error parsing operation mode from state data: {e}")
            # Return default status on error
            return cls()

    def update_from_state_data(self, state_data: Dict[str, Any]) -> bool:
        """
        Update operation mode status from state data.

        Args:
            state_data: The device shadow state data

        Returns:
            True if operation mode changed, False otherwise
        """
        try:
            # Extract new values
            reported = state_data.get("state", {}).get("reported", {})
            features = reported.get("features", {})

            new_operation_mode_value = features.get("operationMode", 5)
            new_operation_mode = OperationMode.from_value(new_operation_mode_value)

            # Check if anything changed
            changed = self.operation_mode != new_operation_mode

            if changed:
                logger.info(
                    f"Operation mode changed from {self.operation_mode} to {new_operation_mode}"
                )
                # Update values
                self.operation_mode = new_operation_mode

            return changed

        except Exception as e:
            logger.warning(f"Error updating operation mode from state data: {e}")
            return False

    @property
    def mode_name(self) -> str:
        """
        Get the human-readable name of the current operation mode.

        Returns:
            String representation of the operation mode
        """
        mode_names = {
            OperationMode.AWAY: "Away",
            OperationMode.STANDARD: "Standard",
            OperationMode.SAVINGS: "Savings",
            OperationMode.SUPER_SAVINGS: "Super Savings",
            OperationMode.WEEKENDER: "Weekender",
            OperationMode.OTHER: "Other",
        }
        return mode_names.get(self.operation_mode, "Unknown")

    @property
    def is_energy_saving(self) -> bool:
        """
        Check if the current mode is an energy-saving mode.

        Returns:
            True if mode is SAVINGS, SUPER_SAVINGS, or AWAY
        """
        return self.operation_mode in (
            OperationMode.SAVINGS,
            OperationMode.SUPER_SAVINGS,
            OperationMode.AWAY,
        )

    def __repr__(self) -> str:
        return f"OperationModeStatus(mode={self.operation_mode.name}, value={self.operation_mode.value})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "operation_mode": self.operation_mode.name,
            "operation_mode_value": self.operation_mode.value,
            "mode_name": self.mode_name,
            "is_energy_saving": self.is_energy_saving,
        }
