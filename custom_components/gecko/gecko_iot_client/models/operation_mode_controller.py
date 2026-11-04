"""Operation mode controller for Gecko IoT devices - handles read/write operations."""

import logging
from typing import Any, Callable, Dict, Optional

from .operation_mode import OperationMode

logger = logging.getLogger(__name__)


class OperationModeController:
    """
    Controller for operation mode (watercare mode) with read/write capabilities.

    Similar to zone classes, this handles both state parsing and control commands
    for the operation mode functionality.
    """

    def __init__(self):
        """Initialize operation mode controller with default values."""
        self.operation_mode: OperationMode = OperationMode.OTHER
        self._publish_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def set_publish_callback(
        self, callback: Callable[[str, Dict[str, Any]], None]
    ) -> None:
        """
        Set the callback function for publishing desired state updates.

        Args:
            callback: Function that takes (feature_name, updates) and handles publishing
        """
        self._publish_callback = callback

    def _publish_desired_state(self, updates: Dict[str, Any]) -> None:
        """
        Publish desired state updates via callback.

        Args:
            updates: Dictionary of state changes to publish
        """
        if self._publish_callback:
            try:
                # Call the callback with feature name and updates
                self._publish_callback("operationMode", updates)
            except Exception as e:
                self._logger.error(
                    f"Failed to publish desired state for operation mode: {e}"
                )
        else:
            self._logger.error(
                "No publish callback set for operation mode - cannot publish desired state"
            )

    @classmethod
    def from_state_data(cls, state_data: Dict[str, Any]) -> "OperationModeController":
        """
        Create OperationModeController from device shadow state data.

        Args:
            state_data: The device shadow state data from AWS IoT

        Returns:
            OperationModeController object with extracted operation mode info
        """
        controller = cls()
        controller.update_from_state_data(state_data)
        return controller

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
                self._logger.info(
                    f"Operation mode changed from {self.operation_mode} to {new_operation_mode}"
                )
                # Update values
                self.operation_mode = new_operation_mode

            return changed

        except Exception as e:
            self._logger.warning(f"Error updating operation mode from state data: {e}")
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

    def set_mode(self, mode: OperationMode) -> None:
        """
        Set the operation mode.

        Args:
            mode: The operation mode to set

        Raises:
            ValueError: If mode is not an OperationMode enum
        """
        if not isinstance(mode, OperationMode):
            raise ValueError(f"Mode must be an OperationMode enum, got {type(mode)}")

        self._logger.info(f"Setting operation mode to: {mode.name} ({mode.value})")
        self._publish_desired_state({"operationMode": mode.value})

    def set_mode_by_name(self, mode_name: str) -> None:
        """
        Set the operation mode by name.

        Args:
            mode_name: String name of the mode (case-insensitive)

        Raises:
            ValueError: If mode name is not recognized
        """
        mode_name_upper = mode_name.upper()

        # Map common names to enum values
        name_mapping = {
            "AWAY": OperationMode.AWAY,
            "STANDARD": OperationMode.STANDARD,
            "SAVINGS": OperationMode.SAVINGS,
            "SUPER_SAVINGS": OperationMode.SUPER_SAVINGS,
            "SUPERSAVINGS": OperationMode.SUPER_SAVINGS,
            "WEEKENDER": OperationMode.WEEKENDER,
            "OTHER": OperationMode.OTHER,
        }

        if mode_name_upper in name_mapping:
            self.set_mode(name_mapping[mode_name_upper])
        else:
            raise ValueError(
                f"Unknown operation mode name: {mode_name}. Valid options: {list(name_mapping.keys())}"
            )

    def set_mode_by_value(self, mode_value: int) -> None:
        """
        Set the operation mode by numeric value.

        Args:
            mode_value: Numeric value of the mode (0-5)
        """
        mode = OperationMode.from_value(mode_value)
        self.set_mode(mode)

    def __repr__(self) -> str:
        return f"OperationModeController(mode={self.operation_mode.name}, value={self.operation_mode.value})"

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary with operation mode information
        """
        return {
            "operation_mode": self.operation_mode.name,
            "operation_mode_value": self.operation_mode.value,
            "mode_name": self.mode_name,
            "is_energy_saving": self.is_energy_saving,
        }
