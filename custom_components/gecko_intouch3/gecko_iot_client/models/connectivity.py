"""Connectivity status model for Gecko IoT devices."""

from typing import Any, Dict


class ConnectivityStatus:
    """Data structure for connectivity status information."""

    def __init__(
        self,
        transport_connected: bool = False,
        gateway_status: str = "UNKNOWN",
        vessel_status: str = "UNKNOWN",
    ):
        self.transport_connected = transport_connected
        self.gateway_status = gateway_status
        self.vessel_status = vessel_status

    @classmethod
    def from_state_data(
        cls, state_data: Dict[str, Any], transport_connected: bool = False
    ) -> "ConnectivityStatus":
        """
        Create ConnectivityStatus from device shadow state data.

        Args:
            state_data: The device shadow state data from AWS IoT
            transport_connected: Current transport connection status

        Returns:
            ConnectivityStatus object with extracted connectivity info
        """
        try:
            # Look for connectivity information in reported state
            reported = state_data.get("state", {}).get("reported", {})
            connectivity = reported.get("connectivity_", {})

            # Extract connectivity status
            gateway_status = connectivity.get("gatewayStatus", "UNKNOWN")
            vessel_status = connectivity.get("vesselStatus", "UNKNOWN")

            return cls(
                transport_connected=transport_connected,
                gateway_status=gateway_status,
                vessel_status=vessel_status,
            )

        except Exception:
            # Return default status on error
            return cls(transport_connected=transport_connected)

    def update_from_state_data(self, state_data: Dict[str, Any]) -> bool:
        """
        Update connectivity status from state data.

        Args:
            state_data: The device shadow state data

        Returns:
            True if any connectivity aspect changed, False otherwise
        """
        try:
            # Extract new values
            reported = state_data.get("state", {}).get("reported", {})
            connectivity = reported.get("connectivity_", {})

            new_gateway = connectivity.get("gatewayStatus", "UNKNOWN")
            new_vessel = connectivity.get("vesselStatus", "UNKNOWN")

            # Check if anything changed
            changed = (
                self.gateway_status != new_gateway or self.vessel_status != new_vessel
            )

            # Update values
            self.gateway_status = new_gateway
            self.vessel_status = new_vessel

            return changed

        except Exception:
            return False

    def update_transport_status(self, connected: bool) -> bool:
        """
        Update transport connection status.

        Args:
            connected: New transport connection status

        Returns:
            True if transport status changed, False otherwise
        """
        changed = self.transport_connected != connected
        self.transport_connected = connected
        return changed

    @property
    def is_fully_connected(self) -> bool:
        """
        Check if the device is fully connected.

        Returns:
            True if transport is connected and both gateway and vessel are in good state
        """
        return (
            self.transport_connected
            and self.gateway_status == "CONNECTED"
            and self.vessel_status in ("RUNNING", "READY")
        )

    def __repr__(self) -> str:
        return (
            f"ConnectivityStatus(transport={self.transport_connected}, "
            f"gateway={self.gateway_status}, vessel={self.vessel_status})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "transport_connected": self.transport_connected,
            "gateway_status": self.gateway_status,
            "vessel_status": self.vessel_status,
            "is_fully_connected": self.is_fully_connected,
        }
