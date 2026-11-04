"""
Unit tests for connectivity status functionality.
"""

import unittest

from custom_components.gecko.gecko_iot_client.models.connectivity import ConnectivityStatus


class TestConnectivityStatus(unittest.TestCase):
    """Test ConnectivityStatus functionality."""

    def test_default_initialization(self):
        """Test default initialization of ConnectivityStatus."""
        status = ConnectivityStatus()
        self.assertFalse(status.transport_connected)
        self.assertEqual(status.gateway_status, "UNKNOWN")
        self.assertEqual(status.vessel_status, "UNKNOWN")
        self.assertFalse(status.is_fully_connected)

    def test_custom_initialization(self):
        """Test initialization with custom values."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        self.assertTrue(status.transport_connected)
        self.assertEqual(status.gateway_status, "CONNECTED")
        self.assertEqual(status.vessel_status, "RUNNING")
        self.assertTrue(status.is_fully_connected)

    def test_from_state_data_complete(self):
        """Test creating ConnectivityStatus from complete state data."""
        state_data = {
            "state": {
                "reported": {
                    "connectivity_": {
                        "gatewayStatus": "CONNECTED",
                        "vesselStatus": "RUNNING",
                    }
                }
            }
        }

        status = ConnectivityStatus.from_state_data(
            state_data, transport_connected=True
        )
        self.assertTrue(status.transport_connected)
        self.assertEqual(status.gateway_status, "CONNECTED")
        self.assertEqual(status.vessel_status, "RUNNING")

    def test_from_state_data_missing_connectivity(self):
        """Test creating ConnectivityStatus from state data missing connectivity."""
        state_data = {"state": {"reported": {}}}

        status = ConnectivityStatus.from_state_data(
            state_data, transport_connected=False
        )
        self.assertFalse(status.transport_connected)
        self.assertEqual(status.gateway_status, "UNKNOWN")
        self.assertEqual(status.vessel_status, "UNKNOWN")

    def test_from_state_data_partial_connectivity(self):
        """Test creating ConnectivityStatus from partial connectivity data."""
        state_data = {
            "state": {
                "reported": {
                    "connectivity_": {
                        "gatewayStatus": "CONNECTED",
                    }
                }
            }
        }

        status = ConnectivityStatus.from_state_data(state_data)
        self.assertEqual(status.gateway_status, "CONNECTED")
        self.assertEqual(status.vessel_status, "UNKNOWN")

    def test_from_state_data_invalid_structure(self):
        """Test creating ConnectivityStatus from invalid state data."""
        invalid_cases = [
            {},
            {"state": {}},
            {"state": {"reported": None}},
            None,
        ]

        for invalid_data in invalid_cases:
            with self.subTest(data=invalid_data):
                status = ConnectivityStatus.from_state_data(invalid_data)
                self.assertEqual(status.gateway_status, "UNKNOWN")
                self.assertEqual(status.vessel_status, "UNKNOWN")

    def test_update_from_state_data_changed(self):
        """Test updating from state data when connectivity changes."""
        status = ConnectivityStatus()

        state_data = {
            "state": {
                "reported": {
                    "connectivity_": {
                        "gatewayStatus": "CONNECTED",
                        "vesselStatus": "RUNNING",
                    }
                }
            }
        }

        changed = status.update_from_state_data(state_data)
        self.assertTrue(changed)
        self.assertEqual(status.gateway_status, "CONNECTED")
        self.assertEqual(status.vessel_status, "RUNNING")

    def test_update_from_state_data_unchanged(self):
        """Test updating from state data when connectivity doesn't change."""
        status = ConnectivityStatus(gateway_status="CONNECTED", vessel_status="RUNNING")

        state_data = {
            "state": {
                "reported": {
                    "connectivity_": {
                        "gatewayStatus": "CONNECTED",
                        "vesselStatus": "RUNNING",
                    }
                }
            }
        }

        changed = status.update_from_state_data(state_data)
        self.assertFalse(changed)

    def test_update_from_state_data_partial_change(self):
        """Test updating when only one status changes."""
        status = ConnectivityStatus(gateway_status="CONNECTED", vessel_status="RUNNING")

        state_data = {
            "state": {
                "reported": {
                    "connectivity_": {
                        "gatewayStatus": "DISCONNECTED",
                        "vesselStatus": "RUNNING",
                    }
                }
            }
        }

        changed = status.update_from_state_data(state_data)
        self.assertTrue(changed)
        self.assertEqual(status.gateway_status, "DISCONNECTED")

    def test_update_from_state_data_error_handling(self):
        """Test error handling in update_from_state_data."""
        status = ConnectivityStatus()

        changed = status.update_from_state_data({})
        self.assertFalse(changed)

    def test_update_transport_status_changed(self):
        """Test updating transport status when it changes."""
        status = ConnectivityStatus(transport_connected=False)

        changed = status.update_transport_status(True)
        self.assertTrue(changed)
        self.assertTrue(status.transport_connected)

    def test_update_transport_status_unchanged(self):
        """Test updating transport status when it doesn't change."""
        status = ConnectivityStatus(transport_connected=True)

        changed = status.update_transport_status(True)
        self.assertFalse(changed)
        self.assertTrue(status.transport_connected)

    def test_is_fully_connected_all_conditions_met(self):
        """Test is_fully_connected when all conditions are met."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        self.assertTrue(status.is_fully_connected)

    def test_is_fully_connected_vessel_ready(self):
        """Test is_fully_connected with vessel status READY."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="READY",
        )
        self.assertTrue(status.is_fully_connected)

    def test_is_fully_connected_transport_disconnected(self):
        """Test is_fully_connected when transport is disconnected."""
        status = ConnectivityStatus(
            transport_connected=False,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        self.assertFalse(status.is_fully_connected)

    def test_is_fully_connected_gateway_disconnected(self):
        """Test is_fully_connected when gateway is disconnected."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="DISCONNECTED",
            vessel_status="RUNNING",
        )
        self.assertFalse(status.is_fully_connected)

    def test_is_fully_connected_vessel_stopped(self):
        """Test is_fully_connected when vessel is stopped."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="STOPPED",
        )
        self.assertFalse(status.is_fully_connected)

    def test_repr(self):
        """Test string representation."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        repr_str = repr(status)
        self.assertIn("transport=True", repr_str)
        self.assertIn("gateway=CONNECTED", repr_str)
        self.assertIn("vessel=RUNNING", repr_str)

    def test_to_dict(self):
        """Test dictionary conversion."""
        status = ConnectivityStatus(
            transport_connected=True,
            gateway_status="CONNECTED",
            vessel_status="RUNNING",
        )
        result = status.to_dict()

        expected = {
            "transport_connected": True,
            "gateway_status": "CONNECTED",
            "vessel_status": "RUNNING",
            "is_fully_connected": True,
        }

        self.assertEqual(result, expected)

    def test_to_dict_not_fully_connected(self):
        """Test dictionary conversion when not fully connected."""
        status = ConnectivityStatus()
        result = status.to_dict()

        self.assertFalse(result["is_fully_connected"])
        self.assertFalse(result["transport_connected"])


if __name__ == "__main__":
    unittest.main()
