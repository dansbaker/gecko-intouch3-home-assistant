"""Regression tests for sparse Gecko connectivity updates."""

from __future__ import annotations

import unittest

from custom_components.gecko.gecko_iot_client.helpers import connectivity


class ConnectivityTests(unittest.TestCase):
    """Verify sparse updates do not erase explicit connectivity state."""

    def test_unknown_update_preserves_last_explicit_status(self) -> None:
        gateway_status = connectivity.preserve_known_connectivity_value(
            "CONNECTED", "UNKNOWN"
        )
        vessel_status = connectivity.preserve_known_connectivity_value("RUNNING", None)

        self.assertEqual(gateway_status, "CONNECTED")
        self.assertEqual(vessel_status, "RUNNING")
        self.assertTrue(
            connectivity.is_fully_connected(
                True,
                gateway_status,
                vessel_status,
            )
        )

    def test_initial_unknown_status_remains_unknown(self) -> None:
        self.assertEqual(
            connectivity.preserve_known_connectivity_value("UNKNOWN", "UNKNOWN"),
            "UNKNOWN",
        )

    def test_explicit_disconnect_replaces_connected_status(self) -> None:
        self.assertEqual(
            connectivity.preserve_known_connectivity_value("CONNECTED", "DISCONNECTED"),
            "DISCONNECTED",
        )

    def test_transport_loss_is_not_fully_connected(self) -> None:
        self.assertFalse(connectivity.is_fully_connected(False, "CONNECTED", "RUNNING"))

    def test_gateway_or_vessel_outage_is_not_fully_connected(self) -> None:
        self.assertFalse(
            connectivity.is_fully_connected(True, "DISCONNECTED", "RUNNING")
        )
        self.assertFalse(connectivity.is_fully_connected(True, "CONNECTED", "OFFLINE"))

    def test_ready_and_running_vessels_are_fully_connected(self) -> None:
        self.assertTrue(connectivity.is_fully_connected(True, "CONNECTED", "RUNNING"))
        self.assertTrue(connectivity.is_fully_connected(True, "connected", "ready"))


if __name__ == "__main__":
    unittest.main()
