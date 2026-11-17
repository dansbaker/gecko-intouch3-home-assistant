"""Shareable Gecko diagnostics with an allowlist of modeled data."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.const import __version__ as HA_VERSION
from homeassistant.loader import async_get_integration
from homeassistant.util import dt as dt_util

from . import GeckoConfigEntry
from .connection_manager import GECKO_CONNECTION_MANAGER_KEY
from .gecko_iot_client.models.zone_types import ZoneType
from .gecko_iot_client.helpers.waterlab import reading_diagnostics


def _connection_diagnostics(connection) -> dict[str, Any]:
    """Expose connection health and a public client snapshot, never identifiers."""
    result = {
        "transport_connected": bool(connection.is_connected),
        "fully_connected": bool(connection.is_fully_connected),
        "update_subscribers": len(connection.update_callbacks),
    }
    if connection.gecko_client is not None:
        try:
            result["client"] = connection.gecko_client.diagnostic_snapshot()
        except Exception:  # noqa: BLE001 -- Fail closed without exposing provider errors.
            # An exception may contain tokens/URLs; neither serialize nor log it.
            result["client"] = {"status": "snapshot_unavailable"}
    return result


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, config_entry: GeckoConfigEntry
) -> dict[str, Any]:
    """Read only this entry's runtime; do not create a connection manager."""
    integration = await async_get_integration(hass, config_entry.domain)
    runtime = getattr(config_entry, "runtime_data", None)
    manager = hass.data.get(GECKO_CONNECTION_MANAGER_KEY)
    coordinators = []
    connections = {}
    for index, coordinator in enumerate(runtime.coordinators if runtime else [], 1):
        # Anonymous per-entry labels preserve relationships without exposing
        # account, vessel or monitor IDs, names or dictionary keys.
        label = f"vessel_{index}"
        coordinators.append(
            {
                "vessel": label,
                "has_initial_zones": coordinator._has_initial_zones,
                "zone_counts": {
                    kind.value: len(zones)
                    for kind, zones in coordinator.get_all_zones().items()
                    if isinstance(kind, ZoneType)
                },
                "consecutive_failures": coordinator._consecutive_failures,
                "reconnect_attempts": coordinator._reconnect_attempts,
                "waterlab": {
                    "available": coordinator.waterlab_available,
                    "polling_disabled": coordinator._waterlab_poll_disabled,
                    "reading_count": len(coordinator.waterlab_readings),
                    "readings": reading_diagnostics(coordinator.waterlab_readings),
                },
            }
        )
        if (
            manager is not None
            and (connection := manager.get_connection(coordinator.monitor_id))
            is not None
        ):
            connections[label] = _connection_diagnostics(connection)
    return {
        "report": {
            "schema_version": 1,
            "captured_at": dt_util.utcnow().isoformat(),
            "home_assistant_version": HA_VERSION,
            "integration_version": integration.version,
            "collection": "modeled_snapshot_no_raw_logs",
        },
        "config_entry": {
            "domain": config_entry.domain,
            "state": config_entry.state.value,
        },
        "coordinators": coordinators,
        "connections": connections,
        "runtime_loaded": runtime is not None,
    }
