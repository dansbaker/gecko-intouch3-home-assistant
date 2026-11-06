"""Verify a built standalone client in an environment without Home Assistant."""

import json
from importlib import metadata, util
from pathlib import Path
from unittest.mock import Mock


def main() -> None:
    """Exercise installed public imports and commands without cloud access."""
    assert util.find_spec("homeassistant") is None, "Use a clean standalone environment"
    import gecko_iot_client as client
    from gecko_iot_client.models.operation_mode_controller import (
        OperationModeController,
    )
    from gecko_iot_client.models.zone_parser import ZoneConfigurationParser
    from gecko_iot_client.models.zone_types import ZoneType

    distribution = metadata.distribution("gecko-intouch3-client")
    assert distribution.version == client.__version__
    assert (
        distribution.metadata["License-Expression"] == "GPL-3.0-or-later AND Apache-2.0"
    )
    assert (
        Path(client.__file__)
        .resolve()
        .is_relative_to(Path(distribution.locate_file("")).resolve())
    )
    assert Path(client.__file__).with_name("LICENSE").is_file()
    assert Path(client.__file__).with_name("py.typed").is_file()
    assert Path(client.__file__).with_name("LICENSE-APACHE").is_file()
    assert Path(client.__file__).with_name("NOTICE").is_file()
    assert not any(
        "homeassistant" in requirement.lower()
        for requirement in distribution.requires or []
    )

    parser = ZoneConfigurationParser()
    zones = parser.parse_zones_configuration(
        {
            "flow": {
                "1": {"speed": {"minimum": 50, "maximum": 100, "stepIncrement": 50}}
            },
            "lighting": {"1": {}},
        }
    )
    parser.apply_state_to_zones(
        zones,
        {
            "state": {
                "reported": {
                    "zones": {
                        "flow": {"1": {"speed": 50, "active": True}},
                        "lighting": {"1": {"active": False}},
                    }
                }
            }
        },
    )
    # The public diagnostics API must also work outside Home Assistant.
    device = client.GeckoIotClient("PRIVATE_MONITOR", Mock())
    device._zones = zones
    snapshot = device.diagnostic_snapshot()
    assert snapshot["zones"]["flow"]["count"] == 1
    assert snapshot["zones"]["flow"]["samples"][0]["speed"] == 50
    assert "PRIVATE" not in json.dumps(snapshot, allow_nan=False)
    published = []
    pump = zones[ZoneType.FLOW_ZONE][0]
    pump.set_publish_callback(
        lambda kind, identifier, payload: published.append(payload)
    )
    assert pump.speed_config["maximum"] == 100
    pump.set_speed(100)
    assert published.pop() == {"speed": 100, "active": True}
    light = zones[ZoneType.LIGHTING_ZONE][0]
    light.set_publish_callback(
        lambda kind, identifier, payload: published.append(payload)
    )
    light.set_color(255, 0, 0, 1)
    assert published.pop() == {"rgbi": [255, 0, 0, 1], "active": True}
    modes = OperationModeController()
    modes.set_publish_callback(lambda feature, payload: published.append(payload))
    modes.set_mode_by_name("Super Savings")
    assert published.pop() == {"operationMode": 3}
    from gecko_iot_client.helpers.connectivity import preserve_known_connectivity_value
    from gecko_iot_client.helpers.lighting import rgbi_payload
    from gecko_iot_client.helpers.shadow_metrics import water_quality_kind
    from gecko_iot_client.helpers.telemetry import (
        get_flow_speed_step_values,
        redact_raw_api_payload,
        reports_binary_near_max_speed_encoding,
    )
    from gecko_iot_client.helpers.waterlab import (
        extract_readings,
        measurement_freshness,
        reading_diagnostics,
    )

    assert measurement_freshness({}) == {"measurement_time_status": "unknown"}
    assert (
        reading_diagnostics({"ph": {"source": "PRIVATE"}})[0]["source"]
        == "unrecognized"
    )

    assert (
        extract_readings(
            {"status": {"readings": {"ph": {"value": 7.4, "source": "monitor"}}}}
        )["ph"]["value"]
        == 7.4
    )
    assert water_quality_kind("zones.waterlab.ph.calibration.value") is None
    assert water_quality_kind("zones.waterlab.ph.value") == "ph"
    assert get_flow_speed_step_values(pump) == (50, 100)
    assert not reports_binary_near_max_speed_encoding(pump)
    parser.apply_state_to_zones(
        zones,
        {
            "state": {
                "reported": {"zones": {"flow": {"1": {"speed": 99, "active": True}}}}
            }
        },
    )
    assert reports_binary_near_max_speed_encoding(pump)
    assert redact_raw_api_payload({"token": "secret", "reading": 7.4}) == {
        "token": "<redacted>",
        "reading": 7.4,
    }
    assert rgbi_payload((255, 0, 0), 128) == [128, 0, 0, 1]
    assert preserve_known_connectivity_value("CONNECTED", "UNKNOWN") == "CONNECTED"
    print(
        f"Standalone client {distribution.version}: metadata, imports and command checks passed"
    )


if __name__ == "__main__":
    main()
