"""Verify a built standalone client in an environment without Home Assistant."""

from importlib import metadata, util
from pathlib import Path


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
    assert distribution.metadata["License-Expression"] == "GPL-3.0-or-later"
    assert (
        Path(client.__file__)
        .resolve()
        .is_relative_to(Path(distribution.locate_file("")).resolve())
    )
    assert Path(client.__file__).with_name("LICENSE").is_file()
    assert Path(client.__file__).with_name("py.typed").is_file()
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
    print(
        f"Standalone client {distribution.version}: metadata, imports and command checks passed"
    )


if __name__ == "__main__":
    main()
