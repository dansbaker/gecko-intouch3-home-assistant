"""Unconfirmed desired state and failed commands must not become device state."""
from unittest.mock import Mock

import pytest

from custom_components.gecko.gecko_iot_client.models.zone_parser import ZoneConfigurationParser
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType


@pytest.fixture
def parsed_zones():
    parser = ZoneConfigurationParser()
    zones = parser.parse_zones_configuration({
        "lighting": {"1": {}},
        "flow": {"1": {"speed": {"minimum": 50, "maximum": 100, "stepIncrement": 50}}},
        "temperatureControl": {"1": {"minTemperatureSetPointC": 10, "maxTemperatureSetPointC": 40}},
    })
    parser.apply_state_to_zones(zones, {"state": {"reported": {"zones": {
        "lighting": {"1": {"active": False}},
        "flow": {"1": {"active": False, "speed": 50}},
        "temperatureControl": {"1": {"setPoint": 30}},
    }}}})
    return parser, zones


@pytest.mark.parametrize("reported", [None, {}, {"connectivity_": {}}])
def test_desired_only_updates_do_not_change_any_reported_zone(parsed_zones, reported):
    parser, zones = parsed_zones
    pump = zones[ZoneType.FLOW_ZONE][0]
    before_sequence = pump.report_sequence
    state = {"desired": {"zones": {
        "lighting": {"1": {"active": True}},
        "flow": {"1": {"active": True, "speed": 100}},
        "temperatureControl": {"1": {"setPoint": 37}},
    }}}
    if reported is not None:
        state["reported"] = reported
    parser.apply_state_to_zones(zones, {"state": state})
    assert zones[ZoneType.LIGHTING_ZONE][0].active is False
    assert pump.active is False
    assert pump.speed == 50
    assert pump.reported_active is False
    assert pump.report_sequence == before_sequence
    assert zones[ZoneType.TEMPERATURE_CONTROL_ZONE][0].target_temperature == 30


def test_reported_off_wins_and_later_reported_on_still_works(parsed_zones):
    parser, zones = parsed_zones
    light = zones[ZoneType.LIGHTING_ZONE][0]
    parser.apply_state_to_zones(zones, {"state": {
        "reported": {"zones": {"lighting": {"1": {"active": False}}}},
        "desired": {"zones": {"lighting": {"1": {"active": True}}}},
    }})
    assert light.active is False
    parser.apply_state_to_zones(zones, {"state": {"reported": {"zones": {"lighting": {"1": {"active": True}}}}}})
    assert light.active is True


@pytest.mark.parametrize("kind", ["temperature", "pump"])
@pytest.mark.parametrize("error", [ConnectionError, TimeoutError])
def test_failed_command_keeps_previous_model_state(parsed_zones, kind, error):
    _, zones = parsed_zones
    if kind == "temperature":
        zone = zones[ZoneType.TEMPERATURE_CONTROL_ZONE][0]
        command = lambda: zone.set_target_temperature(37)
    else:
        zone = zones[ZoneType.FLOW_ZONE][0]
        command = lambda: zone.set_speed(100)
    before = zone.to_config()
    zone.set_publish_callback(Mock(side_effect=error("not delivered")))
    with pytest.raises(error):
        command()
    assert zone.to_config() == before


@pytest.mark.parametrize("kind", ["temperature", "pump"])
def test_successful_command_publishes_then_updates_model(parsed_zones, kind):
    _, zones = parsed_zones
    if kind == "temperature":
        zone = zones[ZoneType.TEMPERATURE_CONTROL_ZONE][0]
        command = lambda: zone.set_target_temperature(37)
        expected = {"setPoint": 37}
    else:
        zone = zones[ZoneType.FLOW_ZONE][0]
        command = lambda: zone.set_speed(100, active=None)
        expected = {"speed": 100, "active": False}
    before = zone.to_config()
    def publish(zone_type, identifier, payload):
        assert zone.to_config() == before
        assert payload == expected
    zone.set_publish_callback(publish)
    command()
    if kind == "temperature":
        assert zone.target_temperature == 37
    else:
        assert zone.speed == 100
        assert zone.active is False
