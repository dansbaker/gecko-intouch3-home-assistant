"""Exercise both version-selected temperature paths without replacing HA modules."""

import builtins
import runpy
from pathlib import Path
from unittest.mock import patch

import pytest
from homeassistant.components.climate import ClimateEntity
from homeassistant.const import UnitOfTemperature

from .conftest import build_zones
from custom_components.gecko.gecko_iot_client.models.zone_types import ZoneType


@pytest.mark.parametrize("native", [False, True])
def test_temperature_api_selection_and_reported_values(native):
    original = builtins.hasattr

    def has_attribute(obj, name):
        if obj is ClimateEntity and name == "native_current_temperature":
            return native
        return original(obj, name)

    # A separate namespace avoids mutating the class used by other HA tests.
    with patch("builtins.hasattr", side_effect=has_attribute):
        module = runpy.run_path(
            str(Path(__file__).parents[1] / "custom_components/gecko/climate.py"),
            run_name="custom_components.gecko._climate_api_test",
        )
    cls = module["GeckoClimate"]
    entity = cls.__new__(cls)
    entity.hass = None
    zone = build_zones(
        {"temperatureControl": {"1": {"temperature_": 32, "setPoint": 37}}}
    )[ZoneType.TEMPERATURE_CONTROL_ZONE][0]
    entity._current_zone = lambda: zone
    entity._update_from_zone()
    prefix = "_attr_native_" if native else "_attr_"
    assert getattr(entity, prefix + "temperature_unit") == UnitOfTemperature.CELSIUS
    assert getattr(entity, prefix + "current_temperature") == 32
    assert getattr(entity, prefix + "target_temperature") == 37
    zone.update_from_state({"temperature_": 33, "setPoint": 38})
    entity._update_from_zone()
    assert getattr(entity, prefix + "current_temperature") == 33
    assert getattr(entity, prefix + "target_temperature") == 38
