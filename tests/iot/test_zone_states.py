"""
Unit tests for zone states and serialization functionality.
"""

import unittest

from custom_components.gecko.gecko_iot_client.models.zone_types import (
    RGB,
    AbstractZone,
    FlowZone,
    LightingZone,
    TemperatureControlMode,
    TemperatureControlZone,
    ZoneType,
)


class TestAbstractZone(unittest.TestCase):
    """Test AbstractZone base functionality."""

    def test_zone_creation(self):
        """Test basic zone creation."""
        zone = FlowZone("test_1", {"speed": 50.0, "active": True})
        self.assertEqual(zone.id, "test_1")
        self.assertEqual(zone.zone_type, ZoneType.FLOW_ZONE)
        self.assertEqual(zone.speed, 50.0)
        self.assertTrue(zone.active)

    def test_to_config_serialization(self):
        """Test zone serialization to config dictionary."""
        zone = FlowZone(
            "flow_1", {"name": "Test Flow Zone", "speed": 75.5, "active": True}
        )

        config = zone.to_config()
        expected = {
            "id": "flow_1",
            "name": "Test Flow Zone",
            "active": True,
            "speed": 75.5,
        }
        self.assertEqual(config, expected)

    def test_to_state_dict_serialization(self):
        """Test zone serialization to complete state dictionary."""
        zone = FlowZone(
            "flow_1", {"name": "Test Flow Zone", "speed": 25.0, "active": False}
        )

        state_dict = zone.to_state_dict()
        self.assertEqual(state_dict["id"], "flow_1")
        self.assertEqual(state_dict["name"], "Test Flow Zone")
        self.assertEqual(state_dict["zone_type"], "flow")
        self.assertIn("config", state_dict)
        self.assertEqual(state_dict["config"]["speed"], 25.0)
        self.assertFalse(state_dict["config"]["active"])

    def test_from_state_dict_deserialization(self):
        """Test zone deserialization from state dictionary."""
        state_dict = {
            "id": "flow_2",
            "name": "Deserialized Zone",
            "zone_type": "flow",
            "config": {"active": True, "speed": 80.0},
        }

        zone = AbstractZone.from_state_dict(state_dict)
        self.assertIsInstance(zone, FlowZone)
        self.assertEqual(zone.id, "flow_2")
        self.assertEqual(zone.name, "Deserialized Zone")
        self.assertEqual(zone.zone_type, ZoneType.FLOW_ZONE)
        self.assertEqual(zone.speed, 80.0)
        self.assertTrue(zone.active)

    def test_update_from_config(self):
        """Test updating zone from configuration dictionary."""
        zone = FlowZone("flow_1", {"speed": 30.0, "active": False})

        update_config = {"speed": 90.0, "active": True, "name": "Updated Zone"}

        zone.update_from_config(update_config)
        self.assertEqual(zone.speed, 90.0)
        self.assertTrue(zone.active)
        self.assertEqual(zone.name, "Updated Zone")
        # ID should not change
        self.assertEqual(zone.id, "flow_1")

    def test_from_config_factory_method(self):
        """Test zone creation using from_config factory method."""
        config = {"name": "Factory Zone", "speed": 45.0, "active": True}

        zone = AbstractZone.from_config("factory_1", config, ZoneType.FLOW_ZONE)
        self.assertIsInstance(zone, FlowZone)
        self.assertEqual(zone.id, "factory_1")
        self.assertEqual(zone.name, "Factory Zone")
        self.assertEqual(zone.speed, 45.0)
        self.assertTrue(zone.active)


class TestFlowZone(unittest.TestCase):
    """Test FlowZone specific functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.flow_zone = FlowZone("flow_test", {"speed": 50.0, "active": True})

    def test_default_name_assignment(self):
        """Test that default name is assigned when none provided."""
        zone = FlowZone("2", {})
        self.assertEqual(zone.name, "Pump 2")

    def test_custom_name_preserved(self):
        """Test that custom name is preserved when provided."""
        zone = FlowZone("1", {"name": "Custom Pump"})
        self.assertEqual(zone.name, "Custom Pump")

    def test_get_flow_state(self):
        """Test getting flow state summary."""
        state = self.flow_zone.get_flow_state()
        expected = {"active": True, "speed": 50.0, "has_initiators": False}
        self.assertEqual(state, expected)

    def test_set_speed(self):
        """Test setting flow speed."""
        self.flow_zone.set_speed(75.0)
        self.assertEqual(self.flow_zone.speed, 75.0)
        self.assertTrue(self.flow_zone.active)  # Should default to True

    def test_set_speed_with_active_false(self):
        """Test setting flow speed with active=False."""
        self.flow_zone.set_speed(25.0, active=False)
        self.assertEqual(self.flow_zone.speed, 25.0)
        self.assertFalse(self.flow_zone.active)


class TestLightingZone(unittest.TestCase):
    """Test LightingZone specific functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.lighting_zone = LightingZone("light_test", {})

    def test_default_name_assignment(self):
        """Test that default name is assigned when none provided."""
        zone = LightingZone("3", {})
        self.assertEqual(zone.name, "Light 3")

    def test_custom_name_preserved(self):
        """Test that custom name is preserved when provided."""
        zone = LightingZone("1", {"name": "RGB Strip"})
        self.assertEqual(zone.name, "RGB Strip")

    def test_get_lighting_state_empty(self):
        """Test getting lighting state when no values set."""
        state = self.lighting_zone.get_lighting_state()
        expected = {"active": None, "color": None, "effect": None}
        self.assertEqual(state, expected)

    def test_set_color(self):
        """Test setting lighting color."""
        self.lighting_zone.set_color(255, 128, 64, 200)
        self.assertTrue(self.lighting_zone.active)
        self.assertIsNotNone(self.lighting_zone.rgbi)
        self.assertEqual(self.lighting_zone.rgbi.r, 255)
        self.assertEqual(self.lighting_zone.rgbi.g, 128)
        self.assertEqual(self.lighting_zone.rgbi.b, 64)
        self.assertEqual(self.lighting_zone.rgbi.i, 200)

    def test_set_color_without_intensity(self):
        """Test setting lighting color without intensity."""
        self.lighting_zone.set_color(100, 150, 200)
        self.assertEqual(self.lighting_zone.rgbi.r, 100)
        self.assertEqual(self.lighting_zone.rgbi.g, 150)
        self.assertEqual(self.lighting_zone.rgbi.b, 200)
        self.assertIsNone(self.lighting_zone.rgbi.i)

    def test_set_effect(self):
        """Test setting lighting effect."""
        self.lighting_zone.set_effect("rainbow")
        self.assertEqual(self.lighting_zone.effect, "rainbow")
        self.assertTrue(self.lighting_zone.active)

    def test_get_lighting_state_with_values(self):
        """Test getting lighting state with values set."""
        self.lighting_zone.set_color(255, 0, 0, 255)
        self.lighting_zone.set_effect("pulse")

        state = self.lighting_zone.get_lighting_state()
        self.assertTrue(state["active"])
        self.assertEqual(state["effect"], "pulse")
        self.assertIsNotNone(state["color"])
        self.assertEqual(state["color"]["r"], 255)
        self.assertEqual(state["color"]["g"], 0)
        self.assertEqual(state["color"]["b"], 0)
        self.assertEqual(state["color"]["i"], 255)


class TestTemperatureControlZone(unittest.TestCase):
    """Test TemperatureControlZone specific functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_zone = TemperatureControlZone(
            "temp_test",
            {
                "temperature_": 22.5,
                "set_point": 24.0,
                "min_temperature_set_point_c": 20.0,
                "max_temperature_set_point_c": 40.0,
            },
        )

    def test_default_name_assignment(self):
        """Test that default name is assigned when none provided."""
        zone = TemperatureControlZone("1", {})
        self.assertEqual(zone.name, "Water Temperature 1")

    def test_custom_name_preserved(self):
        """Test that custom name is preserved when provided."""
        zone = TemperatureControlZone("1", {"name": "Spa Temperature"})
        self.assertEqual(zone.name, "Spa Temperature")

    def test_get_temperature_state(self):
        """Test getting temperature state."""
        state = self.temp_zone.get_temperature_state()
        expected = {
            "current_temperature": 22.5,
            "target_temperature": 24.0,
            "eco_mode": None,
            "status": None,
        }
        self.assertEqual(state, expected)

    def test_set_target_temperature(self):
        """Test setting target temperature."""
        self.temp_zone.set_target_temperature(26.0)
        self.assertEqual(self.temp_zone.set_point, 26.0)

    def test_set_target_temperature_no_limits_configured(self):
        """Test that setting target temperature fails when no limits are configured."""
        zone_without_limits = TemperatureControlZone(
            "test_no_limits", {"temperature_": 22.5, "set_point": 24.0}
        )

        with self.assertRaises(ValueError) as context:
            zone_without_limits.set_target_temperature(26.0)

        self.assertIn("Temperature limits not configured", str(context.exception))

    def test_set_target_temperature_outside_range(self):
        """Test that setting target temperature fails when outside configured range."""
        with self.assertRaises(ValueError) as context:
            self.temp_zone.set_target_temperature(50.0)  # Above max of 40.0

        self.assertIn("outside configured range", str(context.exception))

    def test_eco_mode_new(self):
        """Test eco mode when no mode exists initially."""
        # Eco mode is read-only, set through state updates
        self.temp_zone.mode_ = TemperatureControlMode(eco=True)
        self.assertIsNotNone(self.temp_zone.mode_)
        self.assertTrue(self.temp_zone.mode_.eco)

    def test_eco_mode_existing(self):
        """Test eco mode when mode already exists."""
        self.temp_zone.mode_ = TemperatureControlMode(eco=False)
        # Update the eco mode directly (simulating state update)
        self.temp_zone.mode_.eco = True
        self.assertTrue(self.temp_zone.mode_.eco)

    def test_get_temperature_state_with_mode(self):
        """Test getting temperature state with eco mode set."""
        self.temp_zone.mode_ = TemperatureControlMode(eco=True)
        state = self.temp_zone.get_temperature_state()
        self.assertTrue(state["eco_mode"])


class TestRGB(unittest.TestCase):
    """Test RGB color model."""

    def test_rgb_creation(self):
        """Test RGB color creation."""
        color = RGB(r=255, g=128, b=64)
        self.assertEqual(color.r, 255)
        self.assertEqual(color.g, 128)
        self.assertEqual(color.b, 64)
        self.assertIsNone(color.i)

    def test_rgb_with_intensity(self):
        """Test RGB color creation with intensity."""
        color = RGB(r=100, g=150, b=200, i=180)
        self.assertEqual(color.r, 100)
        self.assertEqual(color.g, 150)
        self.assertEqual(color.b, 200)
        self.assertEqual(color.i, 180)

    def test_rgb_validation_bounds(self):
        """Test RGB color validation bounds."""
        with self.assertRaises(ValueError):
            RGB(r=256, g=128, b=64)  # r > 255

        with self.assertRaises(ValueError):
            RGB(r=100, g=-1, b=64)  # g < 0


if __name__ == "__main__":
    unittest.main()
