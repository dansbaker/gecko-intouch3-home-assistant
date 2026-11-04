"""Lighting zone models for Gecko IoT devices."""

from typing import Any, Dict, Optional

from .abstract_zone import AbstractZone, ZoneType


class RGB:
    """RGB color representation with optional intensity."""

    def __init__(self, r: int, g: int, b: int, i: Optional[int] = None):
        """
        Initialize RGB color with validation.

        Args:
            r: Red component (0-255)
            g: Green component (0-255)
            b: Blue component (0-255)
            i: Optional intensity component (0-255)

        Raises:
            ValueError: If any component is outside the 0-255 range
        """
        if not (0 <= r <= 255):
            raise ValueError(f"Red component {r} must be between 0 and 255")
        if not (0 <= g <= 255):
            raise ValueError(f"Green component {g} must be between 0 and 255")
        if not (0 <= b <= 255):
            raise ValueError(f"Blue component {b} must be between 0 and 255")
        if i is not None and not (0 <= i <= 255):
            raise ValueError(f"Intensity component {i} must be between 0 and 255")

        self.r = r
        self.g = g
        self.b = b
        self.i = i

    def model_dump(self) -> Dict[str, Any]:
        """
        Convert to dictionary (replaces Pydantic's model_dump).

        Returns:
            Dictionary with r, g, b, and optionally i keys
        """
        result = {"r": self.r, "g": self.g, "b": self.b}
        if self.i is not None:
            result["i"] = self.i
        return result


@AbstractZone.register_zone_type(ZoneType.LIGHTING_ZONE)
class LightingZone(AbstractZone):
    """State representation for lighting zone v1 with validation"""

    def __init__(self, zone_id: str, config: Dict[str, Any]):
        """
        Initialize LightingZone with zone_id and config.

        Args:
            zone_id: Unique identifier for the lighting zone
            config: Configuration dictionary with lighting zone settings
        """
        # Set default name if not provided
        if "name" not in config or config["name"] is None:
            config["name"] = f"Light {zone_id}"

        super().__init__(
            id=zone_id,
            zone_type=ZoneType.LIGHTING_ZONE,
            name=config.get("name"),
            config=config,
        )

        # Initialize lighting zone specific attributes from config
        self.active: Optional[bool] = config.get("active")
        self.rgbi: Optional[RGB] = config.get("rgbi")
        self.effect: Optional[str] = config.get("effect")

        # Validate effect length if present
        if self.effect is not None and self._is_valid_effect_name(self.effect):
            self._validate_effect_name(self.effect)

    def _validate_effect_name(self, effect: str) -> None:
        """
        Validate effect name length.

        Args:
            effect: Effect name to validate

        Raises:
            ValueError: If effect name is not between 1 and 50 characters
        """
        if len(effect) < 1 or len(effect) > 50:
            raise ValueError(
                f"Effect name '{effect}' must be between 1 and 50 characters"
            )

    def _is_valid_effect_name(self, effect: str) -> bool:
        """
        Check if effect name should be validated.

        Args:
            effect: Effect name to check

        Returns:
            True if effect is a string that should be validated
        """
        return isinstance(effect, str)

    def get_lighting_state(self) -> Dict[str, Any]:
        """
        Get the current lighting state as a simple dictionary.

        Returns:
            Dictionary with active status, color, and effect information
        """
        return {
            "active": self.active,
            "color": self.rgbi.model_dump() if self.rgbi else None,
            "effect": self.effect,
        }

    def set_color(self, r: int, g: int, b: int, i: Optional[int] = None) -> None:
        """
        Set lighting color.

        Args:
            r: Red component (0-255)
            g: Green component (0-255)
            b: Blue component (0-255)
            i: Optional intensity component (0-255)

        Raises:
            ValueError: If any component is outside the 0-255 range
        """
        rgb_color = RGB(r=r, g=g, b=b, i=i)
        self.rgbi = rgb_color
        self.active = True
        self._publish_desired_state({"rgbi": rgb_color, "active": True})

    def _get_runtime_state_fields(self) -> set:
        """
        Runtime state fields for lighting zones.

        Returns:
            Set of field names that represent runtime state
        """
        return {"active", "rgbi", "effect"}

    def _get_field_mappings(self) -> Dict[str, str]:
        """
        Lighting zone specific field mappings.

        Returns:
            Dictionary mapping external field names to internal field names
        """
        return {
            "isActive": "active",
            "color": "rgbi",
            "rgb": "rgbi",
            "lightEffect": "effect",
            "lightingEffect": "effect",
            "mode": "effect",
            "running": "active",
            "enabled": "active",
            "on": "active",
        }

    def update_from_state(self, state: Dict[str, Any]) -> None:
        """
        Update lighting zone from runtime state with special handling for RGBI.

        Args:
            state: State dictionary with current values
        """
        # Handle RGBI conversion if it's a list
        if "rgbi" in state:
            rgbi_value = state["rgbi"]
            if isinstance(rgbi_value, list) and len(rgbi_value) >= 3:
                # Convert list [r, g, b, i] to RGB object
                r, g, b = rgbi_value[0], rgbi_value[1], rgbi_value[2]
                i = rgbi_value[3] if len(rgbi_value) > 3 else None
                state = state.copy()  # Don't modify original
                state["rgbi"] = RGB(r=r, g=g, b=b, i=i)

        # Call parent update method
        super().update_from_state(state)

    def set_effect(self, effect_name: str) -> None:
        """
        Set lighting effect with validation.

        Args:
            effect_name: Name of the effect to set (1-50 characters)

        Raises:
            ValueError: If effect name is not between 1 and 50 characters
        """
        self._validate_effect_name(effect_name)
        self.effect = effect_name
        self.active = True
        self._publish_desired_state({"effect": effect_name, "active": True})

    def activate(self) -> None:
        """Activate this lighting zone."""
        self._publish_desired_state({"active": True})

    def deactivate(self) -> None:
        """Deactivate this lighting zone."""
        self._publish_desired_state({"active": False})
