"""Flow zone models and configurations for Gecko IoT devices."""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, TypedDict

from .abstract_zone import AbstractZone, ZoneType


class SpeedConfig(TypedDict):
    """Configuration for flow zone speed settings."""

    maximum: int
    minimum: int
    stepIncrement: int


class FlowConfiguration(TypedDict):
    """Configuration dictionary for flow zones."""

    name: Optional[str]
    pumps: Optional[List[str]]
    speed: SpeedConfig


class FlowZoneCapabilities(Enum):
    """Enum for flow zone capabilities"""

    SUPPORTS_SPEED_PRESETS = "supports_speed_presets"
    SUPPORTS_SPEED_PERCENTAGE = "supports_speed_percentage"
    SUPPORTS_TURN_ON = "supports_turn_on"
    SUPPORTS_TURN_OFF = "supports_turn_off"


class FlowZoneInitiator(Enum):
    """Enum for flow zone initiators"""

    USER_DEMAND = "UD"
    CHECKFLOW = "CF"
    PURGE = "PU"
    FILTRATION = "FI"
    HEATING = "HT"
    COOLDOWN = "CD"
    HEAT_PUMP = "HTP"


PRESET_NAMES = ["Low", "Medium", "High", "Max"]


@dataclass
class FlowZonePreset:
    """Preset configuration for flow zone speeds."""

    name: str
    speed: float


class FlowZoneType(Enum):
    """Types of flow zones available in Gecko IoT devices."""

    FLOW_ZONE = "flow_zone"
    WATERFALL_ZONE = "waterfall_zone"
    BLOWER_ZONE = "blower_zone"


@dataclass
class FlowZoneTypeProperties:
    """Properties for different flow zone types."""

    format_name: callable


# Type properties mapping zone types to their characteristics
FLOW_ZONE_TYPE_PROPERTIES: Dict[FlowZoneType, FlowZoneTypeProperties] = {
    FlowZoneType.WATERFALL_ZONE: FlowZoneTypeProperties(
        format_name=lambda zone_id: "Waterfall",
    ),
    FlowZoneType.BLOWER_ZONE: FlowZoneTypeProperties(
        format_name=lambda zone_id: "Blower",
    ),
    FlowZoneType.FLOW_ZONE: FlowZoneTypeProperties(
        format_name=lambda zone_id: f"Pump {zone_id}",
    ),
}


@AbstractZone.register_zone_type(ZoneType.FLOW_ZONE)
class FlowZone(AbstractZone):
    """State representation for flow zone v1 with validation"""

    def __init__(self, zone_id: str, config: FlowConfiguration):
        """
        Initialize FlowZone with zone_id and config.

        Args:
            zone_id: Unique identifier for the flow zone
            config: Configuration dictionary with flow zone settings
        """
        # Set default name if not provided
        if "name" not in config or config["name"] is None:
            # Determine the flow zone type and get its properties
            flow_zone_type = self._determine_flow_zone_type(config)
            type_props = FLOW_ZONE_TYPE_PROPERTIES[flow_zone_type]
            config["name"] = type_props.format_name(zone_id)

        super().__init__(
            id=zone_id, zone_type=ZoneType.FLOW_ZONE, name=config["name"], config=config
        )

        # Initialize flow zone specific attributes from config
        self.active: Optional[bool] = config.get("active")
        self.speed: Optional[float] = config.get("speed")
        self.initiators_: Optional[List[FlowZoneInitiator]] = config.get("initiators_")

        # Validate speed if present
        if self.speed is not None:
            if not isinstance(self.speed, (int, float)):
                raise ValueError(
                    f"Flow speed must be a number, got {type(self.speed).__name__}: {self.speed}"
                )
            self._validate_speed(self.speed)

    @property
    def speed_config(self) -> Optional[SpeedConfig]:
        """
        Get speed configuration if it exists and is properly structured.

        Returns:
            SpeedConfig dictionary or None if not available
        """
        speed_value = self.config.get("speed")
        if isinstance(speed_value, dict):
            return speed_value  # type: ignore
        return None

    def _validate_speed(self, speed: float) -> None:
        """
        Validate speed is within acceptable range.

        Args:
            speed: Speed value to validate

        Raises:
            ValueError: If speed is outside the configured min/max range
        """
        if self.speed_config:
            if not (
                self.speed_config["minimum"] <= speed <= self.speed_config["maximum"]
            ):
                min_val = self.speed_config["minimum"]
                max_val = self.speed_config["maximum"]
                raise ValueError(
                    f"Flow speed {speed}% must be between {min_val} and {max_val}"
                )

    @property
    def initiators(self) -> Optional[List[FlowZoneInitiator]]:
        """
        Get the list of active initiators for this flow zone.

        Returns:
            List of FlowZoneInitiator enums or None
        """
        return self.initiators_

    @staticmethod
    def _determine_flow_zone_type(config: FlowConfiguration) -> FlowZoneType:
        """
        Determine the flow zone type from configuration.

        Args:
            config: Flow zone configuration dictionary

        Returns:
            FlowZoneType enum value based on configuration
        """
        if config.get("waterfalls") and len(config.get("waterfalls", [])) > 0:
            return FlowZoneType.WATERFALL_ZONE
        if config.get("blowers") and len(config.get("blowers", [])) > 0:
            return FlowZoneType.BLOWER_ZONE
        return FlowZoneType.FLOW_ZONE

    @property
    def type(self) -> FlowZoneType:
        """
        Get the type of the flow zone.

        Returns:
            FlowZoneType enum value
        """
        return self._determine_flow_zone_type(self.config)

    @property
    def capabilities(self) -> List[FlowZoneCapabilities]:
        """
        Get the capabilities of the flow zone.

        Returns:
            List of FlowZoneCapabilities enums
        """
        capabilities = [
            FlowZoneCapabilities.SUPPORTS_TURN_ON,
            FlowZoneCapabilities.SUPPORTS_TURN_OFF,
        ]

        if self.speed_config and self.speed_config["stepIncrement"] != 0:
            capabilities.append(FlowZoneCapabilities.SUPPORTS_SPEED_PRESETS)

        return capabilities

    @property
    def presets(self) -> List[FlowZonePreset]:
        """
        Get the speed presets for the flow zone, if supported.

        Returns:
            List of FlowZonePreset objects with name and speed
        """
        presets = []
        if (
            FlowZoneCapabilities.SUPPORTS_SPEED_PRESETS in self.capabilities
            and self.speed_config
        ):
            step = self.speed_config["stepIncrement"]
            min_speed = self.speed_config["minimum"]
            max_speed = self.speed_config["maximum"]
            preset_speeds = list(range(min_speed, max_speed + 1, step))
            for i, speed in enumerate(preset_speeds):
                name = PRESET_NAMES[i] if i < len(PRESET_NAMES) else f"Preset {i + 1}"
                presets.append(FlowZonePreset(name=name, speed=speed))
        return presets

    def get_flow_state(self) -> Dict[str, Any]:
        """
        Get the current flow state as a simple dictionary.

        Returns:
            Dictionary with active status, speed, and initiator information
        """
        return {
            "active": self.active,
            "speed": self.speed,
            "has_initiators": bool(self.initiators_),
        }

    def _get_runtime_state_fields(self) -> set:
        """
        Runtime state fields for flow zones.

        Returns:
            Set of field names that represent runtime state
        """
        return {"active", "speed"}

    def _get_field_mappings(self) -> Dict[str, str]:
        """
        Flow zone specific field mappings.

        Returns:
            Dictionary mapping external field names to internal field names
        """
        return {
            "isActive": "active",
            "flowSpeed": "speed",
            "pumpSpeed": "speed",
            "running": "active",
            "enabled": "active",
        }

    def set_speed(self, speed: float, active: Optional[bool] = True) -> None:
        """
        Set flow speed with validation and optional active state.

        Args:
            speed: Speed value to set (percentage)
            active: Whether to activate the zone (default: True)

        Raises:
            ValueError: If speed is outside valid range
        """
        self._validate_speed(speed)
        self.speed = speed
        if active is not None:
            self.active = active
        self._publish_desired_state({"speed": speed, "active": self.active})

    def activate(self) -> None:
        """Activate this flow zone."""
        self._publish_desired_state({"active": True})

    def deactivate(self) -> None:
        """
        Deactivate this flow zone.

        Raises:
            RuntimeError: If zone has active non-user initiators
        """
        non_user_initiators = self.initiators_ is not None and any(
            initiator != FlowZoneInitiator.USER_DEMAND.value
            for initiator in self.initiators_
        )
        if non_user_initiators:
            raise RuntimeError(
                "Cannot deactivate flow zone with active non-user initiators."
            )

        self._publish_desired_state({"active": False})
