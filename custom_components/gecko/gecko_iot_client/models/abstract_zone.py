import logging
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class ZoneType(Enum):
    """Enumeration of available zone types in Gecko IoT devices."""

    FLOW_ZONE = "flow"
    TEMPERATURE_CONTROL_ZONE = "temperatureControl"
    LIGHTING_ZONE = "lighting"


class AbstractZone:
    """Base zone class with change callback functionality"""

    # Callback function for publishing desired state updates
    _publish_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None

    def __init__(
        self, id: str, zone_type: ZoneType, config: Any, name: Optional[str] = None
    ):
        """
        Initialize zone with required fields.

        Args:
            id: Unique identifier for the zone
            zone_type: Type of zone (flow, temperature control, or lighting)
            config: Configuration dictionary for the zone
            name: Optional human-readable name for the zone
        """
        self.id = id
        self.name = name
        self.zone_type = zone_type
        self.config = config

    def set_publish_callback(
        self, callback: Callable[[str, str, Dict[str, Any]], None]
    ) -> None:
        """
        Set the callback function for publishing desired state updates.

        Args:
            callback: Function that takes (zone_type, zone_id, updates) and handles publishing
        """
        self._publish_callback = callback

    def _publish_desired_state(self, updates: Dict[str, Any]) -> None:
        """
        Publish desired state updates via callback.

        Args:
            updates: Dictionary of state changes to publish
        """
        if self._publish_callback:
            try:
                # Call the callback with zone type, zone id, and updates
                self._publish_callback(self.zone_type.value, self.id, updates)
            except Exception as e:
                logger.error(f"Failed to publish desired state for zone {self.id}: {e}")
        else:
            logger.warning(
                f"No publish callback set for zone {self.id} - cannot publish desired state"
            )

    # Class registry for zone types
    @classmethod
    def _get_zone_registry(cls) -> Dict[ZoneType, type["AbstractZone"]]:
        """
        Get the zone registry, creating it if it doesn't exist.

        Returns:
            Dictionary mapping zone types to their implementation classes
        """
        if "_registry" not in cls.__dict__:
            cls._registry: Dict[ZoneType, type["AbstractZone"]] = {}
        return cls._registry

    @classmethod
    def register_zone_type(
        cls, zone_type: ZoneType
    ) -> Callable[[type["AbstractZone"]], type["AbstractZone"]]:
        """
        Decorator to register a zone class with its type.

        Args:
            zone_type: The zone type to register

        Returns:
            Decorator function that registers the zone class
        """

        def decorator(zone_class: type["AbstractZone"]) -> type["AbstractZone"]:
            registry = cls._get_zone_registry()
            registry[zone_type] = zone_class
            zone_class.ZONE_TYPE = zone_type  # type: ignore
            return zone_class

        return decorator

    @classmethod
    def from_config(
        cls, zone_id: str, config: Dict[str, Any], zone_type: ZoneType
    ) -> "AbstractZone":
        """
        Create a zone instance from configuration data.

        Args:
            zone_id: Unique identifier for the zone
            config: Configuration dictionary
            zone_type: Type of zone to create

        Returns:
            An instance of the appropriate zone class
        """
        registry = cls._get_zone_registry()
        zone_class = registry.get(zone_type)
        if not zone_class:
            raise ValueError(f"No zone class registered for type {zone_type}")

        # Create instance with zone_id and config (new signature)
        return zone_class(zone_id, config)

    @classmethod
    def from_state_dict(cls, state_dict: Dict[str, Any]) -> "AbstractZone":
        """
        Deserialize a zone from a complete state dictionary.

        Args:
            state_dict: Dictionary with zone state and metadata

        Returns:
            An instance of the appropriate zone class
        """
        zone_type_str = state_dict.get("zone_type")
        if not zone_type_str:
            raise ValueError("Missing zone_type in state dictionary")

        # Convert string back to enum
        zone_type = ZoneType(zone_type_str)
        zone_id = state_dict.get("id")
        if not zone_id:
            raise ValueError("Missing zone id in state dictionary")
        zone_config = state_dict.get("config", {})

        # Add name from state if present
        if "name" in state_dict:
            zone_config["name"] = state_dict["name"]

        return cls.from_config(zone_id, zone_config, zone_type)

    def update_from_config(self, config: Dict[str, Any]) -> None:
        """
        Update zone from configuration data (structure, limits, capabilities).

        Only instance attributes (set in __init__) are updatable. Class-level defaults
        and properties are not matched. Subclasses must assign all updatable fields
        as instance attributes in their __init__.

        Args:
            config: Configuration dictionary with zone setup values
        """
        for field_name, field_value in config.items():
            if field_name in self.__dict__ and not field_name.startswith("_"):
                # Skip zone_type and id as they shouldn't change
                if field_name not in ["zone_type", "id"]:
                    setattr(self, field_name, field_value)

    def update_from_state(self, state: Dict[str, Any]) -> None:
        """
        Update zone from runtime state data.

        Only instance attributes (set in __init__) are updatable. Class-level defaults
        and properties are not matched. Subclasses must assign all updatable fields
        as instance attributes in their __init__.

        Args:
            state: State dictionary with current values
        """
        # Get field mappings from subclass implementation
        field_mappings = self._get_field_mappings()

        for field_name, field_value in state.items():
            # Check if there's a mapping for this field
            mapped_field = field_mappings.get(field_name, field_name)

            if mapped_field in self.__dict__ and not mapped_field.startswith("_"):
                setattr(self, mapped_field, field_value)

    def _get_runtime_state_fields(self) -> set:
        """
        Get the set of fields that represent runtime state.

        Should be overridden by subclasses to specify which fields are runtime state.

        Returns:
            Set of field names that represent runtime state
        """
        return set()

    def _get_field_mappings(self) -> Dict[str, str]:
        """
        Get field name mappings for state updates.

        Should be overridden by subclasses to map external field names to internal ones.

        Returns:
            Dictionary mapping external field names to internal field names
        """
        return {}

    def to_config(self) -> Dict[str, Any]:
        """
        Serialize zone to configuration dictionary.

        Returns:
            Dictionary with zone configuration
        """
        config = {"id": self.id, "name": self.name}

        # Add runtime state fields
        runtime_fields = self._get_runtime_state_fields()
        for field in runtime_fields:
            if field in self.__dict__:
                config[field] = self.__dict__[field]

        return config

    def to_state_dict(self) -> Dict[str, Any]:
        """
        Serialize zone to complete state dictionary.

        Returns:
            Dictionary with zone state and metadata
        """
        config = {}
        runtime_fields = self._get_runtime_state_fields()
        for field in runtime_fields:
            if field in self.__dict__:
                config[field] = self.__dict__[field]

        return {
            "id": self.id,
            "name": self.name,
            "zone_type": self.zone_type.value,
            "config": config,
        }


# Example usage and utility functions
def create_zone_logger(zone_name: str) -> Callable[[str, Any, Any], None]:
    """
    Create a logging callback for zone changes.

    Args:
        zone_name: Name of the zone for logging

    Returns:
        Callback function that logs attribute changes
    """

    def log_change(attribute: str, old_value: Any, new_value: Any) -> None:
        print(f"[{zone_name}] {attribute} changed: {old_value} -> {new_value}")

    return log_change


def create_validation_callback(
    attribute: str,
    validator: Callable[[Any], bool],
    error_message: str = "Invalid value",
) -> Callable[[str, Any, Any], None]:
    """
    Create a validation callback for specific attributes.

    Args:
        attribute: Name of the attribute to validate
        validator: Function that returns True if value is valid
        error_message: Message to display on validation failure

    Returns:
        Callback function that validates attribute changes
    """

    def validate_change(attr: str, old_value: Any, new_value: Any) -> None:
        if attr == attribute and new_value is not None:
            if not validator(new_value):
                print(f"Warning: {error_message} for {attr}: {new_value}")

    return validate_change
