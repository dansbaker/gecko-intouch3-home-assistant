"""
Zone configuration parser module.

Simple parser for converting zone configurations into zone instances.
"""

import logging
from typing import Any, Dict, List

from .zone_types import (  # This imports all zone types and registers them
    AbstractZone,
    FlowZone,
    LightingZone,
    TemperatureControlZone,
    ZoneType,
)

logger = logging.getLogger(__name__)


def _extract_value_from_config(field_value: Any) -> Any:
    """
    Extract actual value from config metadata like {'minimum': 0, 'maximum': 100}.

    Args:
        field_value: Configuration value (can be dict with metadata or direct value)

    Returns:
        Extracted value or None if not found
    """
    if isinstance(field_value, dict):
        # Look for actual value keys
        for key in ["value", "currentValue", "default", "initialValue"]:
            if key in field_value:
                return field_value[key]
        # Use minimum as fallback if no value found
        if "minimum" in field_value:
            return field_value["minimum"]
        return None
    return field_value


class ZoneConfigurationParser:
    """
    Simple parser for zone configurations.

    Converts raw zone configuration data into typed zone instances
    and applies runtime state updates to existing zones.
    """

    # Zone type mapping
    ZONE_TYPES = {
        "flow": ZoneType.FLOW_ZONE,
        "lighting": ZoneType.LIGHTING_ZONE,
        "temperatureControl": ZoneType.TEMPERATURE_CONTROL_ZONE,
    }

    ZONE_TYPE_TO_CLASS = {
        ZoneType.FLOW_ZONE: FlowZone,
        ZoneType.LIGHTING_ZONE: LightingZone,
        ZoneType.TEMPERATURE_CONTROL_ZONE: TemperatureControlZone,
    }

    def parse_zones_configuration(
        self, zones_config: Dict[str, Any]
    ) -> Dict[ZoneType, List[AbstractZone]]:
        """
        Parse zones configuration into zone instances.

        Args:
            zones_config: Raw zone configuration dictionary

        Returns:
            Dictionary mapping zone types to lists of zone instances
        """
        logger.info("Parsing zones configuration")
        zones: Dict[ZoneType, List[AbstractZone]] = {}

        # Check for unknown zone types first
        for zone_type_key in zones_config.keys():
            if zone_type_key not in self.ZONE_TYPES:
                logger.warning(f"Unknown zone type: {zone_type_key}")

        for zone_type, zone_class in self.ZONE_TYPE_TO_CLASS.items():
            zone_list = []
            zone_type_config = zones_config.get(zone_type.value, {})
            logger.debug(
                f"Processing zone type: {zone_type}, found {len(zone_type_config)} zones"
            )
            for zone_id, zone_config in zone_type_config.items():
                # Skip zones with empty IDs
                if not zone_id or zone_id.strip() == "":
                    logger.warning(f"Skipping zone with empty ID in {zone_type.value}")
                    continue

                try:
                    # Process config values to extract actual values from metadata
                    processed_config = {}
                    for key, value in zone_config.items():
                        processed_value = _extract_value_from_config(value)
                        if processed_value is not None:  # Only include non-None values
                            processed_config[key] = processed_value

                    zone = zone_class(zone_id, processed_config)
                    zone_list.append(zone)
                    logger.debug(f"Created zone {zone_id} of type {zone_type}")
                except Exception as e:
                    logger.warning(
                        f"Failed to create zone {zone_id} of type {zone_type}: {e}"
                    )

            if zone_list:
                zones[zone_type] = zone_list

        total_zones = sum(len(zlist) for zlist in zones.values())
        logger.info(f"Parsed {total_zones} zones successfully")
        return zones

    def apply_state_to_zones(
        self, zones: Dict[ZoneType, List[AbstractZone]], state_data: Dict[str, Any]
    ) -> None:
        """
        Apply runtime state data to existing zone instances (not configuration).

        Args:
            zones: Dictionary of existing zone instances organized by type
            state_data: Device shadow state data containing runtime zone states
        """
        logger.debug("Applying runtime state data to zones")

        # Extract the state from the shadow structure
        state = state_data.get("state", {})
        reported_state = state.get("reported", {})
        desired_state = state.get("desired", {})

        # Look for zone runtime state data in the reported state first, then desired state
        zones_state = reported_state.get("zones", {}) if reported_state else {}

        if not zones_state and desired_state:
            logger.debug(
                "No zones runtime state found in reported state, checking desired state"
            )
            zones_state = desired_state.get("zones", {})

        if not zones_state:
            logger.debug("No zones runtime state found")
            return

        logger.debug(f"Found zones state data with {len(zones_state)} zone type(s)")

        updated_count = 0

        # Apply runtime state to each zone type
        for zone_type_key, zones_of_type_state in zones_state.items():
            zone_type = self.ZONE_TYPES.get(zone_type_key)
            if not zone_type:
                logger.warning(f"Unknown zone type in state data: {zone_type_key}")
                continue

            if zone_type not in zones:
                logger.warning(
                    f"Zone type {zone_type_key} found in state but no zones of this type exist"
                )
                continue

            # Get the zones of this type
            zone_list = zones[zone_type]
            logger.debug(
                f"Processing {len(zones_of_type_state)} zone(s) of type {zone_type_key}"
            )

            # Apply runtime state to each zone
            for zone_id, zone_runtime_state in zones_of_type_state.items():
                # Find the zone with this ID
                zone = next((z for z in zone_list if z.id == zone_id), None)
                if zone:
                    try:
                        # Use the zone's update_from_state method for proper runtime state handling
                        zone.update_from_state(zone_runtime_state)
                        logger.debug(
                            f"Updated zone {zone_id} of type {zone_type_key} with state: {zone_runtime_state}"
                        )
                        updated_count += 1
                    except Exception as e:
                        logger.warning(
                            f"Failed to update zone {zone_id} from state: {e}"
                        )
                else:
                    logger.warning(
                        f"Zone {zone_id} of type {zone_type_key} found in state but not in configured zones"
                    )

        logger.debug(f"Applied runtime state to {updated_count} zones")
