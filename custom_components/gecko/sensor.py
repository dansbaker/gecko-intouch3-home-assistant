"""Sensor entities for Gecko telemetry."""

from __future__ import annotations

import hashlib
import logging
import math
from typing import Any, ClassVar

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import GeckoVesselCoordinator
from .entity import GeckoEntityAvailabilityMixin, GeckoZoneEntityMixin
from .gecko_iot_client.helpers.shadow_metrics import (
    MAX_EXTENSION_METRICS,
    extract_extension_metrics,
    humanize_shadow_path,
    is_calibration_path,
    water_quality_kind,
)
from .gecko_iot_client.helpers.telemetry import (
    FLOW_SPEED_MODE_OPTIONS,
    derive_flow_speed_mode,
    get_flow_initiators,
    get_flow_manual_demand_reason,
    get_flow_runtime_state,
    get_flow_speed_step_values,
    get_supported_flow_speed_modes,
    get_temperature_flow_status,
    is_manual_flow_demand,
)
from .gecko_iot_client.models.flow_zone import FlowZone
from .gecko_iot_client.models.temperature_control_zone import (
    TemperatureControlZone,
    TemperatureControlZoneStatus,
)
from .gecko_iot_client.models.zone_types import ZoneType

# Explicit platform concurrency: read-only coordinator push updates.
PARALLEL_UPDATES = 0

_LOGGER = logging.getLogger(__name__)

TEMPERATURE_STATUS_OPTIONS: tuple[str, ...] = tuple(
    status.name for status in TemperatureControlZoneStatus
)

DEVICE_TELEMETRY_SENSOR_DESCRIPTIONS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="rf_signal_strength",
        translation_key="rf_signal_strength",
    ),
    SensorEntityDescription(
        key="rf_channel",
        translation_key="rf_channel",
    ),
    SensorEntityDescription(
        key="pack_configuration",
        translation_key="pack_configuration",
    ),
    SensorEntityDescription(
        key="home_firmware_version",
        translation_key="home_firmware_version",
    ),
    SensorEntityDescription(
        key="home_serial_number",
        translation_key="home_serial_number",
    ),
    SensorEntityDescription(
        key="spa_firmware_version",
        translation_key="spa_firmware_version",
    ),
    SensorEntityDescription(
        key="spa_serial_number",
        translation_key="spa_serial_number",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Gecko sensor entities from a config entry."""
    runtime_data = getattr(config_entry, "runtime_data", None)
    if not runtime_data or not runtime_data.coordinators:
        _LOGGER.error(
            "No coordinators found in runtime_data for config entry %s",
            config_entry.entry_id,
        )
        return

    added_temperature_zone_ids: dict[str, set[str]] = {}
    added_flow_zone_ids: dict[str, set[str]] = {}

    @callback
    def discover_new_sensor_entities(coordinator: GeckoVesselCoordinator) -> None:
        """Discover telemetry sensors for temperature and flow zones."""
        vessel_key = f"{coordinator.entry_id}_{coordinator.vessel_id}"
        added_temperature_zone_ids.setdefault(vessel_key, set())
        added_flow_zone_ids.setdefault(vessel_key, set())

        new_entities: list[SensorEntity] = []

        for zone in coordinator.get_zones_by_type(ZoneType.TEMPERATURE_CONTROL_ZONE):
            zone_id = str(zone.id)
            if zone_id in added_temperature_zone_ids[vessel_key]:
                continue

            if not isinstance(zone, TemperatureControlZone):
                continue

            new_entities.extend(
                (
                    GeckoTemperatureStatusSensor(coordinator, zone),
                    GeckoTemperatureFlowStatusSensor(coordinator, zone),
                    GeckoSpaTemperatureSensor(coordinator, zone, "current"),
                    GeckoSpaTemperatureSensor(coordinator, zone, "target"),
                )
            )
            added_temperature_zone_ids[vessel_key].add(zone_id)

        for zone in coordinator.get_zones_by_type(ZoneType.FLOW_ZONE):
            zone_id = str(zone.id)
            if zone_id in added_flow_zone_ids[vessel_key]:
                continue

            if not isinstance(zone, FlowZone):
                continue

            new_entities.append(GeckoFlowSpeedModeSensor(coordinator, zone))
            added_flow_zone_ids[vessel_key].add(zone_id)

        if new_entities:
            async_add_entities(new_entities)

    for coordinator in runtime_data.coordinators:
        async_add_entities(
            [
                *(
                    GeckoDeviceTelemetrySensor(coordinator, description)
                    for description in DEVICE_TELEMETRY_SENSOR_DESCRIPTIONS
                ),
                GeckoRawApiSensor(coordinator),
            ]
        )
        discover_new_sensor_entities(coordinator)
        coordinator.register_zone_update_callback(
            lambda coord=coordinator: discover_new_sensor_entities(coord)
        )
        discovered_waterlab = set()

        @callback
        def discover_waterlab(coord=coordinator, added=discovered_waterlab):
            keys = set(coord.waterlab_readings) - added
            if keys:
                async_add_entities(
                    [GeckoWaterlabSensor(coord, key) for key in sorted(keys)]
                )
                added.update(keys)

        discover_waterlab()
        coordinator.register_zone_update_callback(discover_waterlab)
        discovered_paths = set()

        @callback
        def discover_extensions(coord=coordinator, added=discovered_paths):
            metrics = extract_extension_metrics(coord.get_spa_state())
            new_entities = []
            for path in metrics:
                if path not in added and len(added) < MAX_EXTENSION_METRICS:
                    new_entities.append(GeckoShadowMetricSensor(coord, path))
                    added.add(path)
            if new_entities:
                async_add_entities(new_entities)

        discover_extensions()
        coordinator.register_zone_update_callback(discover_extensions)


class GeckoDeviceTelemetrySensor(
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    SensorEntity,
):
    """Expose RF and EN/CO metadata from the raw Gecko shadow."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: GeckoVesselCoordinator,
        description: SensorEntityDescription,
    ) -> None:
        """Initialize a device telemetry sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_{description.key}"
        )
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))},
        )
        self._attr_available = False
        self._update_from_coordinator()

    def _update_from_coordinator(self) -> None:
        """Update this sensor from retained device telemetry."""
        self._attr_native_value = self.coordinator.get_device_telemetry().get(
            self.entity_description.key
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated shadow data."""
        self._update_from_coordinator()
        self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, str | tuple[str, ...]]:
        """Show which raw API field supplied the telemetry value."""
        attributes: dict[str, str | tuple[str, ...]] = {}
        source = self.coordinator.get_device_telemetry_source(
            self.entity_description.key
        )
        if source:
            attributes["source_field"] = source
        elif candidate_paths := (
            self.coordinator.get_device_metadata_candidate_paths()
        ):
            attributes["candidate_fields"] = candidate_paths
        return attributes


class GeckoRawApiSensor(
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    SensorEntity,
):
    """Expose credential-redacted raw API payloads for opt-in debugging."""

    _attr_has_entity_name = True
    _attr_translation_key = "raw_api_data"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ("captured", "empty")
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: GeckoVesselCoordinator) -> None:
        """Initialize the raw API diagnostic sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_raw_api_data"
        )
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))},
        )
        self._attr_available = False
        self._update_from_coordinator()

    def _update_from_coordinator(self) -> None:
        """Update the diagnostic state from captured API payloads."""
        self._attr_native_value = (
            "captured" if self.coordinator.get_raw_api_payloads() else "empty"
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the latest redacted payload grouped by source."""
        return {"payloads": self.coordinator.get_raw_api_payloads()}

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle newly captured API data."""
        self._update_from_coordinator()
        self.async_write_ha_state()


class GeckoTemperatureStatusSensor(
    GeckoZoneEntityMixin,
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    SensorEntity,
):
    """Expose the full Gecko temperature-control status enum."""

    _zone_type = ZoneType.TEMPERATURE_CONTROL_ZONE
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = TEMPERATURE_STATUS_OPTIONS

    def __init__(
        self,
        coordinator: GeckoVesselCoordinator,
        zone: TemperatureControlZone,
    ) -> None:
        """Initialize the temperature status sensor."""
        super().__init__(coordinator)
        self._zone = zone
        self._attr_unique_id = f"{coordinator.entry_id}_{coordinator.vessel_id}_temperature_status_{zone.id}"
        self._attr_translation_key = "temperature_status"
        self._attr_translation_placeholders = {"zone_name": zone.name}
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))},
        )
        self._attr_available = False
        self._update_from_zone()

    def _update_from_zone(self) -> None:
        """Update sensor state from the Gecko temperature zone."""
        if self._current_zone() is None:
            return
        self._attr_native_value = self._zone.status.name if self._zone.status else None

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Return additional temperature telemetry."""
        if self._current_zone() is None:
            return {}
        return {
            "status_code": self._zone.status.value if self._zone.status else None,
            "eco_mode": self._zone.mode.eco if self._zone.mode else None,
            "current_temperature": self._zone.temperature,
            "target_temperature": self._zone.target_temperature,
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_from_zone()
        self.async_write_ha_state()


class GeckoTemperatureFlowStatusSensor(
    GeckoZoneEntityMixin,
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    SensorEntity,
):
    """Expose the raw Gecko flow status for a temperature-control zone."""

    _zone_type = ZoneType.TEMPERATURE_CONTROL_ZONE
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ("ok", "flow_check", "other")
    _attr_translation_key = "flow_status"
    _CODE_TO_STATE: ClassVar[dict[str, str]] = {"OK": "ok", "IP": "flow_check"}

    def __init__(
        self,
        coordinator: GeckoVesselCoordinator,
        zone: TemperatureControlZone,
    ) -> None:
        """Initialize a temperature-zone flow status sensor."""
        super().__init__(coordinator)
        self._zone = zone
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_flow_status_{zone.id}"
        )
        self._attr_translation_placeholders = {"zone_name": zone.name}
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))},
        )
        self._attr_available = False
        self._update_from_coordinator()

    def _update_from_coordinator(self) -> None:
        """Update the raw flow status from the latest shadow."""
        if self._current_zone() is None:
            return
        raw_code = get_temperature_flow_status(
            self._zone,
            self.coordinator.get_spa_state(),
        )
        self._raw_code = raw_code
        self._attr_native_value = (
            None
            if raw_code is None
            else self._CODE_TO_STATE.get(str(raw_code).strip().upper(), "other")
        )

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the raw shadow field used for this zone."""
        if self._current_zone() is None:
            return {}
        return {
            "raw_code": self._raw_code,
            "source_field": (
                "MQTT shadow: state.reported.zones.temperatureControl."
                f"{self._zone.id}.flo_"
            ),
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated flow status data."""
        self._update_from_coordinator()
        self.async_write_ha_state()


class GeckoFlowSpeedModeSensor(
    GeckoZoneEntityMixin,
    GeckoEntityAvailabilityMixin,
    CoordinatorEntity[GeckoVesselCoordinator],
    SensorEntity,
):
    """Expose the derived Gecko flow speed mode."""

    _zone_type = ZoneType.FLOW_ZONE
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = FLOW_SPEED_MODE_OPTIONS

    def __init__(
        self,
        coordinator: GeckoVesselCoordinator,
        zone: FlowZone,
    ) -> None:
        """Initialize the flow speed mode sensor."""
        super().__init__(coordinator)
        self._zone = zone
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_flow_speed_mode_{zone.id}"
        )
        self._attr_translation_key = "speed_mode"
        self._attr_translation_placeholders = {"zone_name": zone.name}
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))},
        )
        self._attr_available = False
        self._update_from_zone()

    def _update_from_zone(self) -> None:
        """Update sensor state from the Gecko flow zone."""
        if self._current_zone() is None:
            return
        self._attr_native_value = derive_flow_speed_mode(self._zone)

    @property
    def extra_state_attributes(self) -> dict[str, object]:
        """Return additional flow telemetry."""
        if self._current_zone() is None:
            return {}
        spa_state = self.coordinator.get_spa_state()
        temperature_zones = self.coordinator.get_zones_by_type(
            ZoneType.TEMPERATURE_CONTROL_ZONE
        )
        return {
            "active": self._zone.active,
            "raw_speed": self._zone.speed,
            "zone_type": self._zone.type.value,
            "manual_demand": is_manual_flow_demand(
                self._zone,
                spa_state,
                temperature_zones,
            ),
            "manual_demand_reason": get_flow_manual_demand_reason(
                self._zone,
                spa_state,
                temperature_zones,
            ),
            "initiators": sorted(get_flow_initiators(self._zone, spa_state)),
            "raw_zone_state": get_flow_runtime_state(self._zone, spa_state),
            "speed_steps": list(get_flow_speed_step_values(self._zone)),
            "supported_speed_modes": list(get_supported_flow_speed_modes(self._zone)),
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._update_from_zone()
        self.async_write_ha_state()


class GeckoSpaTemperatureSensor(
    GeckoZoneEntityMixin, GeckoEntityAvailabilityMixin, CoordinatorEntity, SensorEntity
):
    """Numeric temperature mirrors adapted from @markus-lassfolk's fork."""

    _zone_type = ZoneType.TEMPERATURE_CONTROL_ZONE
    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 1

    def __init__(self, coordinator, zone, kind):
        super().__init__(coordinator)
        self._zone = zone
        self._kind = kind
        self._attr_translation_key = f"{kind}_temperature"
        self._attr_translation_placeholders = {"zone_name": zone.name}
        self._attr_state_class = (
            SensorStateClass.MEASUREMENT if kind == "current" else None
        )
        self._attr_unique_id = f"{coordinator.entry_id}_{coordinator.vessel_id}_spa_{kind}_temperature_{zone.id}"
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))}
        )
        self._update_value()

    def _update_value(self):
        zone = self._current_zone()
        value = (
            None
            if zone is None
            else (
                zone.temperature if self._kind == "current" else zone.target_temperature
            )
        )
        self._attr_native_value = (
            value
            if isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            else None
        )

    @callback
    def _handle_coordinator_update(self):
        self._update_value()
        self.async_write_ha_state()


class GeckoShadowMetricSensor(
    GeckoEntityAvailabilityMixin, CoordinatorEntity, SensorEntity
):
    """A read-only reported extension metric, including available Waterlab data."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, path):
        super().__init__(coordinator)
        self._path = path
        self._kind = water_quality_kind(path)
        self._attr_translation_key = f"reported_{self._kind or 'metric'}"
        self._attr_translation_placeholders = {
            "metric_name": humanize_shadow_path(path)
        }
        digest = hashlib.sha256(path.encode()).hexdigest()[:16]
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_extension_{digest}"
        )
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))}
        )
        self._attr_entity_registry_enabled_default = self._kind is not None
        self._attr_entity_category = None if self._kind else EntityCategory.DIAGNOSTIC
        if self._kind == "ph":
            self._attr_device_class = SensorDeviceClass.PH
            self._attr_state_class = SensorStateClass.MEASUREMENT
        # Flattened MQTT extensions do not establish an ORP unit. Keep the
        # value readable without inventing voltage units or statistics.
        self._update_value()

    def _update_value(self):
        value = extract_extension_metrics(self.coordinator.get_spa_state()).get(
            self._path
        )
        self._attr_native_value = (
            None
            if self._kind == "ph" and value is not None and not 0 <= value <= 14
            else value
        )

    @property
    def extra_state_attributes(self):
        return {
            "source_path": self._path,
            "calibration_parameter": is_calibration_path(self._path),
        }

    @callback
    def _handle_coordinator_update(self):
        self._update_value()
        self.async_write_ha_state()


class GeckoWaterlabSensor(CoordinatorEntity, SensorEntity):
    """A chemistry reading returned by Gecko's optional Waterlab endpoint."""

    _attr_has_entity_name = True

    def __init__(self, coordinator, key):
        super().__init__(coordinator)
        self._key = key
        self._attr_unique_id = (
            f"{coordinator.entry_id}_{coordinator.vessel_id}_waterlab_{key}"
        )
        self._attr_translation_key = f"waterlab_{key.lower()}"
        self._attr_device_info = dr.DeviceInfo(
            identifiers={(DOMAIN, str(coordinator.vessel_id))}
        )
        self._update_metadata()

    def _update_metadata(self):
        record = self.coordinator.waterlab_readings.get(self._key, {})
        unit = record.get("unit")
        self._attr_device_class = None
        self._attr_native_unit_of_measurement = unit
        self._attr_state_class = SensorStateClass.MEASUREMENT
        if self._key == "ph":
            self._attr_device_class = SensorDeviceClass.PH
            self._attr_native_unit_of_measurement = None
        elif self._key == "orp" and unit in ("mV", "V"):
            self._attr_device_class = SensorDeviceClass.VOLTAGE
        elif self._key == "waterTemp" and unit in (
            "°C",
            "C",
            "celsius",
            "°F",
            "F",
            "fahrenheit",
        ):
            self._attr_device_class = SensorDeviceClass.TEMPERATURE
            self._attr_native_unit_of_measurement = (
                UnitOfTemperature.CELSIUS
                if unit in ("°C", "C", "celsius")
                else UnitOfTemperature.FAHRENHEIT
            )
        elif self._key in ("orp", "waterTemp"):
            # A missing/unknown unit cannot establish a physical measurement.
            self._attr_state_class = None

    @callback
    def _handle_coordinator_update(self):
        self._update_metadata()
        self.async_write_ha_state()

    @property
    def available(self):
        return (
            self.coordinator.waterlab_available
            and self._key in self.coordinator.waterlab_readings
        )

    @property
    def native_value(self):
        return self.coordinator.waterlab_readings.get(self._key, {}).get("value")

    @property
    def extra_state_attributes(self):
        record = self.coordinator.waterlab_readings.get(self._key, {})
        return {
            **{key: value for key, value in record.items() if key != "value"},
            "last_successful_poll": self.coordinator.waterlab_last_success,
            "data_source": "Gecko cloud Waterlab",
        }
