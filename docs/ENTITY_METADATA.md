# Entity metadata and coverage review

Completed locally on 5 November 2026 against Home Assistant 2026.9.4. This is a
review of the existing custom integration, not a Core acceptance or tier award.

## Names, icons and registry compatibility

- Every platform uses entity-only names with `has_entity_name`. Vessel-level
  binary sensors no longer embed the vessel name a second time in their entity
  name. Existing generated object IDs and all unique IDs are retained.
- Fixed names use translation keys. Zone names and generated extension field
  names remain provider data and enter translated name templates as placeholders.
  Thermostat, Waterlab and zone status/temperature names are covered by English
  translations. Device-provided pump and light names retain their spelling.
- Fixed icons live in `icons.json`; pump/blower/waterfall icons follow the
  reported flow type. Device-class defaults handle other sensor icons.
- Original uppercase temperature-status enum values and title-case Watercare
  option strings remain unchanged for existing automations. Unusable translations
  with non-slug keys were removed. Translating these legacy state values in a Core
  adapter requires a separately versioned compatibility decision; this review
  does not silently change their automation contract or claim the Gold tier.
- Real HA tests verify existing user entity IDs/names survive the metadata update,
  controls retain IDs and device associations across reloads, and late-reported
  capabilities update their existing entities.

## Classes, units, categories and statistics

| Entity group | Decision |
| --- | --- |
| Thermostats | Celsius at the adapter boundary, reported limits and a 0.5-degree step; only heating is selectable. Watercare presets are advertised when the controller exists. |
| Current temperature mirrors | Temperature device class, Celsius, measurement statistics and one decimal of suggested precision. |
| Target temperature mirrors | Temperature device class and Celsius; no measurement state class because a setpoint is not an observed measurement. |
| Pump controls | Fan percentage uses the reported speed ladder or an observed binary encoding. Missing configuration does not invent a numeric speed command. |
| Light controls | RGB/brightness appears when color reports establish capability; on/off remains available for plain lights. Reported effects populate the effect list. |
| Gateway, spa and transport connectivity | Diagnostic category with connectivity classes. READY and RUNNING are online; unknown gateway/spa status remains unknown rather than false. |
| Firmware, serial and RF metadata | Diagnostic category. RF units/device classes are not guessed because observed sources mix different signal encodings. |
| Heating, eco mode, filtration and flow check | Heating uses the heat binary-sensor class. Derived eco/flow/in-use states have no invented physical device class. |
| Raw API debug sensor | Diagnostic enum, disabled by default; credential redaction remains active. |
| Waterlab pH | pH class, no invented unit and measurement statistics. |
| Waterlab ORP | Voltage class only for explicit V/mV units; unknown/missing units remain unclassified without measurement statistics. |
| Waterlab temperature | Temperature class only for recognized C/F units; unit metadata refreshes with readings. |
| Other Waterlab readings | Preserve the explicit provider unit and expose numeric observations without inventing a chemistry-specific device class. |
| MQTT extension pH | Valid pH readings receive the pH class; values outside 0–14 are unknown. |
| MQTT extension ORP | Keep the raw numeric value without a voltage class/unit/statistics, because the flattened extension does not establish its unit. Use explicit-unit Waterlab records for voltage measurements. |
| Calibration/unknown extensions | Opt-in diagnostic entities without measurement statistics or control actions. |

This changes statistics eligibility for target temperatures and untyped MQTT ORP;
existing history is not deleted. Entity IDs and native reading values are retained.

## Verification and regression gates

The complete suite passes **594 tests and 46 subtests**. Coverage is measured on
all integration and bundled client modules in one run:

| HA module | Statements | Branches |
| --- | --- | --- |
| fan, light, climate, select, entity, diagnostics | 100% | 100% |
| sensor | 99.3% | 94.2% |
| binary_sensor | 99.3% | 90.5% |
| config_flow | 100% | 100% |

Overall integration plus bundled client coverage is 77.8% of statements and 68.8%
of branches. The entity coverage gate requires all eight entity/diagnostic modules
to exceed 95% combined statement/branch coverage; controls, shared entity handling
and diagnostics must remain fully covered. It fails when a module or branch data
is absent, when a fully covered module regresses, or when a threshold is missed.
The separate full config-flow coverage gate remains enabled.

Ruff passes for the edited production modules and new tests. The official
2026.9.4 hassfest translation and icon validators pass for both catalogs and
`icons.json`. Only these validators were run locally; this is not a claim that
all hassfest plugins or remote GitHub checks ran. Existing CI also invokes the
hassfest action when changes are pushed.

No live Home Assistant instance or spa was changed. Waterlab and additional-pump
hardware still require community confirmation; simulated reports and service
checks establish software behavior, not successful operation of unowned hardware.

## Reference rules checked

- [Entity naming](https://contributors.home-assistant.io/core/entities/naming/)
- [Entity attributes](https://contributors.home-assistant.io/core/entities/entity-class/)
- [Sensor units and statistics](https://contributors.home-assistant.io/core/entities/sensor/)
- [Translations](https://contributors.home-assistant.io/core/integrations/translations/)
- [Icon translations](https://contributors.home-assistant.io/core/entities/icons/)
- [Per-module test coverage](https://contributors.home-assistant.io/core/quality-scale/test-coverage/)
