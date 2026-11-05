# Gecko in.touch 3 / 3+ for Home Assistant

**This repository is no longer abandoned.** Development has resumed here, and community contributions are welcome: fixes, device reports, documentation, tests and carefully scoped improvements all help.

This is the continuation of Dan Baker's original community repository. The revived integration uses [Gecko's official integration](https://github.com/geckoal/ha-gecko-integration) as its code base, together with selected community fixes and improvements. It is maintained independently.

Thank you to the Gecko team for building the official integration and IoT client and making their work available. Maintaining an open source Home Assistant integration takes sustained work: keeping up with Home Assistant, supporting different spa configurations, investigating reports and reviewing contributions. We appreciate that effort and want to build on it constructively.

## Features

- Temperature control, current/target temperature sensors, heating and heat pump status, eco state, and watercare presets.
- Pump/blower control using the reported speed configuration. Physical running state remains visible, with separate manual, filtration and flow-check telemetry.
- RGB, brightness and effects on lights that report those capabilities; on/off control for simpler lighting zones.
- Connection health, RF/firmware telemetry, diagnostics and stable entity discovery.
- Read-only Waterlab chemistry readings from Gecko's cloud: pH, ORP and supported additional readings when supplied by your account/device.
- One repository and one installation: the IoT client ships inside the integration.

Available controls and sensors depend on your equipment and the data Gecko exposes. This integration uses Gecko's cloud and your existing Gecko account.

## Installation

In HACS, add `https://github.com/dansbaker/gecko-intouch3-home-assistant` as a custom repository with category **Integration**, download Gecko, and restart Home Assistant. Until a revived release is published, use a checkout of the restoration branch for manual testing.

For manual installation, copy the complete `custom_components/gecko` directory into your Home Assistant `custom_components` directory and restart. The bundled client directory must be included.

Then open **Settings → Devices & services → Add integration → Gecko** and follow the Gecko OAuth login. Keep Home Assistant's **My** integration enabled for the standard callback. If a login has lost its refresh token, use the prompted reauthentication flow.

If Gecko has issued OAuth credentials for your application, the integration also supports Home Assistant-managed [application credentials](docs/OAUTH.md). The existing bundled login remains available.

### Existing installations

This build uses the official integration's `gecko` domain. Replace the existing `custom_components/gecko` files as a complete directory, then restart. It retains official config-entry data and migrates older name-based entity identifiers where possible.

The original abandoned implementation used `gecko_spa`. Its configuration and entity identities are different: remove that old integration and configure Gecko again, then update automations referencing its entities. Do not run both implementations for the same spa. Keep a Home Assistant backup before migrating.

## Waterlab

Waterlab support is read-only. After setup, the integration requests the vessel's cloud readings and refreshes them every five minutes independently of MQTT traffic. Sensors appear when Gecko returns actual supported reading records. This includes pH and ORP, plus water temperature and supported chemistry records such as alkalinity or chlorine when present. Additional records can originate from manual tests or computed results; each sensor retains the cloud's `source`, `status`, units and available timestamp fields, rather than presenting every value as a live probe measurement.

A failed refresh makes cloud readings unavailable. A missing reading is not replaced with zero. Cloud access denied/not found (HTTP 403/404) stops optional chemistry polling until reload, without taking pump or temperature controls offline. Cloud chemistry availability is independent of the MQTT link. `last_successful_poll` describes retrieval time, not measurement age; an old sample returned by Gecko can still be old.

Explicit numeric pH/ORP readings in reported MQTT extensions are also discovered. Unknown extension fields and calibration constants are opt-in diagnostics, disabled by default; calibration values are never presented as live chemistry. This build does not calibrate probes, issue dosing commands or change undocumented Waterlab settings.

The cloud payload handling is covered by automated tests based on public fork examples. Live chemistry and account permissions still need verification on Waterlab hardware. Reports with redacted payloads and timestamps are very welcome.

Entity names and icons now use Home Assistant translations, and connection/firmware details appear as diagnostics. Existing entity IDs and Watercare option strings are retained. Target-temperature mirrors no longer contribute measurement statistics. MQTT ORP extensions retain their values without assuming a voltage unit; explicit-unit Waterlab readings retain their physical units. See the [entity metadata review](docs/ENTITY_METADATA.md).

## Troubleshooting and contributions

If data stops updating, check the spa in the Gecko app and inspect the gateway/vessel connection entities. A pump running for filtration or heating can remain on after a manual off request; the integration preserves automatic-demand protection. Two-speed pumps parked at high speed can start at low first and wait for a device report before requesting high.

Downloaded diagnostics include anonymous vessel labels, connection health, pump counts and speed limits, lighting capabilities, and thermostat readings. They exclude account/device identifiers, names, credentials, URLs and raw cloud payloads. These snapshots help diagnose spa configurations that maintainers do not own, including additional pumps. Waterlab diagnostics currently report availability and reading counts.

Pump, light and thermostat commands report unavailable controls and delivery failures clearly. Temperature targets must fall within the spa's configured limits. A pump running for heating or filtration cannot be stopped manually. Lights expose color control when reported by the device; plain on/off lights reject color and brightness requests.

Watercare commands now report delivery failures explicitly and wait for the spa's reported mode before changing the displayed state. The unrecognized “Other” mode is no longer offered as a command.

Report problems and contribute changes in [this repository](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues). Include your Home Assistant version, device/controller details, reproduction steps and redacted diagnostics. Remove tokens, credentials and personal identifiers from reports. See [development](docs/DEVELOPMENT.md), the [upstream issue/PR review](docs/UPSTREAM_REVIEW.md), [fork review](docs/FORK_REVIEW.md), and [restoration changes](docs/RESTORATION.md).

Known limits include unverified ARM64 native-runtime behavior on real Home Assistant hardware, device-specific RGB/effect semantics, and unresolved eco/Watercare setpoint behavior. Automated tests cannot establish physical spa behavior.

## Community acknowledgements

Thank you to the authors whose pull requests and fork work were incorporated or adapted:

| Contributor | Incorporated work |
| --- | --- |
| @lacroixdavid1 | [PRs 63/64](https://github.com/geckoal/ha-gecko-integration/pull/64): reconnect cleanup, current-zone rebinding, missing-speed handling, regression tests; low-first two-speed startup from their fork. |
| @oczek | [PR 54](https://github.com/geckoal/ha-gecko-integration/pull/54): standard Home Assistant OAuth callback dependency. |
| @LogixDE | [PRs 56](https://github.com/geckoal/ha-gecko-integration/pull/56), [57](https://github.com/geckoal/ha-gecko-integration/pull/57), [60](https://github.com/geckoal/ha-gecko-integration/pull/60) and [client PR 12](https://github.com/geckoal/gecko-iot-client/pull/12): eco/heat-pump attributes, RGB work and HVAC status; fork watercare presets, readable flow status and passive-cooling correction. |
| @shieldwed | [PR 32](https://github.com/geckoal/ha-gecko-integration/pull/32): pump initiator attribution. |
| @karlg100 | [PR 37](https://github.com/geckoal/ha-gecko-integration/pull/37): telemetry, diagnostics, stable discovery, sparse-state handling, pump interpretation and tests. |
| @jpwoodnet-boop | [Client PR 11](https://github.com/geckoal/gecko-iot-client/pull/11): preserving speed configuration separately from runtime state. |
| @cwm12345 | [Client PR 13](https://github.com/geckoal/gecko-iot-client/pull/13): normalizing Super Savings mode names. |
| @nmonteleone18 | [Fork](https://github.com/nmonteleone18/ha-gecko-integration): RGB hue/brightness normalization helpers. |
| @markus-lassfolk | [Fork](https://github.com/markus-lassfolk/hass_gecko_in_touch3_spa): Waterlab cloud reading shapes/endpoints, reported extension discovery and temperature/heat sensor ideas. |

These changes were reviewed, combined and in several cases repaired rather than merged verbatim. The review documents record the scope and deferred work. Thanks also to everyone who supplied issues, logs, testing and public forks, and to earlier contributors whose work is already in the official baseline.

## Direction

Our long-term goal is inclusion in Home Assistant Core, with Gold as the quality target. The current custom integration is not yet core-ready or awarded a quality tier. See the [core adoption requirements and roadmap](docs/CORE_ADOPTION.md), including the plan to retain one repository while publishing the protocol client as a standalone dependency.

## Source and licensing

Gecko Alliance's original integration license and notices are retained in [LICENSE](LICENSE) and [NOTICE](NOTICE). The original IoT client sources retain their [GPL-3.0-or-later license](custom_components/gecko/gecko_iot_client/LICENSE). Extracted integration helpers retain [Apache-2.0](custom_components/gecko/gecko_iot_client/LICENSE-APACHE), with attribution in the [client NOTICE](custom_components/gecko/gecko_iot_client/NOTICE). The distribution includes both sets of source and notices; the root Apache license does not replace the client's GPL license. Gecko trademarks belong to Gecko Alliance.
