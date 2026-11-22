# Gecko in.touch 3 / 3+ for Home Assistant

**This repository is no longer abandoned.** Development has resumed here, and community contributions are welcome: fixes, device reports, documentation, tests and carefully scoped improvements all help.

This is the continuation of Dan Baker's original community repository. The revived integration uses [Gecko's official integration](https://github.com/geckoal/ha-gecko-integration) as its code base, together with selected community fixes and improvements. It is maintained independently.

Thank you to the Gecko team for building the official integration and IoT client and making their work available. I know this was a passion project for the Gecko team and that they put a lot of time into it. Unfortunately, since launching the official repo the development seems to have stalled. Bug reports go largely unanswered, community pull requests go unmerged. We now have a dozen forks implementing their own bug fixes and feature extensions, creating a confusing landscape for users who just want to control their spa with Home Assistant. I have decided to ressurect my repository and to build out the best Gecko integration possible. I have included features and fixes from other forks (credit given below) as well as pull requests against the official repo. I've sigificantly improved on the reliability of the integration by implementing HA best practices and extending unit test coverage. I welcome pull requests against this repo.

## What this isn't
I'm one person and I own exactly one spa. It's a pretty basic one at that. Some of you have swim spas, waterlabs, RGB lighting, etc. I can't test this stuff. I can check the code looks good but it's going to be up to the community (that's YOU) to contribute logs, pull requests and bug reports to help maintain the device compatbility.

## Features

- Temperature control, current/target temperature sensors, heating and heat pump status, eco state, and watercare presets.
- Pump/blower control using the reported speed configuration. Physical running state remains visible, with separate manual, filtration and flow-check telemetry.
- RGB, brightness and effects on lights that report those capabilities; on/off control for simpler lighting zones.
- Connection health, RF/firmware telemetry, diagnostics and stable entity discovery.
- Read-only Waterlab chemistry readings from Gecko's cloud: pH, ORP and supported additional readings when supplied by your account/device.
- One repository and one installation: the IoT client ships inside the integration.

Available controls and sensors depend on your equipment and the data Gecko exposes. This integration uses Gecko's cloud and your existing Gecko account.

## Installation

Search for **Gecko in.touch 3** in HACS (Marketplace on supported Home Assistant installations) and install it. While the default-catalog submission is awaiting approval, or if search does not find it, add `https://github.com/dansbaker/gecko-intouch3-home-assistant` as a custom repository with category **Integration** (Marketplace: **Add from link**).

Restart Home Assistant, then open **Settings → Devices & services → Add integration → Gecko in.touch 3**. For a new installation, follow the Gecko OAuth login. Keep Home Assistant's **My** integration enabled for the standard callback. Home Assistant-managed [application credentials](docs/OAUTH.md) are also supported.

For manual installation, copy the complete `custom_components/gecko_intouch3` directory into your Home Assistant `custom_components` directory, including the bundled client, then restart.

### Migrating from version 3.x or Gecko's official in.touch 3 integration

**Version 4.0.0 changes the integration domain from `gecko` to `gecko_intouch3`.** This allows gazoodle's local in.touch 2 integration and this cloud in.touch 3 integration to coexist. The old abandoned `gecko_spa` implementation has a different schema and is not eligible for this import.

1. Take a full Home Assistant backup before upgrading. Keep it until you have checked your entities and automations.
2. Disable the existing **in.touch 3 cloud account** under **Settings → Devices & services**. Do not delete its config entry: the importer needs its settings and entity registrations. Do not disable or remove gazoodle's in.touch 2 integration.
3. Install this release, then restart Home Assistant. **Marketplace on HA 2026.11 can block an update across the domain change:** follow the [Marketplace-specific preparation below](#marketplace-on-home-assistant-202611-and-newer) before installing. Keep the disabled old config entry for the importer. The new files belong in `custom_components/gecko_intouch3`; this release does not install a compatibility integration into the shared `gecko` directory.
4. Add **Gecko in.touch 3**. Select the existing cloud account when offered the migration form. The importer copies its authentication and options, transfers entity/device registrations through Home Assistant's registry APIs, and removes the old cloud config entry only after transfer. Account entries are identified by their cloud configuration schema, not by the shared `gecko` name alone.
5. Check that the spa reconnects and that entity IDs, device assignments, dashboards and automations still work. The migration is designed to retain entity IDs and devices; duplicate destination entities stop migration rather than overwriting them. Reauthenticate if Gecko has expired the saved credentials.
6. Remove any obsolete in.touch 3 download from HACS/Marketplace once it is no longer configured. If you moved the old files aside, retain them until testing is complete. Do not remove `custom_components/gecko` if gazoodle's in.touch 2 integration owns it. Do not run both cloud integrations for the same spa.

#### Marketplace on Home Assistant 2026.11 and newer

Marketplace may report that this repository “changed its domain from gecko to gecko_intouch3, uninstall it and install it again”, then refuse uninstall with `repository_in_use` because the old account entry still exists. Disabling the entry alone does not remove this installation block. **Do not use Delete and uninstall or delete the old config entry**: that would remove the settings and registrations needed by the importer.

After taking the backup and disabling the old **in.touch 3 cloud account** in steps 1–2:

1. Verify that `/config/custom_components/gecko/manifest.json` points to this repository or Gecko's official `geckoal/ha-gecko-integration`, **not** `gazoodle/gecko-home-assistant`. If the folder belongs to gazoodle's local in.touch 2 integration, leave it alone; this workaround does not apply to that folder.
2. Move only the verified old cloud integration's `gecko` directory outside `custom_components`. On HAOS, use the **Terminal & SSH** app's web terminal. First check that `/config/gecko-intouch3-before-v4` does not already exist; if it does, choose a different unused backup name. This command refuses to overwrite that destination:

   ```sh
   test ! -e /config/gecko-intouch3-before-v4 && mv /config/custom_components/gecko /config/gecko-intouch3-before-v4
   ```

   Other installation types must use their actual Home Assistant configuration directory. Move the directory; do not delete its files or edit `.storage`.
3. Restart Home Assistant. Marketplace should now mark the old download as no longer installed. The disabled cloud account entry must remain under **Devices & services**; it may show that its integration files are unavailable. If Marketplace still considers the repository installed, stop and report the error rather than deleting the config entry.
4. Install **Gecko in.touch 3 4.0.0 or newer** through Marketplace (use **Add from link** with this repository's URL if it is not in the catalog), then restart Home Assistant again. The new directory is `custom_components/gecko_intouch3`.
5. Continue at step 4 of the main migration instructions: add **Gecko in.touch 3** and select the retained cloud account in the import form. If installation opened a setup flow automatically, continue that flow rather than starting a second one.

Thanks to @cwm12345 for reporting and testing this path in [issue #20](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues/20): their two-spa migration preserved 66 entity IDs and both device IDs. This workaround addresses Marketplace installation; the importer still performs the registry migration.

For a rollback, restore the Home Assistant backup and the matching old integration files. Downgrading only the files does not reverse the namespace migration. Backups contain authentication data; keep them private.

Entity-based automations should retain their references. Update any integration-domain-specific references such as diagnostic download URLs, logger settings and custom Python imports from `gecko` to `gecko_intouch3`. The bundled standalone `gecko_iot_client` Python package keeps its existing import name.

## Waterlab

Waterlab support is read-only. After setup, the integration requests the vessel's cloud readings and refreshes them every five minutes independently of MQTT traffic. Sensors appear when Gecko returns actual supported reading records. This includes pH and ORP, plus water temperature and supported chemistry records such as alkalinity or chlorine when present. Additional records can originate from manual tests or computed results; each sensor retains the cloud's `source`, `status`, units and available timestamp fields, rather than presenting every value as a live probe measurement.

A failed refresh makes cloud readings unavailable. A missing reading is not replaced with zero. Cloud access denied/not found (HTTP 403/404) stops optional chemistry polling until reload, without taking pump or temperature controls offline. Cloud chemistry availability is independent of the MQTT link. `last_successful_poll` describes retrieval time. Sensor attributes separately expose `measurement_timestamp`, `measurement_age_seconds` and `measurement_time_status` when a timezone-aware sample timestamp exists. Age is computed when the entity updates, not continuously. Missing/invalid timestamps are `unknown`; future timestamps are flagged `future` for clock skew. No expiry threshold is assumed; an old sample returned by Gecko can still be old.

Explicit numeric pH/ORP readings in reported MQTT extensions are also discovered. Unknown extension fields and calibration constants are opt-in diagnostics, disabled by default; calibration values are never presented as live chemistry. This build does not calibrate probes, issue dosing commands or change undocumented Waterlab settings.

The cloud payload handling is covered by automated tests based on public fork examples. Live chemistry and account permissions still need verification on Waterlab hardware. Reports with redacted payloads and timestamps are very welcome.

Entity names and icons now use Home Assistant translations, and connection/firmware details appear as diagnostics. Existing entity IDs and Watercare option strings are retained. Target-temperature mirrors no longer contribute measurement statistics. MQTT ORP extensions retain their values without assuming a voltage unit; explicit-unit Waterlab readings retain their physical units. See the [entity metadata review](docs/ENTITY_METADATA.md).

## Help expand hardware support

Own extra pumps, RGB lighting, Waterlab or another configuration? [Download diagnostics and report your hardware](docs/HARDWARE_REPORTING.md)—no terminal or packet capture needed. The guide explains how to collect before/after snapshots using the Gecko app and [submit a hardware report](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues/new?template=hardware_report.yml). Please include what physically happened, as well as what the app and HA showed.

## Troubleshooting and contributions

If data stops updating, check the spa in the Gecko app and inspect the gateway/vessel connection entities. A pump running for filtration or heating can remain on after a manual off request; the integration preserves automatic-demand protection. Two-speed pumps parked at high speed can start at low first and wait for a device report before requesting high.

Downloaded diagnostics include anonymous vessel labels, connection health, pump counts and speed limits, lighting capabilities, and thermostat readings. They exclude account/device identifiers, names, credentials, URLs and raw cloud payloads. These snapshots help diagnose spa configurations that maintainers do not own, including additional pumps. Waterlab diagnostics include reading types, allowlisted units/source/status, and valid measurement timestamps and ages. Unknown free-text metadata is withheld.

Pump, light and thermostat commands report unavailable controls and delivery failures clearly. Temperature targets must fall within the spa's configured limits. A pump running for heating or filtration cannot be stopped manually. Lights expose color control when reported by the device; plain on/off lights reject color and brightness requests.

Watercare commands now report delivery failures explicitly and wait for the spa's reported mode before changing the displayed state. The unrecognized “Other” mode is no longer offered as a command.

Report problems and contribute changes in [this repository](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues). Include your Home Assistant version, device/controller details, reproduction steps and redacted diagnostics. Remove tokens, credentials and personal identifiers from reports. See the [device fixture guide](docs/DEVICE_FIXTURES.md), [development](docs/DEVELOPMENT.md), the [upstream issue/PR review](docs/UPSTREAM_REVIEW.md), [fork review](docs/FORK_REVIEW.md), and [restoration changes](docs/RESTORATION.md).

The 3.0.0 runtime has been deployed successfully on HAOS ARM64 with Home Assistant 2026.10.4: startup, preserved entity identities, connection diagnostics and reported states were verified. Device-specific RGB/effect semantics and eco/Watercare setpoint behaviour still need owner validation. Automated tests cannot establish physical spa behaviour. See the [hardware verification table](docs/COMPATIBILITY.md) and [release testing/rollback guide](docs/RELEASE_TESTING.md).

### Firmware and serial metadata

Some Gecko third-party accounts cannot read the identity shadow used by the
Gecko app. Firmware and serial sensors stay unavailable when the permitted
payloads provide no value; other controls continue to work. CO serial numbers
come only from explicit serial fields. A vessel ID is not a CO serial, and we do
not copy the home/EN serial into the spa/CO sensor. Existing entity identities
are retained. If genuine metadata arrives, the corresponding sensor becomes
available while the spa is connected. Sparse updates retain the last supplied
metadata; a firmware value is not invented from a shadow revision or pack ID.
See [issue #12](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues/12).

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
| @cwm12345 | [PR 10](https://github.com/dansbaker/gecko-intouch3-home-assistant/pull/10): Marketplace migration instructions; [issue #20](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues/20): tested Marketplace namespace-upgrade workaround; [PR 11](https://github.com/dansbaker/gecko-intouch3-home-assistant/pull/11): valid suggested entity IDs and native climate temperature compatibility. [Client PR 13](https://github.com/geckoal/gecko-iot-client/pull/13): normalizing Super Savings mode names. |
| @nmonteleone18 | [Fork](https://github.com/nmonteleone18/ha-gecko-integration): RGB hue/brightness normalization helpers. |
| @markus-lassfolk | [Fork](https://github.com/markus-lassfolk/hass_gecko_in_touch3_spa): Waterlab cloud reading shapes/endpoints, reported extension discovery and temperature/heat sensor ideas. |

These changes were reviewed, combined and in several cases repaired rather than merged verbatim. The review documents record the scope and deferred work. Thanks also to everyone who supplied issues, logs, testing and public forks, and to earlier contributors whose work is already in the official baseline.

## Direction

Our long-term goal is inclusion in Home Assistant Core, with Gold as the quality target. The current custom integration is not yet core-ready or awarded a quality tier. See the [core adoption requirements and roadmap](docs/CORE_ADOPTION.md), including the plan to retain one repository while publishing the protocol client as a standalone dependency.

## Source and licensing

Gecko Alliance's original integration license and notices are retained in [LICENSE](LICENSE) and [NOTICE](NOTICE). The original IoT client sources retain their [GPL-3.0-or-later license](custom_components/gecko_intouch3/gecko_iot_client/LICENSE). Extracted integration helpers retain [Apache-2.0](custom_components/gecko_intouch3/gecko_iot_client/LICENSE-APACHE), with attribution in the [client NOTICE](custom_components/gecko_intouch3/gecko_iot_client/NOTICE). The distribution includes both sets of source and notices; the root Apache license does not replace the client's GPL license. Gecko trademarks belong to Gecko Alliance.
