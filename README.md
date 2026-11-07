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

In HACS, add `https://github.com/dansbaker/gecko-intouch3-home-assistant` as a custom repository with category **Integration**, download version **3.0.0** or newer, and restart Home Assistant.

On Home Assistant 2026.11 and newer, HACS is built in as the **Marketplace**. Go to **Settings → Marketplace → Add from link**, enter the same URL, then install version **3.0.0** or newer. Adding a custom repository asks you to connect GitHub once.

For manual installation, copy the complete `custom_components/gecko` directory into your Home Assistant `custom_components` directory and restart. The bundled client directory must be included.

Then open **Settings → Devices & services → Add integration → Gecko** and follow the Gecko OAuth login. Keep Home Assistant's **My** integration enabled for the standard callback. If a login has lost its refresh token, use the prompted reauthentication flow.

If Gecko has issued OAuth credentials for your application, the integration also supports Home Assistant-managed [application credentials](docs/OAUTH.md). The existing bundled login remains available.

### Existing installations

This build uses the official integration's `gecko` domain and replaces the official integration in place. It retains official config-entry data and migrates older name-based entity identifiers where possible. A higher version number does **not** make HACS switch repositories automatically.

To move from Gecko's official repository on Home Assistant 2026.10 or older (HACS):

1. Take a Home Assistant backup.
2. Uninstall the official Gecko download **in HACS**. Keep the configured Gecko integration under **Settings → Devices & services**; deleting it would remove its configuration and entities.
3. Add `https://github.com/dansbaker/gecko-intouch3-home-assistant` as a HACS custom repository with category **Integration** and download a revived release from this repository. Do not leave both repositories managing the same `custom_components/gecko` directory.
4. Restart Home Assistant after the replacement is installed, then check that your existing spa entities are available. There is no need to add Gecko again when migrating from the official integration.

#### Home Assistant 2026.11 and newer (Marketplace)

The Marketplace protects the official repository's files while Gecko is configured. It won't uninstall them while a Gecko config entry exists; its **Delete and uninstall** button deletes the config entry with its devices and entities, so don't use it. It also won't install this repository while the official one still owns the `gecko` folder ("The gecko directory belongs to geckoal/ha-gecko-integration"). At startup, the Marketplace marks a repository whose folder is gone as no longer installed, so the swap goes like this:

1. Take a Home Assistant backup.
2. Move the official files out of `custom_components`. The **Terminal & SSH** app's web terminal works:
   `mv /config/custom_components/gecko /config/gecko-official.bak`
3. Restart Home Assistant (`ha core restart` in the same terminal). The log shows `geckoal/ha-gecko-integration is no longer on disk, it is no longer installed`. Your Gecko config entry stays and shows as not loaded until the next step.
4. Go to **Settings → Marketplace → Add from link**, enter `https://github.com/dansbaker/gecko-intouch3-home-assistant`, and install version **3.0.0** or newer. If the install opens a new Gecko setup, close it; your existing entry is used.
5. Restart Home Assistant and check that your existing spa entities are available.

Once the entities are back, you can delete `/config/gecko-official.bak`. To go back, restore the backup from step 1.

For manual upgrades, replace the complete `custom_components/gecko` directory before restarting; include the bundled client. The first revived release is **3.0.0**. Old `v0.1.x` releases contain the abandoned `gecko_spa` integration and are not an upgrade to Gecko's official integration.

The original abandoned implementation used `gecko_spa`. Its configuration and entity identities are different: remove that old integration and configure Gecko again, then update automations referencing its entities. Do not run both implementations for the same spa. Keep a Home Assistant backup before migrating.

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
