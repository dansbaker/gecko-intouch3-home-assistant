# Gecko upstream issue and pull request review

Reviewed 4 November 2026. Destination: `dansbaker/gecko-intouch3-home-assistant`.
Baseline: official `geckoal/ha-gecko-integration` main, `aaf94de`, version 2.1.1.
The original community repository remains on `master`; `restore/official-base` starts from the official history.

All 29 open issues and their discussion comments were read before reviewing the nine open integration PRs. The PR conversations and actual fetched code were then checked against the baseline and the pinned client library. Recommendations below are local review decisions; no PR has been merged, published, or posted to GitHub.

## Decisions

| PR | Decision | Reason |
| --- | --- | --- |
| [63](https://github.com/geckoal/ha-gecko-integration/pull/63) Reconnect and zone rebinding | Accept | Fixes stale pump/thermostat objects, stops replaced clients regardless of transport state, and rejects late events from replaced clients. Meaningful regression coverage passes. |
| [64](https://github.com/geckoal/ha-gecko-integration/pull/64) Active pump without speed | Accept after 63 | Prevents an AttributeError that stops entity updates. Its branch already includes 63; import only its additional commits after 63. |
| [54](https://github.com/geckoal/ha-gecko-integration/pull/54) OAuth callback | Accept | Declaring `my` makes HA select its standard OAuth redirect, addressing 19/34. This fixes redirect selection, not server outages or account eligibility. |
| [56](https://github.com/geckoal/ha-gecko-integration/pull/56) Eco attribute | Accept with integration adjustments | Correct read-only exposure of modeled eco state. Combine its attributes with 60 and read the current zone after 63. It does not fix eco setpoint commands. |
| [60](https://github.com/geckoal/ha-gecko-integration/pull/60) HVAC action and heat pump state | Accept with integration adjustments | All nine mappings match the pinned enum; exposes cooling, defrost and heat pump faults. Combine its attributes with 56 and retain 63's zone rebinding. It adds observation, not heat source control. |
| [32](https://github.com/geckoal/ha-gecko-integration/pull/32) Pump initiators | Adapt | Useful attribution, but a missing initiator value leaves the previous attribute behind. Rebuild the attribute from the current zone each update and distinguish unknown from an empty list. |
| [37](https://github.com/geckoal/ha-gecko-integration/pull/37) Telemetry and flow changes | Split and adapt; do not merge wholesale | Contains valuable diagnostics, discovery and telemetry work, but real-parser speed commands and new sensors still have defects. Its pump state semantics also change existing automation behavior. |
| [57](https://github.com/geckoal/ha-gecko-integration/pull/57) RGB and effects | Hold for corrections | Reproduced a persistent stale-color bug. Capability detection is based on attributes present on every LightingZone. Keep its useful executor and JSON-safe wire-format work when repairing it. |
| [33](https://github.com/geckoal/ha-gecko-integration/pull/33) Refresh token and reauth | Skip wholesale; retain focused missing-token follow-up | HA core already preserves an omitted refresh token, and official main already has reauth. This older branch mixes many changes and conflicts with later work. A missing refresh token still needs explicit handling. |

## Findings that affect acceptance

### PR 37 sends an invalid high-speed command with the real parser

The pinned `gecko-iot-client==1.0.3` converts a configuration such as `speed={minimum:50, maximum:100, stepIncrement:50}` into the scalar `50` in `ZoneConfigurationParser.parse_zones_configuration`. Consequently `FlowZone.speed_config` is `None`.

At current speed 50, [the command helper](https://github.com/geckoal/ha-gecko-integration/blob/7041b7e61a186141c1ccdd7ac0684215176fa0e5/custom_components/gecko/telemetry.py#L548) falls back to `high=3`. At current speed 100, the same helper returns `high=100`. The command encoding therefore depends on current state instead of retained configuration. This reproduces a central complaint in issues 39/40/49. The PR's helper tests use simplified zone objects and miss this parser interaction.

Preserve the raw speed ladder in the client/parser, then derive commands from that configuration. Explicitly test two-speed, single-speed, percentage and 99/100 readback devices through the actual parser. A telemetry value of 100 alone is insufficient evidence that a pump uses binary 99/100 encoding.

### PR 37 introduces more entities tied to obsolete zones

[Temperature status](https://github.com/geckoal/ha-gecko-integration/blob/7041b7e61a186141c1ccdd7ac0684215176fa0e5/custom_components/gecko/sensor.py#L299), flow speed, eco and per-zone heating entities retain the original `self._zone`. Replacing the coordinator's zone with a heating zone leaves the temperature status sensor reporting `IDLE`.

Extend the rebinding rule from 63 to every new zone-backed entity. Also guard the new raw-state and configuration callbacks against replaced clients; 63 only knows about the baseline zone/connectivity callbacks.

### PR 37 weakens the mixed AWS runtime check

Its `runtime_compatibility_error` returns before checking mixed modules outside Python 3.14+ ARM64. The PR discussion itself reports `_certificate_source` failure on an x86_64 upgrade. The native crash and mixed-module failure have different scopes. Preserve the consistency check across platforms, even if the legacy native-version rejection is narrowed. The synchronous package metadata read from issue 62 also remains.

The useful parts to extract first are stable vessel/zone discovery keys, the separator correction in unique-ID migration, current runtime diagnostics, and narrowly tested telemetry. Keep existing physical pump state behavior initially; expose manual demand and automatic activity separately before changing what fan on/off means.

### PR 57 permanently ignores a legitimate previous color

[Stale-echo handling](https://github.com/geckoal/ha-gecko-integration/blob/bc5ab632793b932751eb3ca6bc9bb31238047eb8/custom_components/gecko/light.py#L305) remembers the previous color without an expiry or clearing it after confirmation. Reproduction: red is reported, HA changes to blue, blue is confirmed, then the app changes back to red. HA continues reporting blue on subsequent red reports.

Bound any echo suppression to an outstanding command and clear it after confirmation; use message ordering/version information where available. Reported state must eventually win. Add cases for failed publishes, rapid color changes, reconnects and external brightness changes.

[Capability detection](https://github.com/geckoal/ha-gecko-integration/blob/bc5ab632793b932751eb3ca6bc9bb31238047eb8/custom_components/gecko/light.py#L218) uses `hasattr(rgbi/effect)`, but even an empty LightingZone configuration has both fields. That does not establish hardware support. The author reports successful hardware tests on their spa, which does not establish behavior on on/off-only zones. The JSON-safe list payload and executor dispatch are worth retaining.

### PR 32 leaves old attribution when initiators become unknown

[The update block](https://github.com/geckoal/ha-gecko-integration/blob/9e361bcbc8ede93c812f485c22a259056150986a/custom_components/gecko/fan.py#L121) only writes the attribute when `zone.initiators` is not None. A transition from `['UD']` to None leaves `['UD']` visible. Rebuild attributes each time, using None for unknown and `[]` for known-empty. Apply after 63 so attribution follows the current client.

### PR 33 assumes token replacement behavior that current HA does not have

HA 2026.9.4 `LocalOAuth2Implementation._async_refresh_token` returns `{**token, **new_token}`. A probe with a response omitting `refresh_token` preserves the existing token without this PR. The subclass override is redundant for that case and does not repair a present-but-null refresh token.

Official main's `25ed150` already adds reauth through PR 48. However, the baseline setup path no longer has 33's KeyError handler, and `OAuthGeckoApi.async_get_access_token` does not explicitly check for an absent refresh token. Add a focused check for missing/empty authentication data and raise `ConfigEntryAuthFailed`; do not classify every arbitrary KeyError as an authentication failure. Test that reauth preserves vessel/entity identity and validates the account.

## Complete open issue map

These are classifications against this baseline, not assertions that every report is reproduced on hardware.

| Issue | Assessment and next action |
| --- | --- |
| [65](https://github.com/geckoal/ha-gecko-integration/issues/65) Regular connection failure | Client passes the wrong MQTT5 keepalive keyword. Confirmed against installed SDK: old keyword gives 1200 seconds; correct keyword gives 60. Requires a client change; none of the nine PRs fixes it. |
| [62](https://github.com/geckoal/ha-gecko-integration/issues/62) Blocking metadata lookup | Confirmed synchronous `importlib.metadata.version` in async connection setup. Move compatibility check to executor; caching alone still blocks on its first call. |
| [61](https://github.com/geckoal/ha-gecko-integration/issues/61) Savings setpoint and mode reset | Still unresolved. Capture actual app command/response behavior; 56 only exposes eco state. Do not infer a fix from successful MQTT publication. |
| [59](https://github.com/geckoal/ha-gecko-integration/issues/59) HA crash after 2.1.1 | Existing pins/guard target the previous crash. Discussion disputes which library versions produced the dump. Fresh ARM64 crash evidence is still needed; do not mark resolved. |
| [53](https://github.com/geckoal/ha-gecko-integration/issues/53) Super Savings rejected | Duplicate root cause of 36; display-name normalization in the client. None of the nine PRs fixes the select operation. |
| [50](https://github.com/geckoal/ha-gecko-integration/issues/50) TLS context mismatch | Official 2.1.1 adds matched pins/guard. Clean-restart verification is needed on affected installations. Preserve cross-platform mixed-module detection. |
| [49](https://github.com/geckoal/ha-gecko-integration/issues/49) Pump and missing zone after board replacement | Includes configuration/zone discovery and speed-range problems. Extract repaired speed work from 37; separately investigate missing configured zone 2. |
| [47](https://github.com/geckoal/ha-gecko-integration/issues/47) Authentication 403 | Discussion reports server-side recovery and official 2.1.0 auth improvements. No basis for restoring an alternate auth flow by default. |
| [46](https://github.com/geckoal/ha-gecko-integration/issues/46) 429 and stale broker URL | Main already returns None on refresh failure and has coordinator backoff. Retry-After, single-flight refresh and rate-limit behavior still need tests. 63 helps replaced-client cleanup. |
| [45](https://github.com/geckoal/ha-gecko-integration/issues/45) Temperature increase on mode change | Unresolved, related to 61. Distinguish commanded target from measured temperature and test Celsius/Fahrenheit behavior. None of these PRs establishes a fix. |
| [42](https://github.com/geckoal/ha-gecko-integration/issues/42) Only 10 of 17 spas listed | Investigate API pagination and account limits. Also affects official app according to report; backend cause is plausible, not proven from client code. |
| [40](https://github.com/geckoal/ha-gecko-integration/issues/40) High pump speed | Same control gap as 39/49. 37 helps some 99/100 devices but needs parser/configuration repair before general acceptance. |
| [39](https://github.com/geckoal/ha-gecko-integration/issues/39) Pump speed unavailable | Same speed gap. Logs also contain both `gecko` and `gecko_spa` integrations and 429s; investigate competing installs without assuming causation. |
| [36](https://github.com/geckoal/ha-gecko-integration/issues/36) Super Savings name | Client uppercases but does not normalize the space. Linked client PR 13 is a separate candidate to inspect and test. |
| [35](https://github.com/geckoal/ha-gecko-integration/issues/35) Waterlab | Missing capability; 37 does not implement Waterlab chemistry. Community fork is a separate source requiring review. |
| [34](https://github.com/geckoal/ha-gecko-integration/issues/34) Callback mismatch | Accept 54; verify complete OAuth flow on a deployment without default `my` setup. |
| [31](https://github.com/geckoal/ha-gecko-integration/issues/31) Controls vanish with HA 2026.2 | Main contains lowercase entity fixes and stable unique-ID migration; comments report HA 2026.2.1 recovery. Preserve those improvements. |
| [29](https://github.com/geckoal/ha-gecko-integration/issues/29) Missing refresh token | Main already provides reauth; add explicit missing-token detection and recovery tests rather than importing all of 33. |
| [27](https://github.com/geckoal/ha-gecko-integration/issues/27) Cloud requirement | Architectural limitation/request; none of these integration patches supplies local in.touch3 access. |
| [23](https://github.com/geckoal/ha-gecko-integration/issues/23) Light stuck on | Still needs an on/off state/command regression and device evidence. RGB support in 57 is not itself proof this older symptom is fixed. |
| [21](https://github.com/geckoal/ha-gecko-integration/issues/21) No data/disconnected | Older reconnection/auth symptoms overlap fixes already on main plus 63. Recheck with current client and captures; do not assume one root cause for all reports. |
| [20](https://github.com/geckoal/ha-gecko-integration/issues/20) in.touch2 documentation | Separate protocol/device scope. This restoration targets the official in.touch3 integration. |
| [19](https://github.com/geckoal/ha-gecko-integration/issues/19) Callback mismatch | Duplicate of 34; accept 54. |
| [17](https://github.com/geckoal/ha-gecko-integration/issues/17) EN power loss | Reports conflict; separate RF/pairing recovery from HA token/reconnect defects. Do not encode the anecdotal 13-step reset as a general repair. |
| [16](https://github.com/geckoal/ha-gecko-integration/issues/16) Crash during transition | Claimed orphaned-integration cause is unsupported by the supplied evidence. Document domain/install migration carefully; do not adopt claims that logging config alone causes a system crash. |
| [14](https://github.com/geckoal/ha-gecko-integration/issues/14) Speeds, temperature override, colors | Speeds: repaired extraction from 37. Colors: corrected 57. Keep the controller's configured temperature limits. |
| [13](https://github.com/geckoal/ha-gecko-integration/issues/13) Unreliable reconnect | Missing reconnect method in old version now exists on main. 63 fixes further stale-object/client cleanup failures; client keepalive still needs work. |
| [12](https://github.com/geckoal/ha-gecko-integration/issues/12) Additional sensors | 60 supplies heat pump status; 37 supplies some operational telemetry. Energy, pH/ORP, maintenance, cover and heat pump control remain separate work. |
| [7](https://github.com/geckoal/ha-gecko-integration/issues/7) API account 404 | Report starts with in.touch2; one commenter reports in.touch3 purchase resolved it. Verify supported hardware/account enrollment and API response; unrelated to callback mismatch. |

## Validation

Environment: isolated Python 3.14.7 on macOS ARM64, Home Assistant 2026.9.4, `pytest-homeassistant-custom-component==0.13.367`, Gecko client 1.0.3, awscrt 0.36.1, awsiotsdk 1.31.0. No spa/cloud commands were sent.

| Check | Result |
| --- | --- |
| Official main with 64's regression suite copied in | 12 failed, 7 passed; failures reproduce the targeted defects |
| PR 63 native regression suite | 18 passed |
| PR 64 native regression suite | 19 passed |
| PR 37 documented unittest runner | 36 passed; helper coverage misses the real-parser and entity-lifecycle failures above |
| Independent probes for 32, 37 and 57 | Reproduced stale attributes, parser/speed errors, stale new telemetry sensor, and stale color |
| Independent probes for 54, 56 and 60 | Redirect selection, unknown/true/false eco states, all nine HVAC mappings and heat pump error attribute passed |
| HA core token refresh probe | Existing refresh token preserved without 33 |
| SDK builder with native client constructor mocked | `keep_alive_secs=30` gives 1200; `keep_alive_interval_sec=60, ping_timeout_ms=10000` gives 60 and 10000 |

An initial PR 37 pytest run in the shared review environment failed at fixture setup because its unittest-only project lacks asyncio pytest configuration. Its documented unittest command passes; those setup errors are not counted as product defects.

The small checks are retained in [review/probes.py](review/probes.py). Run with an extracted PR checkout: `python docs/review/probes.py 57 /path/to/pr57`. The script prints observations and labels discrepancies; it is a review probe, not a pass/fail CI test suite. The color-capability case checks the absence of evidence from model fields, not a physical device capability.

Tests using a fake network establish integration behavior, not physical delivery, native AWS thread termination, or platform-wide crash resolution. Before a release, run real restart/reconnect and long-duration checks, exercise pump commands and reported state on representative hardware, complete OAuth/reauth, and verify migration preserves automations. The client-side lifecycle PR linked from 63 remains a separate review item.

## Import sequence

1. Keep official main as the baseline and retain its stable identifiers and AWS dependency pins.
2. Bring in 54, then 63 and the incremental part of 64, including their regression harness.
3. Combine 56 and 60 in one current-zone-aware climate update; add mapping and attribute-retention tests.
4. Adapt 32 with current-zone lookup and proper clearing of unknown initiators.
5. Extract narrowly scoped discovery and diagnostics improvements from 37, then repair parser-backed speed handling and apply zone rebinding to all new sensors before adding them.
6. Repair 57's reconciliation and capability handling before bringing in RGB/effects.
7. Address the uncovered client/integration gaps: keepalive, Super Savings normalization, event-loop blocking, missing-token recovery and watercare/setpoint behavior.

This review does not change the integration domain, OAuth client identity, repository default branch, release version, or installed Home Assistant instance.

## Reviewed PR snapshots

| PR | Head commit |
| --- | --- |
| 32 | `9e361bcbc8ede93c812f485c22a259056150986a` |
| 33 | `d9164574a8b6ae863044154d1cfbd983e312a23e` |
| 37 | `7041b7e61a186141c1ccdd7ac0684215176fa0e5` |
| 54 | `ba637f6e6c51fdbde6f4e52fdcd5f27b1d84d3c1` |
| 56 | `9a64baec5612b1ea7e06027d2bdf035ccddac4e4` |
| 57 | `bc5ab632793b932751eb3ca6bc9bb31238047eb8` |
| 60 | `38e14e84d4084e690bf56dfcda823e112cb2711c` |
| 63 | `cda419fd2c4378a1488962fa4dbc8111f6aac6fd` |
| 64 | `15f39ec59231dab1320ed6c1159820b7e7015a42` |

## Restoration implementation follow-up

The decisions above record the initial review, before repairs. The subsequent local restoration incorporates the accepted parts and repaired adaptations of PRs 32/37/57 rather than leaving their useful changes on hold. [RESTORATION.md](RESTORATION.md) records the final implementation; [FORK_REVIEW.md](FORK_REVIEW.md) records all 16 public forks. In particular, passive `COOLING` status is now idle in HA following Logix's later fork correction; active heat-pump cooling remains cooling. Hardware-specific limitations and unresolved eco-setpoint reports remain open.


### Further repairs, 5 November 2026

The follow-up in [RESTORATION.md](RESTORATION.md) repairs desired-state echoes
being treated as reported zone state, a reproducible contributor candidate for
issue 23. It also prevents failed temperature/pump publishes from changing the
local model. Neither change establishes a physical-hardware resolution of
issue 23 or the distinct eco/Watercare behavior in 45/61.
