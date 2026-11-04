# Community restoration changes

Local restoration on 4 November 2026. Official integration baseline: `aaf94de` (2.1.1). Bundled client baseline: `b799e0c` (v1.0.3). Manifest version 3.0.0 identifies this independent combined build; no release or tag has been published.

## Incorporated and repaired

- Integration PRs 63/64: stop replaced/disconnected clients, rebind every zone-backed entity, guard late callbacks and tolerate active pumps without speed. Transport callbacks dispatch onto HA's loop and check client identity at delivery, including configuration/raw-state updates.
- PR 54: declare `my` for the standard OAuth redirect.
- PRs 56/60 and Logix fork: combine eco/heat-pump attributes and all status mappings; distinguish passive cooling from active heat-pump cooling. Add watercare climate presets and refresh notifications when operation mode changes.
- PR 32: initiator attributes follow current state, including unknown values.
- PR 37: deterministic entity discovery, separator-safe identifier migration, runtime diagnostics, RF/firmware/flow telemetry, heating/eco/cleaning/in-use sensors and sparse connectivity handling. Keep physical pump running state and expose manual/automatic demand separately.
- Client PR 11: preserve flow speed configuration through the real parser. Derive commands from that ladder; single-speed pumps stay on/off. Recognize 99/100 low/high encoding only after observing the distinguishing low value.
- Lacroix fork: start configured two-speed pumps parked at high in low first, then require a new device running report before high. Timeout leaves a clear error; optimistic local command changes cannot count as confirmation.
- PR 57/client PR 12 and nmonteleone18 fork: RGB/effects, JSON-safe `[r,g,b,i]` payloads, normalized hue/brightness and executor dispatch. Replace permanent previous-color suppression: reported external changes win. Failed publish does not commit the color cache or local model color.
- Client PR 13: normalize spaced Super Savings names.
- Issue 65: use the actual MQTT5 `keep_alive_interval_sec` option, 60 seconds, with 10-second ping timeout. Stop a native MQTT client even after its connected flag drops.
- Issue 62: run native package compatibility/metadata checks in the executor while retaining platform-independent mixed-module detection.
- Authentication: explicit missing refresh/access token errors; validate the same Gecko account before accepting reauth. HA core retains refresh tokens omitted during token renewal. Coalesce broker credential requests, cache only briefly, honor retry delay/backoff, and avoid repeated requests while limited.
- Public command failures propagate from the bundled model/client to Home Assistant; synchronous publish confirmation runs in the executor.
- Markus fork: read-only cloud Waterlab chemistry, bounded reported extension metrics, current/target temperature sensors and heating sensor device classes. Waterlab polling is independent of MQTT and cannot disable the primary integration on unsupported endpoints.
- Diagnostics use current runtime coordinators, work without setup runtime data and restrict connection output to the requested entry.

Everything ships in `custom_components/gecko`, including the client. Existing licenses and source provenance are preserved. README credits identify contributors whose code or ideas were adapted. See [UPSTREAM_REVIEW.md](UPSTREAM_REVIEW.md) for the original issue/PR review and [FORK_REVIEW.md](FORK_REVIEW.md) for the full public fork decisions.

## Verification and limits

Final local verification: **374 tests passed and 46 subtests passed** on Python 3.14.7 with Home Assistant 2026.9.4. `git diff --check` also passed.

The unified tests exercise the actual bundled parser/models, MQTT configuration and mocked HA entities/API boundaries. Client transport/model tests run alongside reconnect, stale-zone, telemetry, light, pump, auth/rate-limit and Waterlab regressions. A package test verifies the integration can import with no separately installed `gecko-iot-client` distribution.

This is source/test verification, not physical spa or live cloud verification. Outstanding work includes actual ARM64 native-runtime validation, device-specific RGB/effect formats, optional cloud endpoint permissions, Waterlab sample freshness and issue 45/61 eco setpoint behavior. No spa commands, Home Assistant configuration changes, GitHub comments/merges, push or release were performed.
