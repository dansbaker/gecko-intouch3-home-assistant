# Official integration fork review

Reviewed 4 November 2026 against official `geckoal/ha-gecko-integration` main `aaf94de`. GitHub's public [network members](https://github.com/geckoal/ha-gecko-integration/network/members) listed 16 forks, including second-generation forks. Every listed repository was cloned and every advertised branch head was inventoried and compared. This is a snapshot of the visible public network, not a claim about private, detached or subsequently created repositories.

[Exact branch/head inventory](review/fork-heads.json) makes the scope reproducible. Default branches alone were insufficient: several useful changes existed on feature branches. Duplicate branches and already integrated official changes were compared by content as well as ancestry, since squashed official commits can appear as divergent history.

## Decisions

| Fork | Review result |
| --- | --- |
| [LogixDE](https://github.com/LogixDE/ha-gecko-integration) | Combined upstream PR branch at `e31eb925`. Adapted climate watercare presets, operation-mode refresh notifications, readable flow status and passive cooling as idle. PR work credited separately. Replaced runtime monkey patches with bundled source fixes; did not take stale RGB cache logic. |
| [lacroixdavid1](https://github.com/lacroixdavid1/ha-gecko-integration) | PR 63/64 plus `feat/two-speed-pump` at `b816540a` and `lacroix` at `86113e02`. Adapted low-first startup: require a new reported running state before high speed, with bounded timeout and current-zone identity check. Preserve configured speed ladder rather than infer it from a single runtime value. |
| [karlg100](https://github.com/karlg100/ha-gecko-integration) | Main `7041b7e6` is PR 37, with older review/AWS branches. Extracted telemetry, sparse connectivity handling, discovery, diagnostics and tests; repaired parser integration, physical pump semantics and zone rebinding. Kept current pinned AWS versions and full mixed-module guard. |
| [dk1](https://github.com/dk1/ha-gecko-integration) | Main duplicates PR 37. Additional `debounce-unavailable-transition` at `b0efd053` delays disconnects by five seconds and can continually reschedule on repeated events. Deferred: fix sparse state and keepalive causes, retain prompt reporting of actual disconnects. Other AWS changes duplicate Karl's work. |
| [jodewee](https://github.com/jodewee/ha-gecko-integration) | Main duplicates PR 37; no additional implementation to extract. |
| [nmonteleone18](https://github.com/nmonteleone18/ha-gecko-integration) | `fa7b572a`: extracted pure RGB hue/brightness normalization helpers. Deferred the captured device-specific effect palette/intensity convention. Rejected private raw publish bypass that overrides pump automatic-demand protection. |
| [markus-lassfolk](https://github.com/markus-lassfolk/hass_gecko_in_touch3_spa) | Main `cc493d7a`, diagnostic branch `884ec4a5`. Large expansion reviewed by subsystem, payload extraction, controls, auth, polling and tests. Adapted read-only Waterlab v6 endpoint/reading shapes, reported extension discovery, current/target temperature and heat-device-class ideas. Reimplemented a smaller bounded reader with independent polling. Deferred energy endpoints/app-token auth, undocumented number controls, raw desired writes, dosing/actions, deployment tools and arbitrary 4–45°C display clamping. Did not copy the full fork wholesale. |
| [f1rstxlas7](https://github.com/f1rstxlas7/hass_gecko_in_touch3_spa) | Main `cc493d7a` duplicates Markus's snapshot; credit extracted work to its originating author. |
| [shieldwed](https://github.com/shieldwed/ha-gecko-integration) | Initiator branch matches PR 32 and is adapted. Additional Manuel/RGB branches are superseded by corrected RGB work. Rainbow branch `427f4132` has an undefined exception variable and hardcoded effect assumptions; deferred. |
| [manuelkleinert](https://github.com/manuelkleinert/ha-gecko-integration) | Main `66121070`: early RGB implementation uses incompatible intensity/payload assumptions and blocking calls without robust capability detection. Superseded by repaired PR 57/client 12; no additional extraction. |
| [dansbaker](https://github.com/dansbaker/ha-gecko-integration) | Main `8c8d01ad` and OAuth branches contain earlier official/auth fixes. Official baseline already includes offline access and reauth. Added focused missing-token/account-preserving handling; did not restore headless login or duplicate token management. |
| [jamietre](https://github.com/jamietre/ha-gecko-integration) | Main `242d96e1`: earlier Dan Baker setup-retry change already represented in official baseline. No additional owner-authored work to extract. |
| [Zuntara](https://github.com/Zuntara/ha-gecko-integration) | Main `f5159c07`, bugfix branch `1c26a344`: retry/reconnection work already covered by current official code. No additional extraction. |
| [oczek](https://github.com/oczek/ha-gecko-integration) | Callback dependency branch is PR 54, incorporated; other advertised branches are historical official development. |
| [springerigor](https://github.com/springerigor/ha-gecko-integration) | No new changes beyond the compared official baseline. |
| [thaynes43](https://github.com/thaynes43/ha-gecko-integration) | Default and historical official feature branches add no additional current fixes. |

## Waterlab adaptation

Markus's examples show live chemistry in `GET /v6/accounts/{account}/vessels/{vessel}?customActionsVersion=0`, notably `status.readings.ph`, `orp` and other reading records, while MQTT can contain calibration parameters instead. The restored integration uses the existing OAuth session and supports these records plus explicit cloud pH/ORP summaries. It does not import the fork's separate mobile-app credential flow or assume the Home Assistant OAuth client has access to energy endpoints.

The reader preserves reading source/status/units and exposed timestamps. It accepts finite numeric values only, validates pH range, limits supported reading keys, ignores arbitrary raw metadata and exposes no chemical commands. Cloud reads occur after platform setup and on an independent five-minute timer; frequent MQTT reports cannot postpone them. Transient failures make cloud sensors unavailable, 403/404 stop optional reads until reload, and 429 delays retry. Pump availability is unaffected. Retrieval time is not sample time, and successful responses do not prove the sensor sample is fresh.

Automated tests cover published payload shapes, invalid values, calibration exclusion, reported-only extension discovery, polling, independent availability, recovery/removal, and optional endpoint failures. Actual account authorization, device response shapes and physical Waterlab measurements remain to be verified on hardware.
