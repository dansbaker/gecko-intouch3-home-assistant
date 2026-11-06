# Device regression fixtures

`tests/fixtures/device_sequences/` holds portable JSON protocol sequences replayed
through the real bundled parser. The initial fixtures are **synthetic regressions**,
not hardware recordings. Their metadata states provenance and evidence level.

For a community recording, retain only configuration and reported zone fields
needed to reproduce a problem. Remove account/vessel/monitor IDs, names, serials,
URLs, credentials, MQTT topics and unrelated fields. Replace zone names with
neutral labels while preserving relationships, numeric types and missing fields.
Never commit raw captures. Ask the contributor to review the sanitised fixture.

Include provenance (issue/PR URL and consenting contributor username), controller
model/firmware if known, what was physically observed, and each ordered event's
expected result. Add a replay assertion that fails before the fix. Do not label a
synthetic or reconstructed example as a captured device report.

Parser replay covers sparse reports, pump speed transitions and configuration
replacement; transport disconnect/reconnect and HA entity rebinding remain in
the existing lifecycle/reconnection tests. Add real reconnect recordings when
available rather than inventing hardware evidence.
