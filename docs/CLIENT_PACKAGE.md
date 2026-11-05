# Gecko in.touch 3 client package

This standalone Python package is developed in the same repository as the
community Home Assistant integration. It contains the API client, MQTT transport
and zone models, and imports as `gecko_iot_client`. It does not depend on Home
Assistant. Python 3.14 is the currently supported and tested packaging runtime.

The provisional distribution name is `gecko-intouch3-client`, with development
version `3.0.0.dev1`. No release has been published or package name reserved on
PyPI. Builds are local/CI artifacts only until licensing, release ownership and
the core submission plan have been settled. Original client sources retain
GPL-3.0-or-later. Extracted integration helpers retain Apache-2.0, with per-file
SPDX markers. Package metadata lists both licenses (`GPL-3.0-or-later AND Apache-2.0`)
and includes both license texts and a provenance NOTICE. This is not a relicense
or a claim that core's license compatibility requirements are satisfied.

Source baseline: Gecko Alliance's `geckoal/gecko-iot-client` at
`b799e0cef27099b18d87f52be359353d7ec53c1e` (v1.0.3). Community fixes and provenance
are documented in the repository README and `docs/RESTORATION.md`.

## Build and verify

From the repository root:

```sh
uv build --out-dir /tmp/gecko-client-dist
uv venv /tmp/gecko-client-check --python 3.14
uv pip install --python /tmp/gecko-client-check/bin/python /tmp/gecko-client-dist/*.whl
cd /tmp
/tmp/gecko-client-check/bin/python /absolute/path/to/repository/script/verify_client_package.py
```

The checker rejects an environment with Home Assistant or a source-tree import,
checks distribution identity/version and licenses, and exercises the parser,
speed commands, lighting serialization, operation-mode normalization, Waterlab
readings, calibration exclusion, telemetry redaction and sparse connectivity
without a spa or network requests. CI also rebuilds the source distribution and runs the same checks.

There is one client source tree. The root build configuration maps it from its
current HACS deployment location into a standalone distribution; it does not
copy or alias modules at runtime. The custom integration continues to use its
bundled relative imports during this transition. Do not install the standalone
package as a substitute for part of the custom integration or mix model objects
from the two import namespaces.

Protocol interpretation now lives under `gecko_iot_client.helpers`: telemetry,
connectivity, lighting payloads, extension metrics and Waterlab reading extraction.
The custom integration consumes those modules through its bundled relative
namespace; the standalone wheel exports the same helpers without Home Assistant.

The observed binary-speed detector is public as
`helpers.telemetry.reports_binary_near_max_speed_encoding`; adapters need not
import its former private name.

A future core adapter must pin an approved public client release and use only
the standalone namespace. The adapter import switch, a public tagged/automated
publishing workflow and review of the remaining raw-data/model API boundary
remain subsequent work.
