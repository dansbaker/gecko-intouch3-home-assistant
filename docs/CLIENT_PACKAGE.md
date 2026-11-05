# Gecko in.touch 3 client package

This standalone Python package is developed in the same repository as the
community Home Assistant integration. It contains the API client, MQTT transport
and zone models, and imports as `gecko_iot_client`. It does not depend on Home
Assistant. Python 3.14 is the currently supported and tested packaging runtime.

The provisional distribution name is `gecko-intouch3-client`, with development
version `3.0.0.dev0`. No release has been published or package name reserved on
PyPI. Builds are local/CI artifacts only until licensing, release ownership and
the core submission plan have been settled. The inherited client license is
GPL-3.0-or-later, with its license file preserved in the package. This metadata
is not a claim that the dependency meets Home Assistant Core's license requirements.

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
checks distribution identity/version, and exercises the parser, speed commands,
lighting serialization and operation-mode normalization without a spa or network
requests. CI also rebuilds the source distribution and runs the same checks.

There is one client source tree. The root build configuration maps it from its
current HACS deployment location into a standalone distribution; it does not
copy or alias modules at runtime. The custom integration continues to use its
bundled relative imports during this transition. Do not install the standalone
package as a substitute for part of the custom integration or mix model objects
from the two import namespaces.

A future core adapter must pin an actual public client release and use only
that namespace. Protocol-specific helper extraction, the core adapter import
switch and a public tagged/automated publishing workflow remain subsequent work.
