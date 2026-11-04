# Gecko integration development

The Home Assistant integration and its IoT client are maintained, tested and distributed together. HACS installs the complete `custom_components/gecko` directory. There is no separate client wheel, PyPI dependency, submodule, or client release process.

## Source layout

- `custom_components/gecko/*.py`: Home Assistant setup, coordinators and entities.
- `custom_components/gecko/gecko_iot_client/`: bundled API, MQTT transport and device models.
- `tests/iot/`: client tests adapted to import the bundled package.
- `tests/`: integration tests.

Integration modules import the client with relative imports, such as `from .gecko_iot_client import GeckoIotClient`. Tests use `custom_components.gecko.gecko_iot_client`. Do not alias the bundled package in `sys.modules` or import a separately installed `gecko_iot_client`: that can create duplicate model/enum identities and load stale code.

Client logs are now below `custom_components.gecko.gecko_iot_client`; enabling debug logging for `custom_components.gecko` includes them.

## Tests

Use Python 3.14 for the pinned Home Assistant test environment:

```sh
python3.14 -m venv .venv
.venv/bin/pip install -r requirements_test.txt
.venv/bin/python -m pytest
```

The test environment must not install `gecko-iot-client`. CI verifies its absence. External AWS requirements remain pinned in the integration manifest; aiohttp is supplied by Home Assistant.

When adapting an upstream PR, change client imports and mock targets to the bundled namespace and exercise the real bundled zone parser. The upstream review probes refer to original external-package checkouts and remain historical review evidence.

## Source provenance

The Home Assistant baseline is `geckoal/ha-gecko-integration` at `aaf94de` (2.1.1). The IoT source baseline is `geckoal/gecko-iot-client` at `b799e0cef27099b18d87f52be359353d7ec53c1e` (v1.0.3), the head of its `develop` branch at consolidation. That source matches the integration's previous pinned client release.

The consolidation merge retains the client repository's Git ancestry alongside the integration ancestry. Only its runtime package and tests are brought into the working tree; its separate packaging, release automation and generated documentation are not needed. Historical files remain accessible with Git. The `iot-upstream` remote is a source reference, not a maintained second project.

The client license is preserved at `custom_components/gecko/gecko_iot_client/LICENSE`, with provenance in the root `NOTICE`. Existing integration licensing and notices are retained.

At consolidation, runtime changes are limited to package relocation, relative integration imports and replacing installed-distribution version lookup with the source identifier `1.0.3+bundled`. No upstream PR fixes are included yet. Subsequent bug fixes can update client models, transport and entities in the same change and ship through one integration release.

The imported reconnection tests isolate the transport clock from the test clock and explicitly stop/join their worker threads. This corrects upstream test timing races exposed by the Home Assistant test harness; it does not change runtime reconnect behavior.
