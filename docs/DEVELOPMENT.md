# Gecko integration development

The Home Assistant integration and its IoT client are maintained and tested in this repository. HACS installs the complete `custom_components/gecko` directory; that custom installation still needs no separate client package or submodule. As preparation for core adoption, the root `pyproject.toml` also builds a standalone client wheel and source archive from the same source tree. The package is not published. See [CLIENT_PACKAGE.md](CLIENT_PACKAGE.md) for build checks and the current packaging boundary.

## Core adoption direction

The bundled layout below describes today's custom installation. The goal is Home Assistant Core inclusion. Its requirements call for a separately published protocol library; we can keep that package and the integration in this repository. See [CORE_ADOPTION.md](CORE_ADOPTION.md) for the researched acceptance criteria, licensing/OAuth questions and staged transition. Local standalone packaging is now implemented; HACS imports and deployment remain bundled.

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

At consolidation, runtime changes are limited to package relocation, relative integration imports and replacing installed-distribution version lookup with the source identifier `1.0.3+bundled`. The subsequent restoration changes update client models, transport and entities together; see [RESTORATION.md](RESTORATION.md) for the changes and verification.

The imported reconnection tests isolate the transport clock from the test clock and explicitly stop/join their worker threads. This corrects upstream test timing races exposed by the Home Assistant test harness; it does not change runtime reconnect behavior.


## Coverage gates

The unified CI job now measures statement and branch coverage and requires full
coverage of `config_flow.py`. To reproduce:

```sh
.venv/bin/python -m pytest --cov=custom_components.gecko --cov-branch --cov-report=term --cov-report=json:coverage.json
.venv/bin/python script/check_config_flow_coverage.py coverage.json
```

The gate fails when the flow is absent, branches were not measured, or any line
or branch is uncovered. This is the initial Bronze-focused gate; it does not
claim that other integration modules meet Silver's per-module threshold.


## Standalone client build milestone

The provisional distribution is `gecko-intouch3-client`, import namespace
`gecko_iot_client`, development version `3.0.0.dev0`. The source version identifier
replaces the earlier `1.0.3+bundled` consolidation marker. Original client source
provenance and its GPL license are retained. The root build configuration maps
only client packages into the wheel; it does not package Home Assistant entities.
Both the wheel and rebuilt source archive have been imported and exercised in a
fresh environment without Home Assistant installed. A dedicated CI workflow
repeats that verification. No PyPI publishing workflow is enabled yet.

Some protocol-oriented telemetry/Waterlab helpers still live beside HA modules.
Move those to a well-defined public client API and make the future core adapter
consume an approved public client release before considering the boundary complete.
