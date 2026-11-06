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
`gecko_iot_client`, development version `3.0.0.dev1`. The source version identifier
replaces the earlier `1.0.3+bundled` consolidation marker. Original client source
provenance and its GPL license are retained. The root build configuration maps
only client packages into the wheel; it does not package Home Assistant entities.
Both the wheel and rebuilt source archive have been imported and exercised in a
fresh environment without Home Assistant installed. A dedicated CI workflow
repeats that verification. No PyPI publishing workflow is enabled yet.

Protocol-oriented telemetry, Waterlab, shadow metrics, lighting and connectivity
helpers now live under `gecko_iot_client/helpers`. HA imports this shared source
through its bundled namespace and standalone consumers through `gecko_iot_client`.
Their original Apache-2.0 licensing and attribution are preserved alongside the
inherited GPL client license. No module aliases or duplicate source copies are
used. The future core adapter still needs to consume an approved public client
release and finish auditing the raw-data/model API boundary.


## Publishing integration releases

Bump `custom_components/gecko/manifest.json` to the next stable semantic version,
add matching notes at `docs/releases/<version>.md`, and merge to `master`.
The Release workflow detects an untagged version, runs the complete test suite,
HACS/hassfest validation and standalone package checks, then creates `v<version>`
at that exact checked commit, marks the GitHub release latest, and attaches
`gecko.zip` containing the complete integration and bundled client. Existing tags
are never moved or overwritten. A failed check prevents publication.

`workflow_dispatch` can retry publication of the version currently on `master`;
it does not bypass the checks. Branch pushes and pull requests do not publish.
Integration releases do not publish the separately versioned client to PyPI.

## Community evidence and compatibility checks

Use [DEVICE_FIXTURES.md](DEVICE_FIXTURES.md) for sanitised protocol sequences and
[COMPATIBILITY.md](COMPATIBILITY.md) for owner verification. Synthetic fixtures
must remain labelled as such. Follow [RELEASE_TESTING.md](RELEASE_TESTING.md) for
physical checks and rollback, and [QUALITY_CHECKLIST.md](QUALITY_CHECKLIST.md)
for Core rule evidence.

After the existing coverage commands, run:

```sh
python script/check_entity_coverage.py coverage.json
python script/check_integration_coverage.py coverage.json
pip install -r requirements_lint.txt
ruff check .
```

The non-entity gate measures statement and branch floors separately, including
setup, coordinator and connection management. These are regression baselines,
not a claim of >95% coverage. New top-level HA modules must be assigned a target.
Ruff currently checks syntax/name errors across the repository; expand style
rules separately from inherited-code cleanups.

Weekly scheduled and manual compatibility CI resolves the latest stable HA and
custom-integration test harness, runs the full suite, and uploads resolved package
versions even on failure. The ordinary/release CI retains pinned dependencies.
Dependabot proposes weekly pip and Actions updates for human review. No automatic
merge, deployment or publication is enabled by compatibility checks.

Validation on 6 November 2026: 623 tests passed in both the pinned environment
(HA 2026.9.4) and a clean latest-stable resolver environment (HA 2026.10.4,
custom-component harness 0.13.375). All three coverage gates and Ruff passed.
The standalone wheel and rebuilt source distribution passed checks without HA.
Workflow/form YAML parsed locally; GitHub-hosted workflows will run after push.
The fixture corpus currently contains synthetic pump and chemistry sequences;
community hardware captures and additional owner validation are still needed.
