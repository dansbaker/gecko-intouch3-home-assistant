# Core quality evidence tracker

Reviewed 6 November 2026 against the [official rule inventory](https://contributors.home-assistant.io/core/quality-scale/rules/).
This is a conservative working checklist, not an awarded tier or submission.
“Evidence” means custom-integration implementation/tests exist; every rule still
needs review against the eventual Core adapter. “Open” means work or verification
remains. Proposed exemptions need reviewer agreement. Licensing is owned by Dan
and is not changed by this work.

## Bronze

| Rule | Status and evidence / next step |
| --- | --- |
| action-setup | Proposed exemption: no integration-specific actions; standard entity services only. Reassess if added. |
| appropriate-polling | Evidence: coordinator Waterlab five-minute polling and failure isolation, `tests/test_waterlab.py`; verify vendor API limits with real accounts. |
| brands | Open: confirm domain and acceptable assets in Core brands. |
| common-modules | Evidence: `coordinator.py`, `entity.py`. |
| config-flow | Evidence: OAuth UI and application credentials; `tests/test_config_flow.py`. Core credential arrangement remains open. |
| config-flow-test-coverage | Evidence: full line/branch gate in `script/check_config_flow_coverage.py`. |
| dependency-transparency | Open: standalone build CI exists; approved public client release and Core adapter remain. |
| docs-actions | Open: entity controls described in README; official website service examples needed. |
| docs-conditions | Proposed exemption: no integration-specific conditions. |
| docs-high-level-description | Evidence: README overview; port to official website. |
| docs-installation-instructions | Evidence: README HACS/manual/migration instructions; Core-specific setup documentation needed. |
| docs-removal-instructions | Open: provide official removal guidance and retention/deletion consequences. Rollback is in RELEASE_TESTING.md. |
| docs-triggers | Proposed exemption: no integration-specific triggers. |
| entity-event-setup | Evidence: lifecycle hooks and `tests/test_entity_lifecycle.py`. |
| entity-unique-id | Evidence: metadata/lifecycle tests; Core migration and cross-account identity review remains. |
| has-entity-name | Evidence: translated entity metadata, `docs/ENTITY_METADATA.md`. |
| runtime-data | Evidence: typed runtime container in `__init__.py`; setup lifecycle tests. |
| test-before-configure | Evidence: config flow tests account/vessel API; Core OAuth review remains. |
| test-before-setup | Evidence: setup/lifecycle and retry tests; complete failure classification audit for Core. |
| unique-config-entry | Evidence: account identity, duplicate/legacy matching in config-flow tests. |

## Silver

| Rule | Status and evidence / next step |
| --- | --- |
| action-exceptions | Evidence: command failure and translated control-action tests. |
| config-entry-unloading | Evidence: setup/unload/reload tests; real long-running repeated reload validation remains. |
| docs-configuration-parameters | Open: exhaustively document options in official website documentation. |
| docs-installation-parameters | Open: document OAuth/application credential fields and prerequisites for Core. |
| entity-unavailable | Evidence: connectivity and recovery tests; chemistry and MQTT availability independent. |
| integration-owner | Evidence: @dansbaker in manifest; Core ownership/review commitment required. |
| log-when-unavailable | Open: audit once-per-transition logging across MQTT, API and reconnect paths. |
| parallel-updates | Open: verify each platform's setting and command concurrency policy. |
| reauthentication-flow | Evidence: flow-manager tests and application credentials; real expiry validation remains. |
| test-coverage | Open: entity/config-flow gates strong; non-entity module floors now enforced separately. Floors are not the >95% Silver target. |

## Gold

| Rule | Status and evidence / next step |
| --- | --- |
| devices | Evidence: device associations/metadata tests; verify complete manufacturer/model/firmware on community hardware. |
| diagnostics | Evidence: identity-free modeled snapshots, allowlisted Waterlab metadata, privacy tests. |
| discovery | Open: cloud account discovery eligibility/exemption needs review. No local discovery protocol established. |
| discovery-update-info | Proposed exemption: cloud identifiers, no discovered network address. Confirm with reviewers. |
| docs-data-update | Evidence: README describes MQTT and five-minute chemistry refresh, sample age semantics. Port to official docs. |
| docs-examples | Open: add tested automation examples using generic entity IDs. |
| docs-known-limitations | Evidence: README and COMPATIBILITY.md; keep current. |
| docs-supported-devices | Evidence: COMPATIBILITY.md separates owner tests and automated fixtures; expand with reviewed reports. |
| docs-supported-functions | Evidence: README feature/capability list; complete entity reference for official docs. |
| docs-troubleshooting | Evidence: README, structured bug form, RELEASE_TESTING.md. |
| docs-use-cases | Open: official documentation examples needed. |
| dynamic-devices | Open: test adding another vessel after account setup without reload. Zone discovery is not proof of vessel discovery. |
| entity-category | Evidence: metadata audit and tests. |
| entity-device-class | Evidence: metadata audit, no guessed chemistry units. |
| entity-disabled-by-default | Evidence: opt-in extension/calibration diagnostics; audit full final entity list. |
| entity-translations | Evidence: strings and translation catalog, metadata tests. |
| exception-translations | Evidence: translated control errors; audit all setup/API error paths. |
| icon-translations | Evidence: icons catalog and metadata validation. |
| reconfiguration-flow | Open: define meaningful reconfiguration and add flow-manager tests. |
| repair-issues | Open: identify actionable problems beyond built-in reauth; do not add noise for transient outages. |
| stale-devices | Open: establish safe vessel/device removal behaviour and registry tests. |

## Platinum

| Rule | Status and evidence / next step |
| --- | --- |
| async-dependency | Open: AWS threaded transport requires architecture review. |
| inject-websession | Evidence: session injection exists; audit all standalone API paths. |
| strict-typing | Open: complete annotations and strict type checking. |

CI keeps the pinned environment reproducible and separately schedules latest
stable HA tests. Compatibility failures do not silently update pins or publish a
release. Raise coverage floors when improvements land; never lower them to hide a
regression. See DEVELOPMENT.md for reproduction commands.
