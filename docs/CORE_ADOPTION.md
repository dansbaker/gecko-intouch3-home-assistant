# Path to Home Assistant Core inclusion

Research and initial gap assessment: **5 November 2026**, current local branch
at `72c32b2`. Our goal is inclusion in Home Assistant Core, with Gold as the
longer-term quality target. This is a development roadmap, not a claim that
Home Assistant has accepted, reviewed or awarded a tier to this integration.

The manufacturer-maintained GitHub integration, HACS distribution, and inclusion
in Home Assistant Core are separate things. This document concerns core inclusion.

## Requirements and targets

New core integrations must satisfy **Bronze**. The tiers are cumulative; Silver
adds reliability requirements, Gold improves the user experience, and Platinum
adds async dependencies and strict typing. A tier is recorded in the manifest
and backed by an honest `quality_scale.yaml`; a reviewer approves it. We should
not set a tier merely because we intend to reach it.

Sources: [quality scale](https://contributors.home-assistant.io/core/quality-scale/),
[rule inventory](https://contributors.home-assistant.io/core/quality-scale/rules/),
[quality-scale file](https://contributors.home-assistant.io/core/quality-scale/quality-scale-file/).

| Gate | Implication for this project |
| --- | --- |
| Bronze config-flow tests | Cover all of `config_flow.py`, error recovery and entry identity; our two directly invoked reauth tests are insufficient. |
| Silver coverage | More than 95% in each integration module, not just an aggregate percentage. |
| Library boundary | Protocol communication/parsing belongs in an independently installable library on PyPI. |
| Dependency provenance | Public source, published source distribution, version tags and public automated release workflow. |
| Core review | Use current core development tooling, a small submission, documentation and brand PRs, and responsible human ownership. |

Sources: [config-flow coverage](https://contributors.home-assistant.io/core/quality-scale/config-flow-test-coverage/),
[Silver coverage](https://contributors.home-assistant.io/core/quality-scale/test-coverage/),
[library requirements](https://contributors.home-assistant.io/core/integrations/api-library/),
[dependency transparency](https://contributors.home-assistant.io/core/quality-scale/dependency-transparency/),
[submission process](https://contributors.home-assistant.io/core/development/submitting/).

The measured current baseline is 384 passing tests plus 46 passing subtests:
59.2% statement coverage and 46.5% branch coverage over the integration and bundled
client together. These are our measurements, not a quality-scale award. The
published Silver rule must be evaluated module by module on the integration's
core test suite; a high-coverage library cannot compensate for untested HA code.

## Architecture: keep one repository, publish the client

The current bundled installation is useful for restoring this custom integration,
but does not satisfy the core library boundary. Core's integration must not
contain our MQTT, shadow protocol or chemistry-response parsing code. This
includes the protocol-specific helpers that currently sit beside the HA entities,
not only the existing `gecko_iot_client` directory.

We can preserve the requested **single repository**: a proposed layout is a
standalone client package under `packages/gecko_client`, with its own
`pyproject.toml`, and the custom integration beside it during development. One
repository can produce the client distribution and maintain the custom integration;
core would pin a public release of that client. A separate GitHub repository is
not necessary for this proposal. Package naming, release ownership and the exact
layout remain design work. A local standalone package prototype now builds from
the existing nested source tree using root build metadata; import/deployment
behavior for the HACS integration has not changed. See [CLIENT_PACKAGE.md](CLIENT_PACKAGE.md).

Before publishing, settle source licensing and provenance. The integration has
Apache-2.0 notices, while the inherited client carries GPL-3.0-or-later. The core
checklist requires Apache-compatible dependency licensing and reviewer scrutiny.
Do not assume the root Apache license covers the client or relicense inherited
code without the relevant rights. Determine an acceptable licensing path with
the rightsholders/core reviewers before investing in a submission.

Source: [development checklist](https://contributors.home-assistant.io/core/development/checklist/).

## Initial Bronze audit

These are source-review findings, not a completed hassfest/core review. Review
all applicable rules against the eventual submission; document exemptions with
reasons rather than marking unsupported claims as complete.

| Rule or group | Current evidence and remaining work |
| --- | --- |
| `config-flow`, `test-before-configure` | OAuth and account/vessel API checks exist. Connection failures abort broadly; error recovery needs full flow-manager tests and clearer handling. |
| `config-flow-test-coverage` | Updated 5 November: real flow-manager tests reach 100% line/branch coverage of the flow module; CI now enforces it. Continue testing added paths and real OAuth deployment behavior. |
| `unique-config-entry` | Updated 5 November: stable account unique ID and duplicate abort, with legacy account-data matching. Flow-manager tests cover current and older entries. |
| `test-before-setup` | Connection setup exists, but failure classification and partial-setup cleanup need HA lifecycle tests. |
| `entity-event-setup` | Updated 5 November: availability reads have no subscription side effects; lifecycle hooks own initial subscription and coordinator replacement updates. HA entity tests cover rebinding/removal and stale worker callbacks. |
| `entity-unique-id`, `has-entity-name` | Most entity IDs and names exist. Several IDs embed entry IDs; audit stability, cross-account collisions and migration before changing them. |
| `runtime-data`, `common-modules` | Typed runtime-data container, coordinator and base-entity modules exist. Audit global connection-manager ownership and cleanup. |
| `appropriate-polling` | Independent five-minute Waterlab polling and push updates exist. Verify API limits, retries, task cancellation and that unnecessary polling is avoided. |
| `dependency-transparency` | AWS dependencies are pinned; client packaging/release provenance and dependency licensing need the work above. |
| `brands` | Verify brand assets and domain with core/brands; existing custom icons or HACS metadata do not establish compliance. |
| `action-setup` | No integration-specific custom actions currently identified; assess applicability separately from normal entity services. |
| `docs-high-level-description`, `docs-installation-instructions`, `docs-removal-instructions` | README is a start. Prepare official website documentation, including supported hardware and removal instructions. |
| `docs-actions`, `docs-conditions`, `docs-triggers` | Document applicable features; justify exemptions where none are defined. |

Sources: [Bronze rule list](https://contributors.home-assistant.io/core/quality-scale/rules/#bronze),
[event lifecycle](https://contributors.home-assistant.io/core/quality-scale/entity-event-setup/),
[duplicate entries](https://contributors.home-assistant.io/core/quality-scale/unique-config-entry/).

## OAuth, reliability and user experience

Core's documented OAuth route supports application credentials and delegates
account-token renewal to HA. PKCE is supported through a custom credentials
implementation. Our hardcoded public client ID and `.env` overrides need review
against that route, including how users obtain valid Gecko credentials and
permitted callback URLs. Confirm the vendor/API authorization arrangement and
Waterlab endpoint access; successful existing logins do not settle that design.
No Gecko or Home Assistant contacts have been made.

Source: [OAuth and application credentials](https://contributors.home-assistant.io/core/integrations/oauth2/).

For Silver, prioritize real config-entry setup/unload/reload tests, unavailable
and recovery states, rate limiting, translated/specific errors, reauthentication,
per-platform `PARALLEL_UPDATES`, and a defined maintainer commitment. The current
select/diagnostics modules have no measured coverage, and setup is lightly
covered. Existing tests mostly exercise models and entities directly; add tests
through HA setup, entity states and service calls.

For Gold, audit device information, late-added spas, removal of stale devices,
redacted diagnostics, entity categories/classes, default-disabled diagnostics,
translated names/errors/icons and reconfiguration. Several entity names and
service errors are still hardcoded. Treat network-discovery rules according to
this cloud service's capabilities and justify any exemption. Our README already
has useful limitations, but official documentation needs supported devices,
functions, update behavior, troubleshooting, examples and use cases.

Platinum is a later target: session injection is partly present already, while
threaded AWS MQTT workers and incomplete typing need a separate design audit.
A synchronous dependency used correctly through the executor is not by itself
a Bronze blocker; it does prevent simply claiming the async-dependency rule.

## Submission sequence

1. Settle library licensing, package ownership and the OAuth/API route.
2. Build a reproducible client release from this repository and test its wheel
   and source distribution independently of HA.
3. Fix the Bronze gaps and test through HA's flow/lifecycle APIs. Add an honest
   rule tracker with evidence; only claim a tier after its gates are met.
4. Stabilize the custom integration with users. Replay redacted reporter payloads
   for hardware we do not own, and obtain owner confirmation for Waterlab and
   other unsupported-on-our-spa configurations. Keep fixture and physical proof
   distinct. Seek core maintainers' guidance on eligibility and the domain.
5. Prepare a separate current-core `dev` branch with a minimal **one-platform**
   Bronze integration and corresponding official documentation/brand submissions.
   The full six-platform restoration should not be dumped into the first PR.
   Current guidance explicitly defers diagnostics, extra actions, reauth and
   reconfigure flows to follow-ups; keep those in our custom build until the
   appropriate core follow-up. Agree a practical OAuth staging plan with reviewers.
6. Add remaining platforms and Silver/Gold improvements in focused follow-ups,
   preserving documented identity/migration behavior.

Sources: [eligibility and first-PR scope](https://contributors.home-assistant.io/core/integrations/create/),
[submission process](https://contributors.home-assistant.io/core/development/submitting/).

Core CI includes formatting/linting, tests, hassfest and requirement/metadata
validation. Follow core's actual tooling rather than relying on our custom
integration's passing pytest job. Submission also requires the human contributor's
CLA and understanding of the changes. AI assistance is permitted, but autonomous
submissions are not; Dan must review/understand the work and personally answer
maintainers' substantive questions.

Sources: [development checklist](https://contributors.home-assistant.io/core/development/checklist/),
[AI policy](https://contributors.home-assistant.io/start/ai-policy/).

This roadmap changes no runtime behavior, claims no quality tier, publishes no
package, and opens no Home Assistant issue or pull request.


## First implementation milestone (5 November 2026)

Account setup now has retryable validation with retained OAuth data for temporary
failures. Invalid/incomplete authentication restarts login. Account IDs are
validated before they can become entry identity, including rejecting `None`,
blank values and booleans. Existing account/vessel data remains intact on reauth.

Partial setup now shuts down already-connected vessels, and missing broker or
monitor information cannot silently produce a successful setup. Successful
unload removes platforms before closing clients; a failed platform unload
preserves the runtime. Coordinator shutdown cancels base coordinator timers.

Real HA setup/unload/setup and identifier migration tests supplement the prior
model tests. The measured first milestone is **423 tests and 46 subtests passing**,
with **100% config-flow line and branch coverage**. CI collects overall branch
coverage and enforces the full-flow gate. Formatting/lint checks pass for the
new flow, entity lifecycle, test and coverage-gate modules. This is not a full
core lint/hassfest run, nor a claim that Bronze has been awarded.


## Standalone client packaging milestone (5 November 2026)

A wheel and source archive now build from one source tree in this repository.
The provisional `gecko-intouch3-client` distribution has development version
`3.0.0.dev0`, retains the inherited GPL license, and is not published or reserved
on PyPI. The wheel contains client modules, metadata and license/type-marker
files; it contains no HA integration modules. Verification succeeds for both
wheel installation and a fresh build/install of the source archive in an
isolated environment without Home Assistant. The checker exercises parser
configuration, pump/light wire payloads and operation-mode normalization.

CI builds/verifies these artifacts separately from the HA test job. This prepares
the installable-library boundary; it does not yet satisfy public release,
license-compatibility or thin-core-adapter requirements. Protocol helper
extraction and changing the future core adapter to consume a public client
release remain outstanding. The custom integration still imports the bundled
namespace, preventing a mixed-model installation during this transition.


After both milestones, the full local suite remains at **423 passing tests and
46 passing subtests**. Overall statement coverage is **72.4%** and branch
coverage is **59.2%**, with full config-flow line/branch coverage. The rise from
the earlier aggregate measurement comes from new HA flow/platform/lifecycle
exercise, not removing source files from the coverage denominator. It is still
below Silver's requirement and does not establish hardware-level behavior.


## Managed OAuth application credentials (5 November 2026)

The integration now exposes HA's application-credentials platform. Named stored
credentials provide an independent PKCE implementation; existing entries retain
their original provider and the bundled custom-integration login remains available.
Tests exercise credential storage/lookup, selected-provider flow completion,
S256 verification, code-exchange fields, token renewal and transient/permanent
failure classification. The two OAuth implementation modules have full measured
line coverage, and config-flow line/branch coverage remains 100%.

This completes the local managed-credentials route, not Gecko's credential
issuance/callback approval or a live OAuth deployment test. Before submitting a
core adapter, settle how ordinary users obtain valid credentials and remove the
custom-only hardcoded fallback from that adapter without stranding custom users.
See [OAUTH.md](OAUTH.md) for current behavior and installation parameters.
