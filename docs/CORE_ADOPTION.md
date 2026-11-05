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
layout remain design work. No packaging or import changes have been made yet.

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
| `config-flow-test-coverage` | Only two direct reauth cases; add real UI-flow success, cancellation, invalid auth, network failures, recovery, empty accounts and optional configuration failures. |
| `unique-config-entry` | Missing: no `async_set_unique_id` plus duplicate abort, or account-data duplicate check. Use stable account identity and test both new and existing entries. |
| `test-before-setup` | Connection setup exists, but failure classification and partial-setup cleanup need HA lifecycle tests. |
| `entity-event-setup` | `GeckoEntityAvailabilityMixin.available` may register/rebind callbacks through `_ensure_callback_registered`. Move subscription changes into explicit lifecycle/reconnection handling; test removal and disabled entities. |
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
