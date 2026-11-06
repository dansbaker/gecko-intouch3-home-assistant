# Release testing and rollback

Before release:

1. Run the full suite and coverage gates, lint, HACS/hassfest and standalone client build checks.
2. Review compatibility CI, migration notes and known limitations. Record exact HA, integration and controller versions.
3. Back up HA. Install the candidate from one repository only and restart.
4. Confirm setup, preserved entity IDs, device links, temperatures and capabilities. Review diagnostics/logs without publishing identifiers.
5. With the owner present, check supported controls against the physical spa. Respect filtration/heating demands; do not force pumps off. Record unsupported or untested features explicitly.
6. Test reload and recovery from a safely simulated connection loss, checking for duplicate entities and tasks. Do not interrupt heating protection to manufacture a test.
7. Bump the manifest, add matching release notes and let the gated release workflow publish. Report physical tests separately from automated checks.

To roll back, download the previous compatible revived release, replace the
complete `custom_components/gecko` directory (including its client), and restart.
If configuration or registry migrations are incompatible, restore the HA backup.
Do not install legacy `v0.1.x` as a rollback from `3.x`: it uses `gecko_spa` and
different entity identities. Keep one HACS repository managing `gecko`.

On 5 November 2026, the 3.0.0 runtime was installed on Dan's HAOS ARM64 instance
running HA 2026.10.4. Configuration validation, startup, existing entity identities,
connection diagnostics and reported states were verified. That is native runtime
proof for this installation, not physical verification of every command or spa.
