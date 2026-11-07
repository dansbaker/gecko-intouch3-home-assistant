# Help support your spa hardware

You do not need a terminal, Python or network captures. Start with a downloaded
Gecko diagnostics file and a short description of your equipment. This lets us
investigate hardware the maintainers do not own. A report is useful even if a
feature is completely missing in Home Assistant.

## Quick hardware inventory

1. In Home Assistant, open **Settings → Devices & services → Gecko**.
2. Open the integration entry's three-dot menu and choose **Download diagnostics**.
   Depending on HA's layout, open the entry first to see its menu. If the entry
   menu has no diagnostics option, try the Gecko device page's three-dot menu.
3. Review the downloaded JSON before sharing it. Rename it `inventory.json`.
4. [Open a hardware compatibility report](https://github.com/dansbaker/gecko-intouch3-home-assistant/issues/new?template=hardware_report.yml),
   describe the spa/controller/gateway models and equipment, and drag the file
   into the attachment field. Never include serial numbers or account details.

Version 3.0.1 and newer automatically includes integration/HA versions, UTC capture time,
connection status, pump counts and speed limits, anonymous zone labels, numeric
light colour state and available chemistry metadata. Older releases may contain
less detail: include versions manually if absent. Installing an unreleased build
is not required to submit an initial report.

## Capture a feature changing

Keep the same HA session running for the sequence. Do not reload the integration
between captures: anonymous zone labels reflect list order and are not permanent
hardware identities. Mention any reconnect or configuration refresh during the
sequence, since either can change the ordering. List the controls shown in your Gecko app to help us map
anonymous zones to physical pumps/lights.

1. Download diagnostics **before** changing anything; rename it `before.json`.
2. Change **one supported control in the Gecko app**. Record the time and timezone,
   the control used and what you actually observed at the spa.
3. Wait for the Gecko app and HA to receive the reported state. Download again
   and rename it `after.json`. If HA never changes, report that and the elapsed
   time; do not wait indefinitely or repeat rapid commands.
4. Attach both files and fill out this table. For another action use another row
   and another file (`after-low.json`, `after-high.json`, etc.).

| Time + timezone | App action | Physical observation | HA result | File |
| --- | --- | --- | --- | --- |
| 14:05 Europe/London | Pump 3 on | Pump 3 running | No pump 3 entity | after.json |

Useful sequences depend on what you own:

- **Pumps:** off → low → high, for controls/speeds your app offers. Note heating
  or filtration activity; a pump running automatically may not stop on request.
- **Lights:** on/off; then red → green → blue or two different brightness levels
  if supported. Give effect names in your written observations: diagnostics omit
  free-text effect names, but record whether an effect is present.
- **Waterlab:** send an inventory first, noting whether the app shows probe,
  manual-test or computed readings and their measurement times. If a sample
  naturally updates, collect another file after the next chemistry refresh
  (normally five minutes). Do not dose chemicals or calibrate a probe just to
  create a test. Missing chemistry data is itself useful evidence.

Use only normal, supported controls. Do not override heating/filtration safety,
force pumps off or deliberately cut power. You can stop the test at any point.
If comparing an HA command too, record it as a separate action and capture.

## What the file can and cannot tell us

Diagnostics use an allowlist of modeled fields, excluding names, IDs, credentials,
URLs and raw cloud payloads. Chemistry free-text metadata is withheld unless
recognised; measurement timestamps may reveal when you used the equipment, so
review these too. Sharing is manual: the integration uploads nothing to GitHub.

A snapshot contains reported state, not a continuous log, command history or
proof of physical operation. It may not expose an unknown hardware feature yet.
If more evidence is needed, a maintainer will request a specific bounded field
or capture and explain how to redact it. Do not attach raw Home Assistant debug
logs, packet captures, MQTT topics or cloud responses to a public issue: debug
logging can include configuration, identifiers and authentication details.

Maintainers can turn reviewed reports into regression fixtures following
[DEVICE_FIXTURES.md](DEVICE_FIXTURES.md). Contributor attribution and owner-tested
status belong in the compatibility table only after review; a snapshot alone is
not a hardware certification.
