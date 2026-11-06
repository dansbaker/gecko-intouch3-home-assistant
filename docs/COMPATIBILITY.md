# Hardware verification

These are evidence levels, not a promise that every controller behaves identically.

| Configuration | Evidence | Remaining checks |
| --- | --- | --- |
| Dan's spa: two pumps, waterfall, on/off light, temperature control | Owner-tested installation on HAOS ARM64, HA 2026.10.4, 5 November 2026; preserved nine entity IDs, connected diagnostics and reported states verified | Repeated physical command checks and long-running recovery |
| Three or more pumps and different speed configurations | Automated parser/entity tests; community-derived protocol examples | Owner confirmation for each controller/firmware |
| RGB, brightness and effects | Automated capability and command tests; adapted community work | Physical colour/effect confirmation on capable equipment |
| Waterlab chemistry | Automated cloud response tests based on public fork examples | Real Waterlab account access, units, sample timestamps and owner validation |
| Salt systems requiring a separate app | Unsupported; no verified protocol | Identify hardware/API and obtain owner-supplied evidence |

To add an owner-tested configuration, submit model/firmware (no serials), HA and
integration versions, reviewed diagnostics, actions tried and observed physical
results. State reads, successful API calls and test fixtures alone do not prove
physical operation. Use the bug form for problems and a feature request for new
hardware. Maintainers review submissions before updating this table.
